'use strict';
// HireLoop job portal: zero-dependency Node server (Node 18+). Data lives in DATA_DIR.
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PORT=+process.env.PORT||3000,DIR=process.env.DATA_DIR||path.join(__dirname,'data'),RES=path.join(DIR,'resumes');
fs.mkdirSync(RES,{recursive:true});
const SECRET=process.env.SESSION_SECRET||(()=>{const f=path.join(DIR,'.secret');try{return fs.readFileSync(f,'utf8')}catch{const k=crypto.randomBytes(32).toString('hex');fs.writeFileSync(f,k,{mode:0o600});return k}})();
const ST=['Submitted','Reviewed','Shortlisted','Rejected','Hired'],ROLES=['admin','employer','seeker'],TYPES=['Full-time','Part-time','Contract','Internship'],EMAIL=/^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const DBF=path.join(DIR,'db.json');
let db;try{db=JSON.parse(fs.readFileSync(DBF,'utf8'))}catch{db={n:1,users:[],jobs:[],apps:[],msgs:[],log:[],cfg:{site:'HireLoop',approve:true,maxMB:5,reg:true}}}
const flush=()=>{fs.writeFileSync(DBF+'.tmp',JSON.stringify(db));fs.renameSync(DBF+'.tmp',DBF)};
let tm;const save=()=>{clearTimeout(tm);tm=setTimeout(flush,100)};
['SIGTERM','SIGINT'].forEach(g=>process.on(g,()=>{flush();process.exit(0)}));

class E extends Error{constructor(m,c=400){super(m);this.c=c}}
const need=(c,m,code)=>{if(!c)throw new E(m,code)};
const s=(x,n=500)=>String(x??'').trim().slice(0,n);
const log=m=>{db.log.unshift(new Date().toISOString().slice(11,19)+' UTC · '+m);db.log.length=Math.min(db.log.length,60)};
const hash=(p,salt=crypto.randomBytes(16).toString('hex'))=>salt+':'+crypto.scryptSync(p,salt,32).toString('hex');
const check=(p,h)=>{const[salt,x]=String(h).split(':');return !!x&&crypto.timingSafeEqual(Buffer.from(hash(p,salt).split(':')[1],'hex'),Buffer.from(x,'hex'))};
const sign=t=>crypto.createHmac('sha256',SECRET).update(t).digest('base64url');
const mk=id=>{const b=Buffer.from(JSON.stringify({u:id,e:Date.now()+6048e5})).toString('base64url');return b+'.'+sign(b)};
function who(req){const c=(req.headers.cookie||'').split(/;\s*/).find(x=>x.startsWith('sid='));if(!c)return;const[b,g]=c.slice(4).split('.');
 if(!b||!g||g.length!==sign(b).length||!crypto.timingSafeEqual(Buffer.from(g),Buffer.from(sign(b))))return;
 try{const o=JSON.parse(Buffer.from(b,'base64url'));if(o.e>Date.now())return db.users.find(x=>x.id===o.u)}catch{}}
const cookie=(v,age,req)=>`sid=${v}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${age}`+(req.headers['x-forwarded-proto']==='https'||req.socket.encrypted?'; Secure':'');

if(!db.users.length){const pw=process.env.ADMIN_PASSWORD||crypto.randomBytes(9).toString('base64url'),em=(process.env.ADMIN_EMAIL||'admin@example.com').toLowerCase();
 db.users.push({id:'u'+db.n++,name:'Admin',email:em,role:'admin',pw:hash(pw)});flush();
 if(!process.env.ADMIN_PASSWORD)console.log(`First run: admin login ${em} / ${pw} (change it via the Users tab)`)}

const pub=u=>({id:u.id,name:u.name,email:u.email,role:u.role,company:u.company,skills:u.skills,resume:u.resume});
function state(u){let jobs,apps,users;
 if(u.role==='admin'){jobs=db.jobs;apps=db.apps;users=db.users}
 else if(u.role==='employer'){jobs=db.jobs.filter(j=>j.owner===u.id);apps=db.apps.filter(a=>jobs.some(j=>j.id===a.job));users=db.users.filter(x=>x.id===u.id||apps.some(a=>a.user===x.id))}
 else{apps=db.apps.filter(a=>a.user===u.id);jobs=db.jobs.filter(j=>j.status==='approved'||apps.some(a=>a.job===j.id));users=[u]}
 const ids=new Set(apps.map(a=>a.id));
 return{users:users.map(pub),jobs,apps,msgs:db.msgs.filter(m=>ids.has(m.app)),log:u.role==='admin'?db.log:[],cfg:db.cfg}}
function dropApps(f){db.apps.filter(f).forEach(a=>{fs.rmSync(path.join(RES,'a'+a.id),{force:true});db.msgs=db.msgs.filter(m=>m.app!==a.id)});db.apps=db.apps.filter(a=>!f(a))}
const myJob=(u,id)=>{const j=db.jobs.find(j=>j.id===id);need(j&&(u.role==='admin'||j.owner===u.id),'Job not found.',404);return j};

const ROLE={userSave:'admin',userDel:'admin',jobSet:'admin',cfg:'admin',jobDel:'admin employer',post:'employer',status:'employer',msg:'employer',submit:'seeker',profile:'seeker'};
const ACT={
 userSave(u,b){const name=s(b.name,100),email=s(b.email,200).toLowerCase(),role=b.role,pw=String(b.password||'');
  need(name&&EMAIL.test(email),'Enter a name and a valid email.');need(ROLES.includes(role),'Choose a valid role.');
  need(!db.users.some(x=>x.email===email&&x.id!==b.id),'That email is already in use.');need(!pw||pw.length>=8,'Password must be at least 8 characters.');
  if(b.id){const x=db.users.find(x=>x.id===b.id);need(x,'User not found.',404);need(x.id!==u.id||role==='admin','You cannot remove your own admin role.');
   Object.assign(x,{name,email,role});if(role==='employer')x.company=x.company||name;if(pw)x.pw=hash(pw);return'User updated.'}
  need(pw,'Set a password of at least 8 characters.');db.users.push({id:'u'+db.n++,name,email,role,pw:hash(pw),...(role==='employer'&&{company:name})});return'User created.'},
 userDel(u,b){need(b.id!==u.id,'You cannot delete your own account.');const x=db.users.find(x=>x.id===b.id);need(x,'User not found.',404);
  db.jobs.filter(j=>j.owner===x.id).forEach(j=>dropApps(a=>a.job===j.id));db.jobs=db.jobs.filter(j=>j.owner!==x.id);dropApps(a=>a.user===x.id);
  fs.rmSync(path.join(RES,x.id),{force:true});db.users=db.users.filter(y=>y!==x);return'User deleted.'},
 jobSet(u,b){need(['approved','rejected'].includes(b.status),'Invalid status.');myJob(u,b.id).status=b.status;return'Job '+b.status+'.'},
 jobDel(u,b){const j=myJob(u,b.id);dropApps(a=>a.job===j.id);db.jobs=db.jobs.filter(x=>x!==j);return'Job deleted.'},
 post(u,b){const f={title:s(b.title,120),loc:s(b.loc,80)||'Remote',type:TYPES.includes(b.type)?b.type:'Full-time',salary:s(b.salary,60),desc:s(b.desc,3000),req:s(b.req,1500)};
  need(f.title&&f.desc,'Title and description are required.');const st=db.cfg.approve?'pending':'approved';
  if(b.id){Object.assign(myJob(u,b.id),f,{status:st});return'Job updated.'}
  db.jobs.push({id:db.n++,owner:u.id,company:u.company,status:st,...f});return db.cfg.approve?'Job posted. Waiting for admin approval.':'Job posted and live.'},
 submit(u,b){const j=db.jobs.find(j=>j.id===b.id&&j.status==='approved');need(j,'This job is not open for applications.');need(u.resume,'Add a resume in your profile first.');
  need(!db.apps.some(a=>a.job===j.id&&a.user===u.id),'You already applied to this job.');
  const id=db.n++;fs.copyFileSync(path.join(RES,u.id),path.join(RES,'a'+id));db.apps.push({id,job:j.id,user:u.id,status:'Submitted',cover:s(b.cover,3000),resume:u.resume});return'Application submitted.'},
 status(u,b){const a=db.apps.find(a=>a.id===b.id);need(a&&db.jobs.some(j=>j.id===a.job&&j.owner===u.id),'Application not found.',404);need(ST.includes(b.status),'Invalid status.');a.status=b.status;return'Status updated to '+b.status+'.'},
 msg(u,b){const a=db.apps.find(a=>a.id===b.id);need(a&&db.jobs.some(j=>j.id===a.job&&j.owner===u.id),'Application not found.',404);const t=s(b.text,1000);need(t,'Type a message first.');db.msgs.push({app:a.id,text:t});return'Message sent.'},
 profile(u,b){const f=b.file;
  if(f){const n=s(f.name,120),buf=Buffer.from(String(f.data||''),'base64'),h=buf.subarray(0,4).toString('latin1'),ok=h==='%PDF'||h.startsWith('PK')||buf.subarray(0,4).toString('hex')==='d0cf11e0';
   need(/\.(pdf|docx?)$/i.test(n)&&ok,'Upload a PDF or Word file.');need(buf.length&&buf.length<=db.cfg.maxMB*1048576,'File is too large.');fs.writeFileSync(path.join(RES,u.id),buf);u.resume=n}
  u.name=s(b.name,100)||u.name;u.skills=s(b.skills,300);return'Profile updated.'},
 cfg(u,b){db.cfg={site:s(b.site,60)||'HireLoop',approve:!!b.approve,reg:!!b.reg,maxMB:Math.min(20,Math.max(1,+b.maxMB||5))};return'Settings saved.'}};

const tries=new Map(),ipOf=r=>String(r.headers['x-forwarded-for']||r.socket.remoteAddress||'').split(',')[0].trim();
const SEC={'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'same-origin','Content-Security-Policy':"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com"};
const send=(res,c,o,h={})=>{res.writeHead(c,{'Content-Type':'application/json','Cache-Control':'no-store',...SEC,...h});res.end(JSON.stringify(o))};
const body=req=>new Promise((ok,no)=>{const d=[];let n=0;req.on('data',c=>{n+=c.length;if(n>28e6){no(new E('Request too large.',413));req.destroy()}else d.push(c)});
 req.on('end',()=>{try{ok(JSON.parse(Buffer.concat(d).toString()||'{}'))}catch{no(new E('Bad request.'))}})});
function login(req,res,b){const ip=ipOf(req),t=tries.get(ip)||{n:0,r:0};if(Date.now()>t.r){t.n=0;t.r=Date.now()+9e5}
 need(t.n<10,'Too many attempts. Try again in 15 minutes.',429);const x=db.users.find(x=>x.email===s(b.email,200).toLowerCase());
 if(!x||!check(String(b.password||''),x.pw)){t.n++;tries.set(ip,t);throw new E('Incorrect email or password.',401)}
 log(x.name+' signed in');save();send(res,200,{ok:true},{'Set-Cookie':cookie(mk(x.id),604800,req)})}
function register(req,res,b){need(db.cfg.reg,'Registration is closed.',403);const name=s(b.name,100),email=s(b.email,200).toLowerCase(),role=b.role,pw=String(b.password||'');
 need(name&&EMAIL.test(email),'Enter your name and a valid email.');need(['employer','seeker'].includes(role),'Choose employer or job seeker.');
 need(pw.length>=8,'Password must be at least 8 characters.');need(!db.users.some(x=>x.email===email),'That email is already registered.');
 const x={id:'u'+db.n++,name,email,role,pw:hash(pw)};if(role==='employer')x.company=s(b.company,100)||name;db.users.push(x);log(name+' registered as '+role);save();
 send(res,200,{ok:true},{'Set-Cookie':cookie(mk(x.id),604800,req)})}

const PAGE=fs.readFileSync(path.join(__dirname,'public','index.html'));
http.createServer(async(req,res)=>{try{
 const p=new URL(req.url,'http://x').pathname,u=who(req),get=req.method==='GET';
 if(get&&p==='/healthz')return send(res,200,{ok:true});
 if(get&&(p==='/'||p==='/index.html')){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8',...SEC});return res.end(PAGE)}
 if(get&&p==='/api/state'){need(u,'Please sign in.',401);return send(res,200,{me:pub(u),state:state(u)})}
 const m=get&&p.match(/^\/api\/resume\/(\d+)$/);
 if(m){need(u,'Please sign in.',401);const a=db.apps.find(a=>a.id===+m[1]),j=a&&db.jobs.find(j=>j.id===a.job);
  need(a&&(u.role==='admin'||a.user===u.id||j?.owner===u.id),'Not found.',404);
  res.writeHead(200,{'Content-Type':'application/octet-stream','Content-Disposition':`attachment; filename="${a.resume.replace(/[^\w.\- ]/g,'_')}"`,...SEC});return fs.createReadStream(path.join(RES,'a'+a.id)).pipe(res)}
 if(req.method==='POST'&&p.startsWith('/api/')){
  need((req.headers['content-type']||'').startsWith('application/json'),'Unsupported request.',415);const b=await body(req);
  if(p==='/api/register')return register(req,res,b);if(p==='/api/login')return login(req,res,b);
  if(p==='/api/logout')return send(res,200,{ok:true},{'Set-Cookie':cookie('',0,req)});
  if(p==='/api/act'){need(u,'Please sign in.',401);const f=ACT[b.a];need(f,'Unknown action.',404);need(ROLE[b.a].split(' ').includes(u.role),'You do not have access to that.',403);
   const msg=f(u,b);log(`${u.name} (${u.role}): ${msg}`);save();return send(res,200,{msg})}}
 throw new E('Not found.',404)
}catch(e){if(e instanceof E)return send(res,e.c,{error:e.message});console.error(e);send(res,500,{error:'Server error.'})}}).listen(PORT,()=>console.log('Job portal listening on :'+PORT));
