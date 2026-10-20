# HireLoop: online job portal

Admin, Employer and Job Seeker dashboards with real accounts, roles, resume uploads and persistent data.
No npm dependencies: it needs only Node 18+.

## Run locally
    ADMIN_EMAIL=you@example.com ADMIN_PASSWORD=choose-a-strong-password node server.js
Open http://localhost:3000 and sign in as the admin. If you skip ADMIN_PASSWORD, a random one is printed on first start.

## Environment variables
| Name | Purpose |
|---|---|
| PORT | HTTP port (hosts usually set this) |
| DATA_DIR | Where data and resumes are stored. Must be on a persistent disk |
| SESSION_SECRET | Long random string that signs login cookies |
| ADMIN_EMAIL, ADMIN_PASSWORD | Creates the first admin on the first start only |

## Deploy
- **Render:** push this folder to GitHub, create a Blueprint from `render.yaml`, set ADMIN_EMAIL and ADMIN_PASSWORD.
- **Docker / any VPS:** `docker build -t hireloop .` then `docker run -p 80:3000 -v hireloop-data:/data -e SESSION_SECRET=... -e ADMIN_EMAIL=... -e ADMIN_PASSWORD=... hireloop`
- **Railway / Fly.io:** deploy the Dockerfile and mount a volume at `/data`.

Put it behind HTTPS (the hosts above do this for you). Cookies become `Secure` automatically when the proxy sends `X-Forwarded-Proto: https`.
Free tiers with no persistent disk lose all data on restart.

## How it works
- Roles: admin (users, job approval, settings, statistics, activity log), employer (post jobs, review applications, message candidates), job seeker (search, apply, track, profile and resume, recommendations).
- Passwords use scrypt. Sessions are signed HttpOnly cookies. Every action is role-checked on the server. Login is rate limited.
- Data is a JSON file (`DATA_DIR/db.json`) plus resume files, written atomically. This suits a small to medium site on one server. For many concurrent users, move storage to PostgreSQL or MongoDB.
- Back up the whole DATA_DIR.
- Not included: email notifications, password reset, email verification.
