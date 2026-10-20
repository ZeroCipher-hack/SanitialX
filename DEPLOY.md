# SanitialX — Deployment Guide

Two supported paths. **Managed (Render + Vercel)** is the recommended one for
a small team: cheap, no servers to run, and the backend already understands
Render's Postgres URLs. **Self-hosted (Docker Compose on a VPS)** is the
alternative when you want everything on one box.

Whichever you pick, the single most important post-deploy step is
**verifying the live vulnerability feeds** (NVD / CISA KEV / FIRST EPSS),
because that is what turns the Exposure view from demo data into real data.

---

## Path A — Managed: Render (backend) + Vercel (frontend)

### 1. Backend on Render (Blueprint)

The repo ships `render.yaml`. In Render: **New → Blueprint**, point it at the
repo, and it provisions Postgres, Key Value (Redis), the API, the correlation
worker and the vulnerability scheduler.

- `SANITIALX_JWT_SECRET_KEY` and `SANITIALX_API_KEY` are generated
  automatically and shared across services.
- `alembic upgrade head` runs as the pre-deploy command, so the schema
  (including honeypot + EPSS + active-threat migrations) is applied on every
  deploy.
- Set these in the dashboard after the first deploy:
  - `SANITIALX_FRONTEND_ORIGIN` = your Vercel URL (e.g. `https://sanitialx.vercel.app`) — **required** or the browser will block API calls (CORS).
  - `SANITIALX_GEMINI_API_KEY` = optional; AI analysis degrades gracefully without it.

Health check: Render pings `/api/v1/health` (unauthenticated liveness).

### 2. Frontend on Vercel

- **New Project → import the repo**, set **Root Directory = `frontend`**.
- Environment variable: `NEXT_PUBLIC_API_URL = https://<your-backend>.onrender.com/api/v1`.
- Deploy. Vercel builds with `npm run build` automatically.

> The frontend CSP (`frontend/next.config.ts`) `connect-src` must include your
> real backend origin. It currently allows `https://sanitialx-backend.onrender.com`;
> change that to your actual backend host if different, or the browser blocks
> API calls.

### 3. First operator + verification (both paths)

Create the first admin (Render: use the backend service **Shell**; self-host:
`docker compose exec backend ...`):

```bash
python -m scripts.create_user --username admin --role admin
```

Get a token and confirm the API:

```bash
curl -X POST https://<backend>/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<password>"}'
```

**Verify the live feeds — the step that proves it is real** (admin token):

```bash
curl -X POST "https://<backend>/api/v1/vulnerabilities/sync?hours=72" \
  -H "Authorization: Bearer <JWT>"
# Expect nvd_records_processed > 0, kev_catalog_size > 0, epss_records_updated > 0
```

Then enroll/point an agent at an asset, evaluate it, and open **Exposure** —
real CVEs should appear, ranked by CVSS × EPSS × KEV.

---

## Path B — Self-hosted: Docker Compose on a VPS

Requirements: a VPS with Docker + Docker Compose and outbound HTTPS (for the
feeds).

```bash
git clone https://github.com/ZeroCipher-hack/SanitialX && cd SanitialX
cp backend/.env.example backend/.env
# Edit backend/.env: set a real SANITIALX_JWT_SECRET_KEY (openssl rand -hex 32),
# SANITIALX_API_KEY, SANITIALX_FRONTEND_ORIGIN, and DB/Redis passwords.
docker compose up -d --build        # postgres, redis, migrate, backend, worker, scheduler
docker compose --profile honeypot up -d honeypot   # optional decoys
```

The `migrate` service runs `alembic upgrade head` before the backend starts.
Then create the admin and verify the feeds as in section 3 above.

**Frontend (self-host):** the compose stack does not include the frontend.
Either deploy it to Vercel (section 2) pointing at your VPS backend, or run it
on the VPS:

```bash
cd frontend && npm ci && NEXT_PUBLIC_API_URL=https://<backend>/api/v1 npm run build && npm run start
```

**TLS:** the stack serves plain HTTP on :8000. Put a reverse proxy with
automatic HTTPS in front — e.g. Caddy:

```
your-backend-domain {
    reverse_proxy localhost:8000
}
```

---

## Production readiness — honest status

Ready:
- Migrations apply cleanly on real Postgres (0001–0016), verified.
- Backend understands Render Postgres URLs (`postgres://` + `sslmode`).
- Secrets refuse to boot on known placeholders / weak values.
- CI (GitHub Actions) green: backend tests, migrations, agents, frontend build.

Set before you call it production:
- `SANITIALX_FRONTEND_ORIGIN` = the real frontend origin (CORS).
- Frontend CSP `connect-src` = the real backend origin.
- TLS in front of the backend (managed platforms do this for you).
- Confirm the live feeds actually return data from your deployed environment
  (section 3) — this has only been validated locally so far.

Not yet done (by design — next after first users):
- A running decoy fleet (the honeypot listener is opt-in and unprovisioned).
- Real endpoint agents reporting inventory from production machines.
