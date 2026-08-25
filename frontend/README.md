# SanitialX Frontend

Next.js + TypeScript frontend for the existing SanitialX FastAPI SIEM backend.

## Run

```bash
cd frontend
cp .env.example .env.local
npm install
npm run dev
```

The frontend expects the backend at `http://localhost:8000` by default and uses `/api/v1` for authenticated API calls.

## Current UI

- SOC command-center dashboard
- Security score, critical alerts, active threats, endpoint health
- Threat activity visualization
- Risk posture gauge
- Live security events
- Top attack sources
- Responsive sidebar/topbar
- Threats, Incidents and Detection Rules routes
- API helper for JWT bearer authentication

## Backend contracts already mapped

- `POST /api/v1/auth/token`
- `GET /api/v1/health`
- `GET /api/v1/incidents`
- `GET /api/v1/incidents/{incident_id}`
- `PATCH /api/v1/incidents/{incident_id}/status`
- `GET /api/v1/rules`
- `GET /api/v1/rules/{rule_id}`
- `PUT /api/v1/rules/{rule_id}`
