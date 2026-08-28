# SentinelX — Modular Async SIEM Backend

[![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-async-green?logo=fastapi)](https://fastapi.tiangolo.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-blue?logo=postgresql)](https://www.postgresql.org/)
[![Redis](https://img.shields.io/badge/Redis-Streams-red?logo=redis)](https://redis.io/)
[![Docker](https://img.shields.io/badge/Docker-Compose-blue?logo=docker)](https://www.docker.com/)

**SentinelX** is a security-focused, async-first SIEM backend for ingesting network events, normalizing telemetry, correlating detections, and managing security incidents through a secured REST API.

> **Status:** Active development

## Why SentinelX?

The project demonstrates a production-oriented security event pipeline rather than a simple packet sniffer:

- Network telemetry collection with Scapy
- Canonical event normalization
- Redis Streams event transport
- Background correlation and detection workers
- Incident persistence in PostgreSQL
- JWT authentication and role-based access control
- Dockerized development and test infrastructure
- Automated database migrations with Alembic

## Architecture

```text
Network Traffic
      │
      ▼
 Scapy Sensor
      │
      ▼
 Event Normalizer
      │
      ▼
 Redis Streams
      │
      ▼
 Correlation Worker
      │
      ├── Port Scan Detection
      ├── SSH Brute-force Detection
      └── Honeypot Detection
      │
      ▼
 Incident Service
      │
      ▼
 PostgreSQL
      │
      ▼
 FastAPI REST API
      │
      ▼
 JWT + RBAC
```

## Core Components

| Layer | Responsibility |
|---|---|
| Sensors | Capture network events with Scapy |
| Normalizers | Convert raw telemetry into canonical events |
| Event Bus | Transport events through Redis Streams |
| Correlation Engine | Evaluate detection rules and create incidents |
| Persistence | Store incidents and detection rules in PostgreSQL |
| API | Expose `/api/v1/*` endpoints through FastAPI |
| Security | JWT Bearer authentication and `reader` / `analyst` / `admin` RBAC |

## Detection Rules

Current detection examples include:

- Port scanning
- SSH brute-force activity
- Honeypot events

The architecture is designed so additional detection rules can be added without rewriting the ingestion pipeline.

## Tech Stack

**Backend:** Python, FastAPI, SQLAlchemy 2.x, Alembic  
**Security/Network:** Scapy, JWT, RBAC  
**Data:** PostgreSQL 16, Redis 7 / Redis Streams  
**Infrastructure:** Docker Compose  
**Testing:** pytest, integration/E2E test infrastructure

## Quick Start

### 1. Configure environment

```bash
cp backend/.env.example .env
```

Review the environment values and replace development secrets before using the stack outside local development.

### 2. Start the stack

```bash
docker compose up -d --build
```

The Compose stack includes:

- `postgres` — PostgreSQL 16 with persistent storage
- `redis` — Redis 7 with AOF persistence
- `migrate` — Alembic migration job
- `backend` — FastAPI API on port `8000`
- `worker` — background correlation worker

### 3. Check service health

```bash
curl http://localhost:8000/api/v1/health
```

Authenticated readiness check:

```bash
curl -H "Authorization: Bearer <JWT_TOKEN>" \
  http://localhost:8000/api/v1/health/ready
```

## Authentication

Obtain a JWT token through the authentication endpoint:

```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"analyst_jane","password":"secret_password","requested_role":"analyst"}'
```

Use the returned token as a Bearer token for protected endpoints.

## Testing

Run the backend test suite locally:

```bash
cd backend
source .venv/bin/activate
PYTHONPATH=. python -m pytest tests/ -v
```

For isolated integration infrastructure:

```bash
docker compose -f docker-compose.test.yml up -d
```

## Security

Security-sensitive reports should be submitted privately. See [`SECURITY.md`](SECURITY.md) for the reporting policy.

**Never commit:**

- `.env` files containing real secrets
- API keys or tokens
- production credentials
- private certificates
- real customer or production data

## Roadmap

- [ ] Expand detection rule library
- [ ] Improve event enrichment and correlation
- [ ] Add richer incident investigation workflows
- [ ] Expand observability and metrics
- [ ] Harden production deployment configuration
- [ ] Increase automated security and integration coverage

## Project Structure

```text
SanitialX/
├── backend/
│   ├── app/
│   ├── tests/
│   └── migrations/
├── docker-compose.yml
├── docker-compose.test.yml
└── README.md
```

## License

See the repository license for usage terms.
