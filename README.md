# SentinelX — Modular Production-Grade Async SIEM Backend

SentinelX is a modular, high-performance, async-first SIEM (Security Information and Event Management) backend system built with Python, FastAPI, Scapy, Redis Streams, PostgreSQL, and SQLAlchemy 2.x.

---

## Architecture Overview

1. **Sensors Layer:** Network sniffer (`ScapySensor`) capturing live network events into `RawEvent` objects using a thread-to-async event loop bridge.
2. **Normalizers Layer:** `Dispatcher` and `ScapyNormalizer` transforming raw network payloads into immutable `NormalizedEvent` canonical events.
3. **Pipeline & Bus Layer:** `Pipeline` dispatching normalized events to `RedisEventBus` backed by Redis Streams (`sentinelx.events`).
4. **Correlation Engine & Worker:** `CorrelationWorker` running background event stream processing, evaluating detection rules (`PortScan`, `SSHBruteforce`, `Honeypot`), and building `Incident` domain entities.
5. **Domain & Persistence Layer:** `IncidentService` with optimistic concurrency control (`version` check) persisting incidents to PostgreSQL via `PostgresIncidentRepository` and `PostgresDetectionRuleRepository`.
6. **API & Security Layer:** FastAPI application (`main.py`) exposing `/api/v1/*` endpoints protected by JWT Bearer token authentication and role-based access control (`reader`, `analyst`, `admin`).

---

## Quickstart: Docker Compose Deployment

### 1. Environment Configuration
Copy the example environment file and adjust secrets for production:
```bash
cp backend/.env.example .env
```

### 2. Start the SentinelX Full Stack
Run the complete multi-container stack:
```bash
docker compose up -d --build
```

This starts:
- **`postgres`**: PostgreSQL 16 database container with volume persistence (`postgres_data`).
- **`redis`**: Redis 7 container configured with AOF persistence (`redis_data`).
- **`migrate`**: One-shot container running `alembic upgrade head` to apply database migrations before backend and worker boot up.
- **`backend`**: FastAPI web application running on port `8000`.
- **`worker`**: `CorrelationWorker` background stream consumer.

---

## Health Checks & API Usage

### 1. Health Endpoints
- **Liveness Probe (Unauthenticated):**
  ```bash
  curl http://localhost:8000/api/v1/health
  ```
  Returns `{"status": "ok", "is_ready": true, "details": {"service": "SentinelX Backend"}}`.

- **Readiness Probe (Requires JWT Bearer Auth):**
  ```bash
  curl -H "Authorization: Bearer <JWT_TOKEN>" http://localhost:8000/api/v1/health/ready
  ```

### 2. Obtaining a JWT Authentication Token
```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username": "analyst_jane", "password": "secret_password", "requested_role": "analyst"}'
```

---

## Running Integration & E2E Tests Locally

Ensure your virtual environment is active:
```bash
cd backend
source .venv/bin/activate
PYTHONPATH=. python -m pytest tests/ -v
```

### Isolated Test Infrastructure (Phase 16)
If you want to run integration tests against separate containerized Redis & Postgres instances on non-standard ports (Postgres on 5433, Redis on 6380):
```bash
docker compose -f docker-compose.test.yml up -d
```
