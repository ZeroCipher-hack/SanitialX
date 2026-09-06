#!/usr/bin/env python3
"""SanitialX Docker/API smoke test.

Usage:
  SANITIALX_SMOKE_USERNAME=admin \
  SANITIALX_SMOKE_PASSWORD='...' \
  python3 scripts/docker_smoke_test.py

Optional:
  SANITIALX_BASE_URL=http://127.0.0.1:8000

The script never writes credentials or tokens to disk and only executes a
non-destructive NOTIFY_ANALYST SOAR action.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

BASE_URL = os.getenv("SANITIALX_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
USERNAME = os.getenv("SANITIALX_SMOKE_USERNAME", "")
PASSWORD = os.getenv("SANITIALX_SMOKE_PASSWORD", "")


def ok(label: str, detail: str = "") -> None:
    suffix = f" — {detail}" if detail else ""
    print(f"[PASS] {label}{suffix}")


def fail(label: str, detail: str) -> None:
    print(f"[FAIL] {label} — {detail}", file=sys.stderr)
    raise SystemExit(1)


def request(method: str, path: str, *, token: str | None = None, body: dict[str, Any] | None = None, expect_json: bool = True):
    headers = {"Accept": "application/json"}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(f"{BASE_URL}{path}", data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=30) as response:
            raw = response.read()
            status = response.status
            content_type = response.headers.get("Content-Type", "")
    except HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")
        fail(f"{method} {path}", f"HTTP {exc.code}: {payload[:500]}")
    except URLError as exc:
        fail(f"{method} {path}", f"connection error: {exc.reason}")
    if not 200 <= status < 300:
        fail(f"{method} {path}", f"unexpected HTTP {status}")
    if not expect_json:
        return raw.decode("utf-8", errors="replace"), content_type
    try:
        return json.loads(raw.decode("utf-8")) if raw else None
    except json.JSONDecodeError:
        fail(f"{method} {path}", f"expected JSON, got {content_type}")


def check_compose() -> None:
    try:
        proc = subprocess.run(
            ["docker", "compose", "ps"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        fail("Docker Compose", str(exc))
    if proc.returncode != 0:
        fail("Docker Compose", (proc.stderr or proc.stdout).strip()[:500])
    output = proc.stdout
    required = ["sentinelx-backend", "sentinelx-postgres", "sentinelx-redis", "sentinelx-worker"]
    missing = [name for name in required if name not in output]
    if missing:
        fail("Docker Compose services", f"missing from compose ps: {', '.join(missing)}")
    ok("Docker Compose services", "backend/postgres/redis/worker visible")


def main() -> None:
    print(f"SanitialX smoke test: {BASE_URL}")
    if not USERNAME or not PASSWORD:
        fail(
            "Credentials",
            "set SANITIALX_SMOKE_USERNAME and SANITIALX_SMOKE_PASSWORD; create an operator with `docker compose exec backend python -m scripts.create_user --username admin --role admin` if needed",
        )

    check_compose()

    health = request("GET", "/api/v1/health")
    if not isinstance(health, dict):
        fail("Health", "response is not an object")
    ok("Public health")

    login = request("POST", "/api/v1/auth/token", body={"username": USERNAME, "password": PASSWORD})
    token = login.get("access_token") if isinstance(login, dict) else None
    role = login.get("role") if isinstance(login, dict) else None
    if not token:
        fail("Authentication", "access_token missing")
    if role not in {"analyst", "admin"}:
        fail("Authentication role", f"smoke test needs analyst/admin, got {role!r}")
    ok("Authentication", f"role={role}")

    ready = request("GET", "/api/v1/health/ready", token=token)
    if not isinstance(ready, dict):
        fail("Readiness", "response is not an object")
    if ready.get("is_ready") is False:
        fail("Readiness", json.dumps(ready)[:500])
    ok("Authenticated readiness")

    scenarios = request("GET", "/api/v1/simulations/scenarios", token=token)
    if not isinstance(scenarios, list) or not scenarios:
        fail("Simulation scenarios", "no scenarios returned")
    ok("Simulation scenarios", f"count={len(scenarios)}")

    simulation = request(
        "POST",
        "/api/v1/simulations/run",
        token=token,
        body={"scenario_name": "WEB_APP_COMPROMISE"},
    )
    incident_id = simulation.get("generated_incident_id") if isinstance(simulation, dict) else None
    if not incident_id:
        fail("Controlled attack simulation", f"no incident generated: {simulation}")
    ok("Controlled attack simulation", f"incident={incident_id}")

    incident = request("GET", f"/api/v1/incidents/{incident_id}", token=token)
    if not isinstance(incident, dict) or incident.get("incident_id") != incident_id:
        fail("Incident retrieval", "generated incident could not be retrieved")
    ok("Incident persistence", f"severity={incident.get('severity')} status={incident.get('status')}")

    action = request(
        "POST",
        "/api/v1/soar/actions",
        token=token,
        body={
            "incident_id": incident_id,
            "action_type": "NOTIFY_ANALYST",
            "target_type": "INCIDENT",
            "target_value": incident_id,
            "parameters": {"channel": "smoke-test"},
            "risk_level": "LOW",
            "reason": "Validate approval-based SOAR workflow during Docker smoke test.",
        },
    )
    action_id = action.get("action_id") if isinstance(action, dict) else None
    if not action_id or action.get("status") != "PENDING":
        fail("SOAR action creation", f"unexpected response: {action}")
    ok("SOAR action creation", f"action={action_id}")

    approved = request(
        "POST",
        f"/api/v1/soar/actions/{action_id}/approve",
        token=token,
        body={"note": "Approved by automated non-destructive smoke test."},
    )
    if approved.get("status") != "APPROVED":
        fail("SOAR approval", f"unexpected status: {approved.get('status')}")
    ok("SOAR approval")

    executed = request("POST", f"/api/v1/soar/actions/{action_id}/execute", token=token)
    if executed.get("status") != "EXECUTED":
        fail("SOAR execution", f"unexpected status: {executed.get('status')}")
    ok("SOAR safe execution", executed.get("execution_result", {}).get("mode", ""))

    audit = request("GET", f"/api/v1/soar/actions/{action_id}/audit", token=token)
    events = [item.get("event") for item in audit] if isinstance(audit, list) else []
    for expected in ("REQUESTED", "APPROVED", "EXECUTED"):
        if expected not in events:
            fail("SOAR audit trail", f"missing {expected}: {events}")
    ok("SOAR audit trail", " -> ".join(events))

    report_html, content_type = request(
        "GET",
        f"/api/v1/reports/{incident_id}/print",
        token=token,
        expect_json=False,
    )
    required_report_markers = ["Incident Investigation Report", incident_id, "SOAR Response Actions", "Response Timeline"]
    missing_markers = [marker for marker in required_report_markers if marker not in report_html]
    if missing_markers:
        fail("Professional report", f"missing markers: {', '.join(missing_markers)}")
    ok("Professional report", content_type)

    print("\n=== SANITIALX DOCKER SMOKE TEST: PASS ===")
    print(f"Generated demo incident: {incident_id}")
    print(f"Validated SOAR action:   {action_id}")


if __name__ == "__main__":
    main()
