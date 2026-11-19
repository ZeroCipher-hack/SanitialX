"""Tests for offline Ed25519 license verification."""

from __future__ import annotations

import base64
import copy
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.license import canonical_bytes, load_license, verify_license

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _pub(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def _doc(key: Ed25519PrivateKey, days: int = 30) -> dict:
    payload = {
        "customer": "Test Bank", "plan": "pro", "max_agents": 50, "features": ["soar"],
        "issued_at": NOW.isoformat(), "expires_at": (NOW + timedelta(days=days)).isoformat(),
    }
    return {"payload": payload, "signature": base64.b64encode(key.sign(canonical_bytes(payload))).decode()}


def test_valid_license() -> None:
    key = Ed25519PrivateKey.generate()
    status = verify_license(_doc(key), _pub(key), NOW)
    assert status.is_valid and status.customer == "Test Bank" and status.max_agents == 50 and status.days_left == 30


def test_expired_license() -> None:
    key = Ed25519PrivateKey.generate()
    status = verify_license(_doc(key, days=-1), _pub(key), NOW)
    assert status.state == "EXPIRED" and not status.is_valid


def test_tampered_payload_rejected() -> None:
    key = Ed25519PrivateKey.generate()
    doc = _doc(key)
    forged = copy.deepcopy(doc)
    forged["payload"]["max_agents"] = 100000
    assert verify_license(forged, _pub(key), NOW).state == "INVALID"


def test_wrong_key_and_garbage_rejected() -> None:
    key, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    assert verify_license(_doc(key), _pub(other), NOW).state == "INVALID"
    assert verify_license({"payload": {}, "signature": "!!!"}, _pub(key), NOW).state == "INVALID"
    assert verify_license("nope", _pub(key), NOW).state == "INVALID"


def test_unconfigured_and_missing(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    assert verify_license(_doc(key), "", NOW).state == "UNCONFIGURED"
    assert load_license(str(tmp_path / "none.json"), _pub(key), NOW).state == "MISSING"
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    assert load_license(str(bad), _pub(key), NOW).state == "INVALID"


def test_vendor_tool_roundtrip(tmp_path: Path) -> None:
    tool = Path(__file__).resolve().parent.parent / "scripts" / "license_tool.py"
    subprocess.run([sys.executable, str(tool), "keygen", "--out", str(tmp_path)], check=True, capture_output=True)
    out = tmp_path / "license.json"
    subprocess.run(
        [sys.executable, str(tool), "sign", "--private-key", str(tmp_path / "license_private.key"),
         "--customer", "Bank", "--max-agents", "10", "--days", "5", "--feature", "soar", "--out", str(out)],
        check=True, capture_output=True,
    )
    status = load_license(str(out), (tmp_path / "license_public.key").read_text())
    assert status.is_valid and status.max_agents == 10 and status.features == ["soar"]
    assert oct((tmp_path / "license_private.key").stat().st_mode & 0o777) == "0o600"
    assert json.loads(out.read_text())["payload"]["customer"] == "Bank"


# --- API ---------------------------------------------------------------

from core.security import create_access_token  # noqa: E402
from main import app  # noqa: E402
from tests.test_api import client  # noqa: E402,F401  (shared fixture)


def _headers(role: str) -> dict[str, str]:
    s = app.state.container.settings
    token = create_access_token(subject="u", role=role, secret_key=s.jwt_secret_key, algorithm=s.jwt_algorithm)
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_license_api_install_and_status(client, tmp_path: Path) -> None:  # noqa: F811
    key = Ed25519PrivateKey.generate()
    settings = app.state.container.settings
    settings.license_public_key = _pub(key)
    settings.license_file = str(tmp_path / "license.json")
    # real clock: build a document valid for a year from now
    now = datetime.now(timezone.utc)
    payload = {"customer": "Bank", "plan": "pro", "max_agents": 5, "features": [],
               "issued_at": now.isoformat(), "expires_at": (now + timedelta(days=365)).isoformat()}
    doc = {"payload": payload, "signature": base64.b64encode(key.sign(canonical_bytes(payload))).decode()}

    assert (await client.get("/api/v1/license", headers=_headers("analyst"))).json()["state"] == "MISSING"
    assert (await client.post("/api/v1/license", json=doc, headers=_headers("analyst"))).status_code == 403

    forged = copy.deepcopy(doc)
    forged["payload"]["max_agents"] = 9999
    bad = await client.post("/api/v1/license", json=forged, headers=_headers("admin"))
    assert bad.status_code == 422 and not Path(settings.license_file).exists()

    ok = await client.post("/api/v1/license", json=doc, headers=_headers("admin"))
    assert ok.status_code == 200 and ok.json()["state"] == "VALID"
    shown = await client.get("/api/v1/license", headers=_headers("analyst"))
    assert shown.json()["customer"] == "Bank" and shown.json()["max_agents"] == 5


# --- enrollment enforcement ---------------------------------------------

from core.license import LicenseStatus, enrollment_block_reason  # noqa: E402


def test_enrollment_block_reason_rules() -> None:
    valid = LicenseStatus("VALID", max_agents=2)
    assert enrollment_block_reason(LicenseStatus("UNCONFIGURED"), 999) is None
    assert enrollment_block_reason(valid, 1) is None
    assert "limit" in enrollment_block_reason(valid, 2)
    assert "expired" in enrollment_block_reason(LicenseStatus("EXPIRED", "License has expired."), 0)
    assert enrollment_block_reason(LicenseStatus("MISSING", "No license file installed."), 0)


@pytest.mark.asyncio
async def test_enroll_enforces_agent_limit(client, tmp_path: Path, monkeypatch) -> None:  # noqa: F811
    key = Ed25519PrivateKey.generate()
    settings = app.state.container.settings
    now = datetime.now(timezone.utc)
    payload = {"customer": "Bank", "plan": "pro", "max_agents": 1, "features": [],
               "issued_at": now.isoformat(), "expires_at": (now + timedelta(days=30)).isoformat()}
    lic = tmp_path / "license.json"
    lic.write_text(json.dumps({"payload": payload, "signature": base64.b64encode(key.sign(canonical_bytes(payload))).decode()}))
    settings.license_public_key = _pub(key)
    settings.license_file = str(lic)
    monkeypatch.setattr("api.agents.get_settings", lambda: settings)

    def enroll(agent_id: str):
        return client.post(
            "/api/v1/agents/enroll",
            json={"agent_id": agent_id, "hostname": "h", "ip_address": "10.0.0.1", "os": "linux"},
            headers={"X-Enrollment-Key": settings.api_key},
        )

    assert (await enroll("agent-001")).status_code == 201
    over = await enroll("agent-002")
    assert over.status_code == 402 and "limit" in over.json()["detail"]
    assert (await enroll("agent-001")).status_code == 201  # re-enroll existing agent is not a new seat
