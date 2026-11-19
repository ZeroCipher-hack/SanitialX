"""Offline license verification (Ed25519).

The vendor signs a license payload with a private key that never leaves the
vendor. The customer installation only holds the public key, so verification
works without internet access. The payload is signed in canonical JSON form
(sorted keys, no whitespace), which both signer and verifier reproduce.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# State values: VALID, EXPIRED, INVALID (bad/tampered), MISSING (no file), UNCONFIGURED (no public key)


@dataclass
class LicenseStatus:
    state: str
    reason: str = ""
    customer: str | None = None
    plan: str | None = None
    max_agents: int | None = None
    features: list[str] = field(default_factory=list)
    issued_at: str | None = None
    expires_at: str | None = None
    days_left: int | None = None

    @property
    def is_valid(self) -> bool:
        return self.state == "VALID"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def verify_license(
    document: Any, public_key_b64: str, now: datetime | None = None
) -> LicenseStatus:
    """Verify a license document of the form {"payload": {...}, "signature": "<base64>"}."""
    now = now or datetime.now(timezone.utc)
    if not public_key_b64.strip():
        return LicenseStatus("UNCONFIGURED", "No license public key is configured.")
    if not isinstance(document, dict) or not isinstance(document.get("payload"), dict):
        return LicenseStatus("INVALID", "Malformed license document.")

    payload: dict[str, Any] = document["payload"]
    try:
        public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64.strip(), validate=True))
        public_key.verify(base64.b64decode(str(document.get("signature", "")), validate=True), canonical_bytes(payload))
    except (InvalidSignature, binascii.Error, ValueError):
        return LicenseStatus("INVALID", "Signature verification failed.")

    try:
        expires = _parse_time(str(payload["expires_at"]))
        max_agents = int(payload["max_agents"])
    except (KeyError, ValueError, TypeError):
        return LicenseStatus("INVALID", "License payload is missing required fields.")

    days_left = (expires - now).days
    base = dict(
        customer=payload.get("customer"),
        plan=payload.get("plan"),
        max_agents=max_agents,
        features=[str(f) for f in payload.get("features", [])],
        issued_at=payload.get("issued_at"),
        expires_at=expires.isoformat(),
        days_left=days_left,
    )
    if now >= expires:
        return LicenseStatus("EXPIRED", "License has expired.", **base)
    return LicenseStatus("VALID", "", **base)


def load_license(path: str, public_key_b64: str, now: datetime | None = None) -> LicenseStatus:
    """Read and verify the license file at `path` (empty path or missing file -> MISSING)."""
    if not public_key_b64.strip():
        return LicenseStatus("UNCONFIGURED", "No license public key is configured.")
    if not path or not Path(path).is_file():
        return LicenseStatus("MISSING", "No license file installed.")
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return LicenseStatus("INVALID", "License file is not valid JSON.")
    return verify_license(document, public_key_b64, now)
