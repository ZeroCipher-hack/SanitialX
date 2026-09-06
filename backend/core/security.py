"""
JWT Authentication & Security Utilities for SentinelX.

Architecture Invariants:
- Role-based token claims (reader, analyst, admin).
- Endpoint agents use high-entropy opaque tokens; only SHA-256 digests are stored.
- Never include database/redis credentials or sensitive system secrets in tokens.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from pydantic import BaseModel

DEFAULT_EXPIRATION_MINUTES = 60
_PBKDF2_ALGORITHM = "sha256"
_PBKDF2_ITERATIONS = 390_000
_PBKDF2_SALT_BYTES = 16


def hash_password(password: str) -> str:
    salt = secrets.token_hex(_PBKDF2_SALT_BYTES)
    derived = hashlib.pbkdf2_hmac(
        _PBKDF2_ALGORITHM, password.encode("utf-8"), bytes.fromhex(salt), _PBKDF2_ITERATIONS
    )
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt}${derived.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, iterations_str, salt, expected_hex = password_hash.split("$", 3)
    except ValueError:
        return False
    if algorithm != "pbkdf2_sha256":
        return False
    try:
        iterations = int(iterations_str)
    except ValueError:
        return False
    derived = hashlib.pbkdf2_hmac(
        _PBKDF2_ALGORITHM, password.encode("utf-8"), bytes.fromhex(salt), iterations
    )
    return hmac.compare_digest(derived.hex(), expected_hex)


def generate_agent_token() -> str:
    """Generate a high-entropy opaque credential returned only at enrollment."""
    return secrets.token_urlsafe(32)


def hash_agent_token(token: str) -> str:
    """Return a deterministic digest safe to persist instead of the raw agent token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_agent_token(token: str, expected_hash: str | None) -> bool:
    """Constant-time verification for an opaque endpoint-agent credential."""
    if not token or not expected_hash:
        return False
    return hmac.compare_digest(hash_agent_token(token), expected_hash)


class TokenPayload(BaseModel):
    sub: str
    role: str
    exp: int
    jti: str


def create_access_token(
    subject: str,
    role: str,
    secret_key: str,
    algorithm: str = "HS256",
    expires_delta: timedelta | None = None,
) -> str:
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=DEFAULT_EXPIRATION_MINUTES)
    )
    payload = {
        "sub": subject,
        "role": role,
        "exp": int(expire.timestamp()),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, secret_key, algorithm=algorithm)


def decode_access_token(
    token: str,
    secret_key: str,
    algorithm: str = "HS256",
) -> TokenPayload:
    decoded = jwt.decode(token, secret_key, algorithms=[algorithm])
    return TokenPayload(**decoded)
