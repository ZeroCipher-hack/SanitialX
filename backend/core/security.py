"""
JWT Authentication & Security Utilities for SentinelX.

Architecture Invariants:
- Role-based token claims (reader, analyst, admin).
- Never include database/redis credentials or sensitive system secrets in tokens.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from pydantic import BaseModel

DEFAULT_EXPIRATION_MINUTES = 60

# ── Password hashing (PBKDF2-HMAC-SHA256, stdlib only) ─────────────────────
#
# Format: "pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>"
# No third-party dependency (bcrypt/argon2) required; salted + iterated,
# constant-time comparison on verify.

_PBKDF2_ALGORITHM = "sha256"
_PBKDF2_ITERATIONS = 390_000
_PBKDF2_SALT_BYTES = 16


def hash_password(password: str) -> str:
    """Hash a plaintext password for storage. Never store plaintext passwords."""
    salt = secrets.token_hex(_PBKDF2_SALT_BYTES)
    derived = hashlib.pbkdf2_hmac(
        _PBKDF2_ALGORITHM, password.encode("utf-8"), bytes.fromhex(salt), _PBKDF2_ITERATIONS
    )
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt}${derived.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a plaintext password against a stored hash in constant time."""
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
    """Create a signed JWT access token containing subject, role, and jti claims."""
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
    """Decode and validate a JWT access token.

    Raises jwt.PyJWTError on invalid signature, expiration, or format.
    """
    decoded = jwt.decode(token, secret_key, algorithms=[algorithm])
    return TokenPayload(**decoded)
