"""
User domain model for SentinelX authentication.

Pure domain object — no infrastructure imports allowed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class User:
    """A SentinelX platform user."""

    user_id: str
    username: str
    password_hash: str
    role: str  # one of: reader, analyst, admin
    is_active: bool
    created_at: datetime

    def __post_init__(self) -> None:
        # Guards against a plaintext (or otherwise malformed) password ever
        # being wrapped in a User object — the only valid password_hash
        # values are ones produced by core.security.hash_password().
        if not self.password_hash.startswith("pbkdf2_sha256$"):
            raise ValueError(
                "password_hash must be a valid pbkdf2_sha256 hash produced by "
                "core.security.hash_password() — never a plaintext password."
            )
        if self.role not in {"reader", "analyst", "admin"}:
            raise ValueError(f"role must be one of reader/analyst/admin, got '{self.role}'.")
