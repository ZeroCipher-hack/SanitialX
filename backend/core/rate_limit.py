"""
Simple Redis-backed fixed-window rate limiter.

Used to throttle POST /auth/token so credential stuffing / brute force
cannot run at full speed. Keyed by client IP + username so one attacker
cannot lock out a real user by hammering their username from elsewhere,
and so one IP cannot be used to brute-force many usernames unthrottled.

Note: this module accepts an already-constructed client (typed loosely as
Any) rather than importing the redis package itself, so that
event_bus/redis_bus.py remains the sole permitted site for that import in
the codebase, per architecture.md's stated invariant.
"""

from __future__ import annotations

from typing import Any

WINDOW_SECONDS = 300  # 5 minutes
MAX_ATTEMPTS = 5      # 5 attempts per window


async def check_login_rate_limit(redis_client: Any, key: str) -> bool:
    """Record one attempt for `key` and report whether it is still allowed.

    Returns True if the caller is within the allowed rate, False if the
    caller has exceeded MAX_ATTEMPTS within the current WINDOW_SECONDS.
    """
    redis_key = f"login_attempts:{key}"
    count = await redis_client.incr(redis_key)
    if count == 1:
        # First attempt in this window — start the TTL.
        await redis_client.expire(redis_key, WINDOW_SECONDS)
    return count <= MAX_ATTEMPTS


async def reset_login_rate_limit(redis_client: Any, key: str) -> None:
    """Clear the counter for `key`, e.g. after a successful login."""
    await redis_client.delete(f"login_attempts:{key}")
