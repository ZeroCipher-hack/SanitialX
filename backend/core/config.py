"""
SentinelX configuration — single canonical Settings class.

Uses pydantic-settings to load from environment variables (prefixed SENTINELX_)
and an optional .env file. No module-level mutable singleton — callers must
instantiate Settings() explicitly or receive it via dependency injection.
"""

from __future__ import annotations

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Known placeholder values that must never be used outside local dev.
# If either secret matches one of these (or is too short), the app refuses
# to boot. This is intentional — it is the fix for the "forgeable JWT if
# nobody sets the env var" vulnerability found in review.
_INSECURE_SECRET_VALUES = {
    "sentinelx-secret-key-change-in-production",
    "change_this_placeholder_api_key_in_production",
    "sentinelx-jwt-secret-key-change-in-production",
    "change_this_jwt_secret_key_to_a_secure_random_string_in_production",
}
_MIN_SECRET_LENGTH = 32


class Settings(BaseSettings):
    """Canonical application settings for SentinelX.

    All configuration values are loaded from environment variables prefixed
    with ``SENTINELX_``.  A ``.env`` file in the working directory is also
    read automatically if present.
    """

    model_config = SettingsConfigDict(
        env_prefix="SENTINELX_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────────────
    app_name: str = Field(default="SentinelX", description="Application name")
    debug: bool = Field(default=False, description="Enable debug mode")
    log_level: str = Field(default="INFO", description="Logging level")

    # ── Network capture ──────────────────────────────────────────────
    capture_interface: str = Field(
        default="eth0",
        description="Network interface for packet capture",
    )
    capture_filter: str = Field(
        default="",
        description="BPF filter string for packet capture",
    )

    # ── Environment & API ─────────────────────────────────────────────
    environment: str = Field(default="development", description="Execution environment")
    api_host: str = Field(default="0.0.0.0", description="API listen host")
    api_port: int = Field(default=8000, description="API listen port")
    frontend_origin: str = Field(
        default="http://localhost:3000,http://127.0.0.1:3000",
        description="Allowed CORS frontend origins (comma-separated)",
    )

    # No defaults for secrets anymore — Settings() will raise a clear
    # pydantic ValidationError at boot if these env vars are unset, instead
    # of silently falling back to a value that is printed in this file.
    api_key: str = Field(..., description="API Key for placeholder auth")
    jwt_secret_key: str = Field(..., description="JWT signing secret key")
    jwt_algorithm: str = Field(default="HS256", description="JWT signing algorithm")

    # ── Infrastructure ────────────────────────────────────────────────
    database_url: str = Field(
        default="postgresql+asyncpg://sentinelx:sentinelx@localhost:5432/sentinelx",
        description="PostgreSQL async database URL",
    )
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL",
    )

    @model_validator(mode="after")
    def _reject_insecure_secrets(self) -> "Settings":
        """Refuse to boot with a known placeholder or too-short secret.

        This runs for every Settings instantiation, including in tests —
        tests must pass explicit non-placeholder values (see
        tests/test_auth_endpoint.py for the pattern).
        """
        if self.jwt_secret_key in _INSECURE_SECRET_VALUES:
            raise ValueError(
                "SENTINELX_JWT_SECRET_KEY is set to a known placeholder value. "
                "Generate a real secret, e.g. `openssl rand -hex 32`, and set it "
                "via the SENTINELX_JWT_SECRET_KEY environment variable."
            )
        if len(self.jwt_secret_key) < _MIN_SECRET_LENGTH:
            raise ValueError(
                f"SENTINELX_JWT_SECRET_KEY must be at least {_MIN_SECRET_LENGTH} "
                "characters. Generate one with `openssl rand -hex 32`."
            )
        if self.api_key in _INSECURE_SECRET_VALUES:
            raise ValueError(
                "SENTINELX_API_KEY is set to a known placeholder value. "
                "Set a real value via the SENTINELX_API_KEY environment variable."
            )
        return self

    # ── Property aliases ──────────────────────────────────────────────
    @property
    def ENVIRONMENT(self) -> str:
        return self.environment

    @property
    def DATABASE_URL(self) -> str:
        return self.database_url

    @property
    def REDIS_URL(self) -> str:
        return self.redis_url

    @property
    def SNIFFER_INTERFACE(self) -> str:
        return self.capture_interface

    @property
    def SNIFFER_FILTER(self) -> str:
        return self.capture_filter

    @property
    def API_KEY(self) -> str:
        return self.api_key


def get_settings() -> Settings:
    """Factory function returning a fresh Settings instance."""
    return Settings()
