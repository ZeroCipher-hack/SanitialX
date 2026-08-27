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
_INSECURE_SECRET_VALUES = {
    "sentinelx-secret-key-change-in-production",
    "change_this_placeholder_api_key_in_production",
    "sentinelx-jwt-secret-key-change-in-production",
    "change_this_jwt_secret_key_to_a_secure_random_string_in_production",
}
_MIN_SECRET_LENGTH = 32


class Settings(BaseSettings):
    """Canonical application settings for SentinelX."""

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
    capture_interface: str = Field(default="eth0")
    capture_filter: str = Field(default="")

    # ── Environment & API ───────────────────────────────────────────
    environment: str = Field(default="development")
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    frontend_origin: str = Field(
        default="http://localhost:3000,http://127.0.0.1:3000"
    )

    # Secrets are required for authentication.
    api_key: str = Field(..., description="API Key for placeholder auth")
    jwt_secret_key: str = Field(..., description="JWT signing secret key")
    jwt_algorithm: str = Field(default="HS256")

    # ── Gemini AI ────────────────────────────────────────────────────
    # Optional so the backend can still boot when AI is not configured.
    # The key must NEVER be placed in frontend code or committed to git.
    gemini_api_key: str | None = Field(
        default=None,
        description="Google Gemini API key; keep server-side only",
    )
    gemini_model: str = Field(
        default="gemini-3.6-flash",
        description="Gemini model used for incident analysis",
    )

    # ── Infrastructure ──────────────────────────────────────────────
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
        """Refuse to boot with known placeholder authentication secrets."""
        if self.jwt_secret_key in _INSECURE_SECRET_VALUES:
            raise ValueError(
                "SENTINELX_JWT_SECRET_KEY is set to a known placeholder value. "
                "Generate a real secret, e.g. `openssl rand -hex 32`."
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

    # ── Property aliases ─────────────────────────────────────────────
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
