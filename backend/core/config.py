"""
SanitialX configuration — single canonical Settings class.

Loads from environment variables prefixed ``SANITIALX_`` (and an optional
.env file). The legacy ``SENTINELX_`` prefix is still accepted as a
lower-priority fallback so existing deployments keep working. No
module-level mutable singleton — callers must instantiate Settings()
explicitly or receive it via dependency injection.
"""

from __future__ import annotations

import os

from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

_INSECURE_SECRET_VALUES = {
    "sentinelx-secret-key-change-in-production",
    "sanitialx-secret-key-change-in-production",
    "change_this_placeholder_api_key_in_production",
    "sentinelx-jwt-secret-key-change-in-production",
    "sanitialx-jwt-secret-key-change-in-production",
    "change_this_jwt_secret_key_to_a_secure_random_string_in_production",
}
_MIN_SECRET_LENGTH = 32

_LEGACY_ENV_PREFIX = "SENTINELX_"


class Settings(BaseSettings):
    """Canonical application settings for SanitialX."""

    model_config = SettingsConfigDict(
        env_prefix="SANITIALX_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = Field(default="SanitialX", description="Application name")
    debug: bool = Field(default=False, description="Enable debug mode")
    log_level: str = Field(default="INFO", description="Logging level")

    # Accept the canonical CAPTURE_* names and the historical SNIFFER_* names,
    # under both the SANITIALX_ and legacy SENTINELX_ prefixes, so documented
    # config is never silently ignored.
    capture_interface: str = Field(
        default="eth0",
        validation_alias=AliasChoices(
            "SANITIALX_CAPTURE_INTERFACE", "SANITIALX_SNIFFER_INTERFACE",
            "SENTINELX_CAPTURE_INTERFACE", "SENTINELX_SNIFFER_INTERFACE",
        ),
    )
    capture_filter: str = Field(
        default="",
        validation_alias=AliasChoices(
            "SANITIALX_CAPTURE_FILTER", "SANITIALX_SNIFFER_FILTER",
            "SENTINELX_CAPTURE_FILTER", "SENTINELX_SNIFFER_FILTER",
        ),
    )

    environment: str = Field(default="development")
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    frontend_origin: str = Field(default="http://localhost:3000,http://127.0.0.1:3000")

    api_key: str = Field(..., description="API Key for placeholder auth")
    jwt_secret_key: str = Field(..., description="JWT signing secret key")
    jwt_algorithm: str = Field(default="HS256")

    agent_heartbeat_interval_seconds: int = Field(default=30, ge=5, le=3600)
    agent_offline_timeout_seconds: int = Field(default=120, ge=15, le=86400)
    agent_offline_check_interval_seconds: int = Field(default=30, ge=5, le=3600)
    agent_linux_minimum_version: str = Field(default="0.2.0")
    agent_linux_latest_version: str = Field(default="0.2.0")
    agent_windows_minimum_version: str = Field(default="0.1.0")
    agent_windows_latest_version: str = Field(default="0.1.0")

    gemini_api_key: str | None = Field(default=None, description="Google Gemini API key; keep server-side only")
    gemini_model: str = Field(default="gemini-2.5-flash", description="Gemini model used for incident analysis")

    # Low-interaction honeypot decoy listeners. Disabled by default; a decoy
    # only logs connection attempts and never executes attacker input.
    honeypot_enabled: bool = Field(default=False, description="Start decoy honeypot listeners")
    honeypot_host: str = Field(default="0.0.0.0", description="Bind address for honeypot decoys")
    honeypot_ports: str = Field(
        default="2222:SSH,8080:Fake Web Panel,2323:Telnet",
        description="Comma-separated port:service decoys, e.g. '2222:SSH,8080:Fake Web Panel'",
    )

    database_url: str = Field(
        default="postgresql+asyncpg://sanitialx:sanitialx@localhost:5432/sanitialx",
        description="PostgreSQL async database URL",
    )
    redis_url: str = Field(default="redis://localhost:6379/0", description="Redis connection URL")

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Add legacy SENTINELX_-prefixed sources as a lower-priority fallback.

        Canonical SANITIALX_ values (OS env, then .env) win; the legacy prefix
        is consulted only when the canonical value is absent, keeping older
        deployments working without a config change.
        """
        legacy_env = EnvSettingsSource(settings_cls, env_prefix=_LEGACY_ENV_PREFIX)
        legacy_dotenv = DotEnvSettingsSource(
            settings_cls,
            env_file=".env",
            env_file_encoding="utf-8",
            env_prefix=_LEGACY_ENV_PREFIX,
        )
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            legacy_env,
            legacy_dotenv,
            file_secret_settings,
        )

    @model_validator(mode="after")
    def _normalize_and_validate(self) -> "Settings":
        if not self.database_url.strip():
            legacy_database_url = os.getenv("DATABASE_URL", "").strip()
            if legacy_database_url:
                self.database_url = legacy_database_url
        if not self.redis_url.strip():
            legacy_redis_url = os.getenv("REDIS_URL", "").strip()
            if legacy_redis_url:
                self.redis_url = legacy_redis_url
        if self.jwt_secret_key in _INSECURE_SECRET_VALUES:
            raise ValueError("SANITIALX_JWT_SECRET_KEY is set to a known placeholder value. Generate a real secret, e.g. `openssl rand -hex 32`.")
        if len(self.jwt_secret_key) < _MIN_SECRET_LENGTH:
            raise ValueError(f"SANITIALX_JWT_SECRET_KEY must be at least {_MIN_SECRET_LENGTH} characters. Generate one with `openssl rand -hex 32`.")
        if self.api_key in _INSECURE_SECRET_VALUES:
            raise ValueError("SANITIALX_API_KEY is set to a known placeholder value. Set a real value via the SANITIALX_API_KEY environment variable.")
        if self.agent_offline_timeout_seconds <= self.agent_heartbeat_interval_seconds:
            raise ValueError("SANITIALX_AGENT_OFFLINE_TIMEOUT_SECONDS must be greater than heartbeat interval.")
        return self

    @property
    def ENVIRONMENT(self) -> str: return self.environment
    @property
    def DATABASE_URL(self) -> str: return self.database_url
    @property
    def REDIS_URL(self) -> str: return self.redis_url
    @property
    def SNIFFER_INTERFACE(self) -> str: return self.capture_interface
    @property
    def SNIFFER_FILTER(self) -> str: return self.capture_filter
    @property
    def API_KEY(self) -> str: return self.api_key


def get_settings() -> Settings:
    return Settings()
