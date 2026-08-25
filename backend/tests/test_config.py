"""Unit tests for core.config.Settings."""

from __future__ import annotations

import os

import pytest

from core.config import Settings

_VALID_SECRET = "test-only-secret-" + "x" * 20


@pytest.fixture(autouse=True)
def _required_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Settings() now requires real JWT/API secrets to boot. Every test in
    this module gets throwaway valid ones by default via env vars, matching
    how a real deployment supplies them."""
    monkeypatch.setenv("SENTINELX_JWT_SECRET_KEY", _VALID_SECRET)
    monkeypatch.setenv("SENTINELX_API_KEY", _VALID_SECRET)


class TestSettings:
    """Verify Settings loads defaults and respects env overrides."""

    def test_defaults(self) -> None:
        """Settings should have sensible defaults without any env vars."""
        settings = Settings()
        assert settings.app_name == "SentinelX"
        assert settings.debug is False
        assert settings.log_level == "INFO"
        assert settings.capture_interface == "eth0"
        assert settings.capture_filter == ""

    def test_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Environment variables with SENTINELX_ prefix should override defaults."""
        monkeypatch.setenv("SENTINELX_APP_NAME", "TestApp")
        monkeypatch.setenv("SENTINELX_DEBUG", "true")
        monkeypatch.setenv("SENTINELX_LOG_LEVEL", "DEBUG")
        monkeypatch.setenv("SENTINELX_CAPTURE_INTERFACE", "wlan0")
        monkeypatch.setenv("SENTINELX_CAPTURE_FILTER", "tcp port 80")

        settings = Settings()
        assert settings.app_name == "TestApp"
        assert settings.debug is True
        assert settings.log_level == "DEBUG"
        assert settings.capture_interface == "wlan0"
        assert settings.capture_filter == "tcp port 80"

    def test_extra_env_ignored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Unknown environment variables should be silently ignored."""
        monkeypatch.setenv("SENTINELX_UNKNOWN_FIELD", "whatever")
        settings = Settings()  # should not raise
        assert not hasattr(settings, "unknown_field")

    def test_single_canonical_class(self) -> None:
        """There must be exactly one Settings class — verify identity."""
        s1 = Settings()
        s2 = Settings()
        assert type(s1) is type(s2) is Settings


class TestInsecureSecretsRejected:
    """Settings must refuse to boot with placeholder or weak secrets."""

    def test_placeholder_jwt_secret_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(
            "SENTINELX_JWT_SECRET_KEY",
            "sentinelx-jwt-secret-key-change-in-production",
        )
        monkeypatch.setenv("SENTINELX_API_KEY", _VALID_SECRET)
        with pytest.raises(Exception):
            Settings()

    def test_short_jwt_secret_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINELX_JWT_SECRET_KEY", "too-short")
        monkeypatch.setenv("SENTINELX_API_KEY", _VALID_SECRET)
        with pytest.raises(Exception):
            Settings()

    def test_placeholder_api_key_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINELX_JWT_SECRET_KEY", _VALID_SECRET)
        monkeypatch.setenv(
            "SENTINELX_API_KEY",
            "change_this_placeholder_api_key_in_production",
        )
        with pytest.raises(Exception):
            Settings()

    def test_missing_jwt_secret_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SENTINELX_JWT_SECRET_KEY", raising=False)
        monkeypatch.setenv("SENTINELX_API_KEY", _VALID_SECRET)
        with pytest.raises(Exception):
            Settings()
