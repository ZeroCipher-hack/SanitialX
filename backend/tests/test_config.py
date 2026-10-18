"""Unit tests for core.config.Settings."""

from __future__ import annotations

import pytest

from core.config import Settings

_VALID_SECRET = "test-only-secret-" + "x" * 20

# Every settings key can arrive under either prefix; tests clear both so the
# ambient environment never leaks into a case under test.
_JWT_KEYS = ("SANITIALX_JWT_SECRET_KEY", "SENTINELX_JWT_SECRET_KEY")
_API_KEYS = ("SANITIALX_API_KEY", "SENTINELX_API_KEY")


def _clear(monkeypatch: pytest.MonkeyPatch, *names: str) -> None:
    for name in names:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _required_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Settings() requires real JWT/API secrets to boot. Default every test to
    throwaway valid ones under the canonical prefix, with the legacy prefix
    cleared so it cannot interfere."""
    _clear(monkeypatch, *_JWT_KEYS, *_API_KEYS)
    monkeypatch.setenv("SANITIALX_JWT_SECRET_KEY", _VALID_SECRET)
    monkeypatch.setenv("SANITIALX_API_KEY", _VALID_SECRET)


class TestSettings:
    """Verify Settings loads defaults and respects env overrides."""

    def test_defaults(self) -> None:
        settings = Settings()
        assert settings.app_name == "SanitialX"
        assert settings.debug is False
        assert settings.log_level == "INFO"
        assert settings.capture_interface == "eth0"
        assert settings.capture_filter == ""
        assert settings.gemini_model == "gemini-2.5-flash"

    def test_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Canonical SANITIALX_ env vars override defaults."""
        monkeypatch.setenv("SANITIALX_APP_NAME", "TestApp")
        monkeypatch.setenv("SANITIALX_DEBUG", "true")
        monkeypatch.setenv("SANITIALX_LOG_LEVEL", "DEBUG")
        monkeypatch.setenv("SANITIALX_CAPTURE_INTERFACE", "wlan0")
        monkeypatch.setenv("SANITIALX_CAPTURE_FILTER", "tcp port 80")

        settings = Settings()
        assert settings.app_name == "TestApp"
        assert settings.debug is True
        assert settings.log_level == "DEBUG"
        assert settings.capture_interface == "wlan0"
        assert settings.capture_filter == "tcp port 80"

    def test_sniffer_alias_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The historical SNIFFER_* names are honored, not silently ignored."""
        monkeypatch.setenv("SANITIALX_SNIFFER_INTERFACE", "eth7")
        monkeypatch.setenv("SANITIALX_SNIFFER_FILTER", "udp")
        settings = Settings()
        assert settings.capture_interface == "eth7"
        assert settings.capture_filter == "udp"

    def test_extra_env_ignored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SANITIALX_UNKNOWN_FIELD", "whatever")
        settings = Settings()  # should not raise
        assert not hasattr(settings, "unknown_field")

    def test_single_canonical_class(self) -> None:
        s1 = Settings()
        s2 = Settings()
        assert type(s1) is type(s2) is Settings


class TestLegacyPrefixCompatibility:
    """The legacy SENTINELX_ prefix must keep working as a fallback."""

    def test_legacy_prefix_supplies_values(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clear(monkeypatch, *_JWT_KEYS, *_API_KEYS)
        monkeypatch.setenv("SENTINELX_JWT_SECRET_KEY", _VALID_SECRET)
        monkeypatch.setenv("SENTINELX_API_KEY", _VALID_SECRET)
        monkeypatch.setenv("SENTINELX_APP_NAME", "LegacyApp")
        monkeypatch.setenv("SENTINELX_CAPTURE_INTERFACE", "eth-legacy")

        settings = Settings()
        assert settings.app_name == "LegacyApp"
        assert settings.capture_interface == "eth-legacy"

    def test_canonical_prefix_wins_over_legacy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SANITIALX_APP_NAME", "CanonApp")
        monkeypatch.setenv("SENTINELX_APP_NAME", "LegacyApp")
        assert Settings().app_name == "CanonApp"


class TestInsecureSecretsRejected:
    """Settings must refuse to boot with placeholder or weak secrets."""

    def test_placeholder_jwt_secret_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SANITIALX_JWT_SECRET_KEY", "sanitialx-jwt-secret-key-change-in-production")
        with pytest.raises(Exception):
            Settings()

    def test_short_jwt_secret_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SANITIALX_JWT_SECRET_KEY", "too-short")
        with pytest.raises(Exception):
            Settings()

    def test_placeholder_api_key_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SANITIALX_API_KEY", "change_this_placeholder_api_key_in_production")
        with pytest.raises(Exception):
            Settings()

    def test_missing_jwt_secret_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clear(monkeypatch, *_JWT_KEYS)
        with pytest.raises(Exception):
            Settings(_env_file=None)
