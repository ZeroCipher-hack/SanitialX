from core.agent_versions import evaluate_agent_version
from core.config import Settings


def _settings() -> Settings:
    return Settings(
        api_key="ci-test-api-key",
        jwt_secret_key="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        agent_linux_minimum_version="0.2.0",
        agent_linux_latest_version="0.3.0",
        agent_windows_minimum_version="0.1.0",
        agent_windows_latest_version="0.2.0",
    )


def test_linux_outdated_but_supported() -> None:
    result = evaluate_agent_version(
        agent_id="linux-abc",
        os_name="Linux 6.0",
        current_version="0.2.0",
        settings=_settings(),
    )
    assert result.status == "OUTDATED"
    assert result.update_available is True
    assert result.update_required is False


def test_linux_below_minimum_is_unsupported() -> None:
    result = evaluate_agent_version(
        agent_id="linux-abc",
        os_name="Linux",
        current_version="0.1.9",
        settings=_settings(),
    )
    assert result.status == "UNSUPPORTED"
    assert result.update_required is True


def test_windows_current() -> None:
    result = evaluate_agent_version(
        agent_id="windows-abc",
        os_name="Microsoft Windows 11",
        current_version="0.2.0",
        settings=_settings(),
    )
    assert result.status == "CURRENT"
    assert result.update_available is False


def test_unknown_or_invalid_version_never_forces_update() -> None:
    result = evaluate_agent_version(
        agent_id="other-abc",
        os_name="OtherOS",
        current_version="dev",
        settings=_settings(),
    )
    assert result.status == "UNKNOWN"
    assert result.update_required is False
