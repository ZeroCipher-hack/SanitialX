"""Deterministic SanitialX endpoint agent version policy helpers."""

from __future__ import annotations

from dataclasses import dataclass
import re

from core.config import Settings

_VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$")


@dataclass(frozen=True)
class AgentVersionPolicy:
    platform: str
    current_version: str | None
    minimum_version: str | None
    latest_version: str | None
    status: str
    update_available: bool
    update_required: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "platform": self.platform,
            "current_version": self.current_version,
            "minimum_version": self.minimum_version,
            "latest_version": self.latest_version,
            "status": self.status,
            "update_available": self.update_available,
            "update_required": self.update_required,
        }


def _parse(version: str | None) -> tuple[int, int, int] | None:
    if not version:
        return None
    match = _VERSION_RE.match(version.strip())
    if not match:
        return None
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def _platform(agent_id: str, os_name: str | None) -> str:
    aid = agent_id.lower()
    os_value = (os_name or "").lower()
    if aid.startswith("windows-") or "windows" in os_value:
        return "windows"
    if aid.startswith("linux-") or "linux" in os_value:
        return "linux"
    return "unknown"


def evaluate_agent_version(
    *,
    agent_id: str,
    os_name: str | None,
    current_version: str | None,
    settings: Settings,
) -> AgentVersionPolicy:
    platform = _platform(agent_id, os_name)
    if platform == "linux":
        minimum = settings.agent_linux_minimum_version
        latest = settings.agent_linux_latest_version
    elif platform == "windows":
        minimum = settings.agent_windows_minimum_version
        latest = settings.agent_windows_latest_version
    else:
        minimum = None
        latest = None

    current_parsed = _parse(current_version)
    minimum_parsed = _parse(minimum)
    latest_parsed = _parse(latest)

    if platform == "unknown" or current_parsed is None:
        status = "UNKNOWN"
    elif minimum_parsed is not None and current_parsed < minimum_parsed:
        status = "UNSUPPORTED"
    elif latest_parsed is not None and current_parsed < latest_parsed:
        status = "OUTDATED"
    else:
        status = "CURRENT"

    update_available = bool(
        current_parsed is not None
        and latest_parsed is not None
        and current_parsed < latest_parsed
    )
    update_required = status == "UNSUPPORTED"
    return AgentVersionPolicy(
        platform=platform,
        current_version=current_version,
        minimum_version=minimum,
        latest_version=latest,
        status=status,
        update_available=update_available,
        update_required=update_required,
    )
