"""Scenario registry for the SanitialX controlled cyber range."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SimulationScenario:
    name: str
    title: str
    description: str
    event_indexes: tuple[int, ...]
    difficulty: str


SCENARIOS: dict[str, SimulationScenario] = {
    "WEB_APP_COMPROMISE": SimulationScenario(
        name="WEB_APP_COMPROMISE",
        title="Web Application Compromise & Data Exfiltration",
        description="Reconnaissance through credential abuse, shell access, privilege escalation, data access and simulated exfiltration.",
        event_indexes=tuple(range(9)),
        difficulty="Intermediate",
    ),
    "SSH_BRUTE_FORCE": SimulationScenario(
        name="SSH_BRUTE_FORCE",
        title="SSH Brute Force & Remote Access",
        description="Network reconnaissance followed by credential abuse and remote SSH access.",
        event_indexes=(0, 1, 2, 4),
        difficulty="Beginner",
    ),
    "DATA_EXFILTRATION": SimulationScenario(
        name="DATA_EXFILTRATION",
        title="Sensitive Data Access & Exfiltration",
        description="Privileged access to a simulated database followed by controlled outbound transfer.",
        event_indexes=(6, 7, 8),
        difficulty="Advanced",
    ),
}


def get_scenario(name: str) -> SimulationScenario:
    """Resolve a scenario name or raise a clear validation error."""
    normalized = name.strip().upper()
    try:
        return SCENARIOS[normalized]
    except KeyError as exc:
        supported = ", ".join(sorted(SCENARIOS))
        raise ValueError(f"Unknown simulation scenario '{name}'. Supported scenarios: {supported}") from exc
