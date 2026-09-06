"""Pure SOAR transition and target policy."""
from __future__ import annotations

from ipaddress import ip_address

TERMINAL_STATUSES = {"REJECTED", "EXECUTED", "FAILED"}
ACTION_TARGETS = {
    "ADD_WATCHLIST": "IP",
    "COLLECT_FORENSICS": "ASSET",
    "REQUEST_RESCAN": "ASSET",
    "NOTIFY_ANALYST": "INCIDENT",
    "BLOCK_IP": "IP",
    "ISOLATE_HOST": "ASSET",
    "DISABLE_ACCOUNT": "USER",
    "KILL_PROCESS": "PROCESS",
}


def can_decide(status: str) -> bool:
    return status == "PENDING"


def can_execute(status: str) -> bool:
    return status == "APPROVED"


def next_decision_status(status: str, approve: bool) -> str:
    if not can_decide(status):
        raise ValueError("Only PENDING actions may be decided.")
    return "APPROVED" if approve else "REJECTED"


def validate_execution(status: str) -> None:
    if not can_execute(status):
        raise ValueError("Action must be APPROVED before execution.")


def validate_action_target(action_type: str, target_type: str, target_value: str) -> str:
    expected = ACTION_TARGETS.get(action_type)
    if expected is None:
        raise ValueError("Unsupported SOAR action type.")
    if target_type != expected:
        raise ValueError(f"{action_type} requires target_type {expected}.")
    value = target_value.strip()
    if not value:
        raise ValueError("SOAR target_value must not be empty.")
    if target_type == "IP":
        try:
            ip_address(value)
        except ValueError as exc:
            raise ValueError("SOAR IP target must be a valid IPv4 or IPv6 address.") from exc
    return value
