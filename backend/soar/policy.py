"""Pure SOAR transition policy used by API/repository tests."""
from __future__ import annotations

TERMINAL_STATUSES = {"REJECTED", "EXECUTED", "FAILED"}


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
