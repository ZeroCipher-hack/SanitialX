import pytest
from soar.policy import can_decide, can_execute, next_decision_status, validate_execution


def test_pending_action_can_be_approved_or_rejected():
    assert can_decide("PENDING") is True
    assert next_decision_status("PENDING", True) == "APPROVED"
    assert next_decision_status("PENDING", False) == "REJECTED"


def test_only_approved_action_can_execute():
    assert can_execute("APPROVED") is True
    for status in ("PENDING", "REJECTED", "EXECUTED", "FAILED"):
        assert can_execute(status) is False
        with pytest.raises(ValueError, match="APPROVED"):
            validate_execution(status)


def test_rejected_or_executed_action_cannot_be_decided_again():
    for status in ("REJECTED", "EXECUTED", "APPROVED"):
        with pytest.raises(ValueError, match="PENDING"):
            next_decision_status(status, True)
