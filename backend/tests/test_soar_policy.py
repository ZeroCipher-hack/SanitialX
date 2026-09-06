import pytest
from soar.policy import (
    can_decide,
    can_execute,
    next_decision_status,
    validate_action_target,
    validate_execution,
)


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


def test_block_ip_requires_valid_ip_target():
    assert validate_action_target("BLOCK_IP", "IP", " 192.0.2.10 ") == "192.0.2.10"
    assert validate_action_target("BLOCK_IP", "IP", "2001:db8::1") == "2001:db8::1"
    with pytest.raises(ValueError, match="target_type IP"):
        validate_action_target("BLOCK_IP", "ASSET", "agent-1")
    with pytest.raises(ValueError, match="valid IPv4 or IPv6"):
        validate_action_target("BLOCK_IP", "IP", "not-an-ip")


def test_isolate_host_requires_asset_target():
    assert validate_action_target("ISOLATE_HOST", "ASSET", "agent-123") == "agent-123"
    with pytest.raises(ValueError, match="target_type ASSET"):
        validate_action_target("ISOLATE_HOST", "IP", "192.0.2.5")


def test_empty_targets_are_rejected():
    with pytest.raises(ValueError, match="must not be empty"):
        validate_action_target("DISABLE_ACCOUNT", "USER", "   ")
