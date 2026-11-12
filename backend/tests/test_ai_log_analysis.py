"""Tests for AI log triage (Gemini + deterministic fallback)."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from services.ai_log_analysis import (
    AILogAnalysis,
    LogLineAlert,
    analyze_logs,
    fallback_log_analysis,
)

_SAMPLE = """\
2026-10-19T10:00:01 sshd[123]: Accepted password for alice from 10.0.0.5
2026-10-19T10:00:02 sshd[124]: Failed password for root from 203.0.113.9
2026-10-19T10:00:03 web[9]: GET /search?q=1 UNION SELECT password FROM users
2026-10-19T10:00:04 web[9]: 200 OK /health
"""


def test_fallback_flags_suspicious_lines_and_ranks_severity() -> None:
    result = fallback_log_analysis(_SAMPLE)
    assert isinstance(result, AILogAnalysis)
    assert result.analyzed_lines == 4
    reasons = {a.reason for a in result.alerts}
    assert "Failed authentication attempt" in reasons
    assert "Possible SQL injection" in reasons
    # SQL injection is CRITICAL, so overall escalates to CRITICAL.
    assert result.overall_severity == "CRITICAL"
    assert result.recommended_actions  # non-empty when alerts exist


def test_fallback_clean_logs_have_no_alerts() -> None:
    result = fallback_log_analysis("GET /health 200 OK\nstartup complete\n")
    assert result.alerts == []
    assert result.overall_severity == "LOW"
    assert result.recommended_actions == []


def test_analyze_logs_accepts_structured_response() -> None:
    payload = AILogAnalysis(
        summary="One failed login observed.",
        overall_severity="HIGH",
        alerts=[LogLineAlert(line="Failed password for root", severity="HIGH", reason="brute force")],
        recommended_actions=["Block the source IP"],
        analyzed_lines=4,
    )
    response = SimpleNamespace(parsed=payload, text=payload.model_dump_json())
    fake_client = SimpleNamespace(models=SimpleNamespace(generate_content=lambda **_: response))

    with patch("services.ai_log_analysis.genai.Client", return_value=fake_client):
        result = analyze_logs(_SAMPLE, api_key="test-key")

    assert result.overall_severity == "HIGH"
    assert result.alerts[0].reason == "brute force"
