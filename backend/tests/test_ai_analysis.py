"""Tests for the Gemini incident analysis service."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from core.config import Settings
from correlation.enums import Severity
from incidents.enums import IncidentStatus
from incidents.models import Incident
from services.ai_analysis import AIIncidentAnalysis, analyze_incident, fallback_analysis

_TEST_SECRET_KWARGS = {
    "jwt_secret_key": "test-only-jwt-secret-" + "x" * 20,
    "api_key": "test-only-api-key-" + "x" * 20,
}


def make_incident() -> Incident:
    return Incident(
        incident_id="inc-ai-test",
        title="SSH brute-force detected",
        description="Repeated failed SSH authentication attempts.",
        severity=Severity.HIGH,
        status=IncidentStatus.OPEN,
        source_ip="192.0.2.10",
        destination_ip="192.0.2.20",
        triggering_detection_ids=["rule-ssh-bruteforce"],
        context={"failed_attempts": 42, "service": "ssh"},
    )


def test_fallback_analysis_is_valid_and_bounded() -> None:
    result = fallback_analysis(make_incident())

    assert isinstance(result, AIIncidentAnalysis)
    assert 0 <= result.overall_risk_score <= 100
    assert result.affected_assets == ["192.0.2.20"]
    assert result.recommended_actions


def test_settings_load_gemini_configuration() -> None:
    settings = Settings(
        **_TEST_SECRET_KWARGS,
        gemini_api_key="test-gemini-key",
        gemini_model="gemini-3.6-flash",
    )

    assert settings.gemini_api_key == "test-gemini-key"
    assert settings.gemini_model == "gemini-3.6-flash"


def test_analyze_incident_accepts_structured_response() -> None:
    payload = AIIncidentAnalysis(
        executive_summary="Evidence is consistent with an SSH password-guessing attempt.",
        initial_access_vector="SSH password guessing",
        affected_assets=["192.0.2.20"],
        observed_techniques=["T1110.001"],
        honeypot_engagement="No honeypot evidence provided.",
        simulated_data_loss="No evidence of data loss.",
        overall_risk_score=78,
        recommended_actions=["Block the source IP.", "Review SSH authentication logs."],
    )
    response = SimpleNamespace(parsed=payload, text=payload.model_dump_json())
    fake_client = SimpleNamespace(
        models=SimpleNamespace(generate_content=lambda **_: response)
    )

    with patch("services.ai_analysis.genai.Client", return_value=fake_client):
        result = analyze_incident(
            make_incident(), api_key="test-gemini-key", model="gemini-3.6-flash"
        )

    assert result.overall_risk_score == 78
    assert result.observed_techniques == ["T1110.001"]
    assert result.recommended_actions
