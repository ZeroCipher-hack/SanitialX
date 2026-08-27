"""Gemini-powered incident analysis service.

The Gemini credential is intentionally read from server-side settings only.
The service returns a strict Pydantic model so the API remains predictable
for the frontend even when the model output is generated dynamically.
"""

from __future__ import annotations

import logging
from typing import Any

from google import genai
from google.genai import types
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class AIIncidentAnalysis(BaseModel):
    """Structured fields consumed by the investigation report UI."""

    executive_summary: str
    threat_classification: str = "Unknown"
    confidence_score: int = Field(default=0, ge=0, le=100)
    key_findings: list[str] = Field(default_factory=list)
    indicators_of_compromise: list[str] = Field(default_factory=list)
    initial_access_vector: str
    affected_assets: list[str] = Field(default_factory=list)
    observed_techniques: list[str] = Field(default_factory=list)
    honeypot_engagement: str
    simulated_data_loss: str
    overall_risk_score: int = Field(ge=0, le=100)
    recommended_actions: list[str] = Field(default_factory=list)


def _build_prompt(incident: Any) -> str:
    """Build a bounded prompt from the incident telemetry."""
    context = incident.context or {}
    return f"""
You are the senior SOC analyst for SanitialX, an incident detection and
response platform. Analyze the following security incident using ONLY the
provided telemetry. Do not invent IP addresses, users, commands, assets, or
attack evidence that is not supported by the input. When evidence is missing,
state that it is unknown or inferred.

Return a concise defensive investigation with:
- threat classification
- confidence score from 0 to 100
- key evidence-backed findings
- indicators of compromise actually present in telemetry
- likely MITRE ATT&CK technique IDs only when supported
- initial access vector
- affected assets
- honeypot engagement and simulated impact
- risk score from 0 to 100
- prioritized remediation actions

Do not treat simulated impact as confirmed real-world data loss.

INCIDENT:
incident_id: {incident.incident_id}
title: {incident.title}
description: {incident.description}
severity: {incident.severity.value}
status: {incident.status.value}
source_ip: {incident.source_ip or 'unknown'}
destination_ip: {incident.destination_ip or 'unknown'}
triggering_detection_ids: {incident.triggering_detection_ids}
context: {context}
""".strip()


def analyze_incident(
    incident: Any,
    *,
    api_key: str,
    model: str = "gemini-2.5-flash",
) -> AIIncidentAnalysis:
    """Run one Gemini incident analysis and validate its structured output."""
    client = genai.Client(api_key=api_key)

    response = client.models.generate_content(
        model=model,
        contents=_build_prompt(incident),
        config=types.GenerateContentConfig(
            temperature=0.2,
            response_mime_type="application/json",
            response_schema=AIIncidentAnalysis,
        ),
    )

    if getattr(response, "parsed", None) is not None:
        parsed = response.parsed
        if isinstance(parsed, AIIncidentAnalysis):
            return parsed
        return AIIncidentAnalysis.model_validate(parsed)

    if not response.text:
        raise RuntimeError("Gemini returned an empty analysis response")

    return AIIncidentAnalysis.model_validate_json(response.text)


def fallback_analysis(incident: Any) -> AIIncidentAnalysis:
    """Deterministic fallback used when Gemini is not configured/available."""
    context = incident.context or {}
    return AIIncidentAnalysis(
        executive_summary=context.get(
            "executive_summary",
            f"AI analysis is unavailable. Incident requires manual investigation: {incident.title}.",
        ),
        threat_classification=context.get("threat_classification", "Unknown"),
        confidence_score=int(context.get("confidence_score", 0)),
        key_findings=context.get("key_findings", []),
        indicators_of_compromise=context.get("indicators_of_compromise", []),
        initial_access_vector=context.get(
            "initial_access_vector", "Insufficient telemetry for confident attribution."
        ),
        affected_assets=context.get(
            "affected_assets", [incident.destination_ip or "Target Host"]
        ),
        observed_techniques=context.get("observed_techniques", []),
        honeypot_engagement=context.get(
            "honeypot_engagement", "No AI determination available."
        ),
        simulated_data_loss=context.get(
            "simulated_data_loss", "Impact not determined from available telemetry."
        ),
        overall_risk_score=int(context.get("overall_risk_score", 50)),
        recommended_actions=context.get(
            "recommended_actions",
            [
                "Validate the triggering telemetry and source IP.",
                "Review affected host authentication and process logs.",
                "Contain the source if malicious activity is confirmed.",
            ],
        ),
    )
