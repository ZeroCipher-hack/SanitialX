"""Gemini-powered log triage.

Takes raw log/telemetry text and returns a plain-language explanation plus the
specific lines that look like alerts. The Gemini credential is read from
server-side settings only; when it is unavailable a deterministic keyword
fallback still flags the obvious suspicious lines, so the feature degrades
gracefully instead of failing.
"""

from __future__ import annotations

import logging
import re

from google import genai
from google.genai import types
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

_MAX_INPUT_CHARS = 20_000
_MAX_FALLBACK_ALERTS = 50

# Patterns the deterministic fallback treats as alert-worthy. Each maps to a
# severity so the fallback can rank without a model.
_SUSPICIOUS_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"\bfailed password\b|\bauthentication failure\b|\binvalid user\b", re.I), "HIGH", "Failed authentication attempt"),
    (re.compile(r"\bunauthor(i|)zed\b|\baccess denied\b|\bpermission denied\b|\b403\b", re.I), "HIGH", "Access denied / authorization failure"),
    (re.compile(r"\bsql(i| injection)\b|\bunion select\b|\bor 1=1\b", re.I), "CRITICAL", "Possible SQL injection"),
    (re.compile(r"\btraceback\b|\bunhandled exception\b|\bsegfault\b|\bpanic\b", re.I), "MEDIUM", "Application crash / unhandled error"),
    (re.compile(r"\b5\d\d\b server error|\binternal server error\b|\b500\b", re.I), "MEDIUM", "Server error"),
    (re.compile(r"\bmalware\b|\bexploit\b|\breverse shell\b|\b/etc/passwd\b|\bwget http\b|\bcurl http\b", re.I), "CRITICAL", "Possible exploitation / malicious command"),
    (re.compile(r"\bbrute[- ]?force\b|\btoo many requests\b|\b429\b", re.I), "HIGH", "Brute-force / rate abuse"),
]

_SEVERITY_ORDER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "INFO": 0}


class LogLineAlert(BaseModel):
    line: str
    severity: str = "MEDIUM"
    reason: str


class AILogAnalysis(BaseModel):
    """Structured log triage result for the monitoring UI."""

    summary: str
    overall_severity: str = "LOW"
    alerts: list[LogLineAlert] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    analyzed_lines: int = 0


def _clip(log_text: str) -> str:
    return log_text[:_MAX_INPUT_CHARS]


def _build_prompt(log_text: str) -> str:
    return f"""
You are a SOC analyst triaging logs for SanitialX. Read the log lines and
explain, in plain language, what is happening. Then flag ONLY the lines that
are genuinely alert-worthy (security or reliability), each with a severity
(CRITICAL/HIGH/MEDIUM/LOW) and a one-line reason. Do not invent events that
are not in the text. If nothing is suspicious, say so and return no alerts.

LOGS:
{_clip(log_text)}
""".strip()


def analyze_logs(
    log_text: str,
    *,
    api_key: str,
    model: str = "gemini-2.5-flash",
) -> AILogAnalysis:
    """Run Gemini log triage with model fallback."""
    client = genai.Client(api_key=api_key)
    candidate_models: list[str] = []
    for candidate in (model, "gemini-2.5-flash", "gemini-2.0-flash"):
        if candidate and candidate not in candidate_models:
            candidate_models.append(candidate)

    last_error: Exception | None = None
    for candidate_model in candidate_models:
        try:
            response = client.models.generate_content(
                model=candidate_model,
                contents=_build_prompt(log_text),
                config=types.GenerateContentConfig(
                    temperature=0.1,
                    response_mime_type="application/json",
                    response_schema=AILogAnalysis,
                ),
            )
            parsed = getattr(response, "parsed", None)
            if isinstance(parsed, AILogAnalysis):
                return parsed
            if parsed is not None:
                return AILogAnalysis.model_validate(parsed)
            if response.text:
                return AILogAnalysis.model_validate_json(response.text)
            raise RuntimeError(f"Empty Gemini response from {candidate_model}")
        except Exception as exc:  # noqa: BLE001 - SDK wraps transient errors variously
            last_error = exc
            logger.warning("Gemini log analysis failed on %s: %s", candidate_model, exc)

    raise RuntimeError("All Gemini models failed for log analysis") from last_error


def fallback_log_analysis(log_text: str) -> AILogAnalysis:
    """Deterministic keyword triage used when Gemini is not configured."""
    lines = [ln.strip() for ln in _clip(log_text).splitlines() if ln.strip()]
    alerts: list[LogLineAlert] = []
    for line in lines:
        for pattern, severity, reason in _SUSPICIOUS_PATTERNS:
            if pattern.search(line):
                alerts.append(LogLineAlert(line=line[:500], severity=severity, reason=reason))
                break
        if len(alerts) >= _MAX_FALLBACK_ALERTS:
            break

    overall = "LOW"
    for alert in alerts:
        if _SEVERITY_ORDER.get(alert.severity, 0) > _SEVERITY_ORDER.get(overall, 0):
            overall = alert.severity

    if alerts:
        summary = (
            f"Keyword triage flagged {len(alerts)} line(s) across {len(lines)} analyzed. "
            "Configure a Gemini API key for full natural-language explanation."
        )
        actions = [
            "Review each flagged line in context.",
            "Correlate source IPs/users against known assets.",
            "Escalate CRITICAL/HIGH lines to an incident if confirmed.",
        ]
    else:
        summary = f"No obviously suspicious lines in {len(lines)} analyzed (keyword triage)."
        actions = []

    return AILogAnalysis(
        summary=summary,
        overall_severity=overall,
        alerts=alerts,
        recommended_actions=actions,
        analyzed_lines=len(lines),
    )
