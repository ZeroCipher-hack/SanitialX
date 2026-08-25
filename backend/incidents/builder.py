"""
Incident builder — constructs Incidents from Detections.

Pure domain module — no infrastructure imports.
"""

from __future__ import annotations

from datetime import datetime, timezone

from correlation.models import Detection
from incidents.enums import IncidentStatus
from incidents.models import Incident


def build_incident_from_detection(detection: Detection) -> Incident:
    """Build a new OPEN Incident from a confirmed Detection."""
    now = datetime.now(timezone.utc)
    return Incident(
        title=f"Incident: {detection.title}",
        description=detection.description,
        severity=detection.severity,
        status=IncidentStatus.OPEN,
        version=1,
        created_at=now,
        updated_at=now,
        source_ip=detection.source_ip,
        destination_ip=detection.destination_ip,
        triggering_detection_ids=[detection.detection_id],
        context={
            "rule_id": detection.rule_id,
            "rule_name": detection.rule_name,
            "triggering_event_ids": detection.triggering_event_ids,
            "rule_context": detection.context,
        },
    )
