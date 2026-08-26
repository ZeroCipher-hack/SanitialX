"""
SQLAlchemy database model for Security Events.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.base import Base


class EventModel(Base):
    __tablename__ = "security_events"

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    severity: Mapped[str] = mapped_column(String(20), default="INFO", index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    user: Mapped[str | None] = mapped_column(String(100), nullable=True)
    host: Mapped[str | None] = mapped_column(String(100), nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    mitre_technique: Mapped[str | None] = mapped_column(String(50), nullable=True)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_type": self.event_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "user": self.user,
            "host": self.host,
            "rule_id": self.rule_id,
            "mitre_technique": self.mitre_technique,
            "details": self.details,
            "raw_payload": self.raw_payload or {},
        }
