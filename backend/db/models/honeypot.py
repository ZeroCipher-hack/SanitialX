"""
SQLAlchemy database model for Honeypot & Deception Sessions.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.base import Base


class HoneypotSessionModel(Base):
    __tablename__ = "honeypot_sessions"

    session_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    attacker_ip: Mapped[str] = mapped_column(String(45), index=True)
    service: Mapped[str] = mapped_column(String(50), index=True)  # SSH, Fake Web Panel, Fake DB
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[int] = mapped_column(Integer, default=0)
    credentials_attempted: Mapped[list[str]] = mapped_column(JSON, default=list)
    commands_executed: Mapped[list[str]] = mapped_column(JSON, default=list)
    files_accessed: Mapped[list[str]] = mapped_column(JSON, default=list)
    risk_score: Mapped[int] = mapped_column(Integer, default=50)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "attacker_ip": self.attacker_ip,
            "service": self.service,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "duration_seconds": self.duration_seconds,
            "credentials_attempted": self.credentials_attempted or [],
            "commands_executed": self.commands_executed or [],
            "files_accessed": self.files_accessed or [],
            "risk_score": self.risk_score,
            "notes": self.notes,
        }
