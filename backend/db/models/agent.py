"""
SQLAlchemy database model for Endpoint Agents.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from db.base import Base


class AgentModel(Base):
    __tablename__ = "agents"

    agent_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(100), index=True)
    ip_address: Mapped[str] = mapped_column(String(45))
    os: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(20), default="ONLINE", index=True)  # ONLINE, OFFLINE, WARNING, COMPROMISED
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    cpu_usage: Mapped[float] = mapped_column(Float, default=0.0)
    memory_usage: Mapped[float] = mapped_column(Float, default=0.0)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    events_count: Mapped[int] = mapped_column(Integer, default=0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "os": self.os,
            "status": self.status,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "cpu_usage": self.cpu_usage,
            "memory_usage": self.memory_usage,
            "risk_score": self.risk_score,
            "events_count": self.events_count,
        }
