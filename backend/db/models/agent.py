"""
SQLAlchemy database model for managed endpoint assets / agents.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from db.base import Base


class AgentModel(Base):
    __tablename__ = "agents"

    agent_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(100), index=True)
    ip_address: Mapped[str] = mapped_column(String(45), index=True)
    os: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(20), default="ONLINE", index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    cpu_usage: Mapped[float] = mapped_column(Float, default=0.0)
    memory_usage: Mapped[float] = mapped_column(Float, default=0.0)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    events_count: Mapped[int] = mapped_column(Integer, default=0)

    asset_type: Mapped[str] = mapped_column(String(32), default="ENDPOINT", index=True)
    criticality: Mapped[str] = mapped_column(String(20), default="MEDIUM", index=True)
    environment: Mapped[str] = mapped_column(String(32), default="UNKNOWN", index=True)
    owner: Mapped[str | None] = mapped_column(String(160), nullable=True)
    internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    source: Mapped[str] = mapped_column(String(40), default="agent")
    lifecycle_status: Mapped[str] = mapped_column(String(24), default="DISCOVERED", index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    inventory_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)

    # Agent-system enrollment metadata. Raw tokens are never persisted.
    agent_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    enrolled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    agent_version: Mapped[str | None] = mapped_column(String(40), nullable=True)

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
            "asset_type": self.asset_type,
            "criticality": self.criticality,
            "environment": self.environment,
            "owner": self.owner,
            "internet_exposed": self.internet_exposed,
            "tags": list(self.tags or []),
            "source": self.source,
            "lifecycle_status": self.lifecycle_status,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "inventory_updated_at": self.inventory_updated_at.isoformat() if self.inventory_updated_at else None,
            "enrolled_at": self.enrolled_at.isoformat() if self.enrolled_at else None,
            "agent_version": self.agent_version,
        }
