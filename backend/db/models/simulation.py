"""
SQLAlchemy database model for Attack Simulations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.base import Base


class SimulationModel(Base):
    __tablename__ = "attack_simulations"

    simulation_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scenario_name: Mapped[str] = mapped_column(String(100), index=True)
    target_environment: Mapped[str] = mapped_column(String(100), default="SanitialX Cyber Range")
    difficulty: Mapped[str] = mapped_column(String(20), default="Intermediate")
    status: Mapped[str] = mapped_column(String(20), default="COMPLETED", index=True)  # RUNNING, COMPLETED, FAILED
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    generated_incident_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    events_generated: Mapped[int] = mapped_column(default=0)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "simulation_id": self.simulation_id,
            "scenario_name": self.scenario_name,
            "target_environment": self.target_environment,
            "difficulty": self.difficulty,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "generated_incident_id": self.generated_incident_id,
            "events_generated": self.events_generated,
            "details": self.details or {},
        }
