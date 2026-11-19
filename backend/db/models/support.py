"""SQLAlchemy models for customer support tickets and vendor news.

Both are deliberately small: the product is deployed on the customer's own
infrastructure, so tickets are exported and news/replies are imported manually
or through a signed bundle. Nothing here is sent to the vendor automatically.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.base import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class SupportTicketModel(Base):
    __tablename__ = "support_tickets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    category: Mapped[str] = mapped_column(String(20), index=True)  # QUESTION | BUG | FEATURE
    subject: Mapped[str] = mapped_column(String(200))
    message: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="OPEN", index=True)  # OPEN | ANSWERED | CLOSED
    created_by: Mapped[str] = mapped_column(String(64), index=True)
    vendor_reply: Mapped[str | None] = mapped_column(Text, nullable=True)
    replied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "subject": self.subject,
            "message": self.message,
            "status": self.status,
            "created_by": self.created_by,
            "vendor_reply": self.vendor_reply,
            "replied_at": self.replied_at.isoformat() if self.replied_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class NewsItemModel(Base):
    __tablename__ = "news_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    category: Mapped[str] = mapped_column(String(20), index=True)  # RELEASE | RULES | NOTICE
    title: Mapped[str] = mapped_column(String(200))
    body: Mapped[str] = mapped_column(Text)
    version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "title": self.title,
            "body": self.body,
            "version": self.version,
            "published_at": self.published_at.isoformat() if self.published_at else None,
        }
