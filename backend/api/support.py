"""Support tickets and vendor news for SanitialX (on-prem friendly).

Nothing is sent to the vendor automatically. Admins export open tickets and
import the vendor's replies and news manually, so air-gapped deployments work.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_current_user, get_db_session, require_role
from core.security import TokenPayload
from db.models.support import NewsItemModel, SupportTicketModel

router = APIRouter(tags=["Support & News"])

Category = Literal["QUESTION", "BUG", "FEATURE"]
NewsCategory = Literal["RELEASE", "RULES", "NOTICE"]


class TicketCreate(BaseModel):
    category: Category
    subject: str = Field(min_length=3, max_length=200)
    message: str = Field(min_length=3, max_length=5000)


class TicketReply(BaseModel):
    reply: str = Field(min_length=1, max_length=5000)


class NewsCreate(BaseModel):
    category: NewsCategory
    title: str = Field(min_length=3, max_length=200)
    body: str = Field(min_length=1, max_length=10000)
    version: str | None = Field(default=None, max_length=32)


async def _get_ticket(session: AsyncSession, ticket_id: int) -> SupportTicketModel:
    ticket = await session.get(SupportTicketModel, ticket_id)
    if ticket is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Ticket not found")
    return ticket


@router.get("/news")
async def list_news(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
    limit: int = Query(default=50, ge=1, le=200),
):
    result = await session.execute(
        select(NewsItemModel).order_by(desc(NewsItemModel.published_at)).limit(limit)
    )
    return [row.to_dict() for row in result.scalars()]


@router.post("/news", status_code=status.HTTP_201_CREATED)
async def publish_news(
    payload: NewsCreate,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _user: Annotated[TokenPayload, Depends(require_role(["admin"]))],
):
    item = NewsItemModel(**payload.model_dump())
    session.add(item)
    await session.commit()
    await session.refresh(item)
    return item.to_dict()


@router.post("/support/tickets", status_code=status.HTTP_201_CREATED)
async def create_ticket(
    payload: TicketCreate,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[TokenPayload, Depends(get_current_user)],
):
    ticket = SupportTicketModel(**payload.model_dump(), created_by=user.sub)
    session.add(ticket)
    await session.commit()
    await session.refresh(ticket)
    return ticket.to_dict()


@router.get("/support/tickets")
async def list_tickets(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[TokenPayload, Depends(get_current_user)],
    limit: int = Query(default=100, ge=1, le=500),
):
    stmt = select(SupportTicketModel).order_by(desc(SupportTicketModel.created_at)).limit(limit)
    if user.role != "admin":
        stmt = stmt.where(SupportTicketModel.created_by == user.sub)
    result = await session.execute(stmt)
    return [row.to_dict() for row in result.scalars()]


@router.get("/support/export")
async def export_open_tickets(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _user: Annotated[TokenPayload, Depends(require_role(["admin"]))],
):
    """Open tickets as JSON for manual delivery to the vendor. Contains only ticket text."""
    result = await session.execute(
        select(SupportTicketModel).where(SupportTicketModel.status == "OPEN").order_by(SupportTicketModel.id)
    )
    return {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "tickets": [
            {k: t.to_dict()[k] for k in ("id", "category", "subject", "message", "created_at")}
            for t in result.scalars()
        ],
    }


@router.post("/support/tickets/{ticket_id}/reply")
async def reply_to_ticket(
    ticket_id: int,
    payload: TicketReply,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _user: Annotated[TokenPayload, Depends(require_role(["admin"]))],
):
    """Record the vendor's reply (imported manually by an admin)."""
    ticket = await _get_ticket(session, ticket_id)
    ticket.vendor_reply = payload.reply
    ticket.replied_at = datetime.now(timezone.utc)
    ticket.status = "ANSWERED"
    await session.commit()
    await session.refresh(ticket)
    return ticket.to_dict()


@router.post("/support/tickets/{ticket_id}/close")
async def close_ticket(
    ticket_id: int,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[TokenPayload, Depends(get_current_user)],
):
    ticket = await _get_ticket(session, ticket_id)
    if user.role != "admin" and ticket.created_by != user.sub:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not your ticket")
    ticket.status = "CLOSED"
    await session.commit()
    await session.refresh(ticket)
    return ticket.to_dict()
