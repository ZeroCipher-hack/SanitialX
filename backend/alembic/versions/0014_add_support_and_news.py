"""add support tickets and news items

Revision ID: 0014_support_and_news
Revises: 0013_agent_command_hardening
"""
from alembic import op
import sqlalchemy as sa

revision = "0014_support_and_news"
down_revision = "0013_agent_command_hardening"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "support_tickets",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("category", sa.String(length=20), nullable=False),
        sa.Column("subject", sa.String(length=200), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="OPEN"),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        sa.Column("vendor_reply", sa.Text(), nullable=True),
        sa.Column("replied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_support_tickets_category", "support_tickets", ["category"])
    op.create_index("ix_support_tickets_status", "support_tickets", ["status"])
    op.create_index("ix_support_tickets_created_by", "support_tickets", ["created_by"])
    op.create_table(
        "news_items",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("category", sa.String(length=20), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_news_items_category", "news_items", ["category"])
    op.create_index("ix_news_items_published_at", "news_items", ["published_at"])


def downgrade() -> None:
    op.drop_index("ix_news_items_published_at", table_name="news_items")
    op.drop_index("ix_news_items_category", table_name="news_items")
    op.drop_table("news_items")
    op.drop_index("ix_support_tickets_created_by", table_name="support_tickets")
    op.drop_index("ix_support_tickets_status", table_name="support_tickets")
    op.drop_index("ix_support_tickets_category", table_name="support_tickets")
    op.drop_table("support_tickets")
