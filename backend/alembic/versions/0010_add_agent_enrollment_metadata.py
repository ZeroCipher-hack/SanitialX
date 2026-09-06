"""add agent enrollment metadata

Revision ID: 0010_agent_enrollment
Revises: 0009_add_asset_lifecycle_metadata
Create Date: 2026-09-06
"""

from alembic import op
import sqlalchemy as sa

revision = "0010_agent_enrollment"
down_revision = "0009_add_asset_lifecycle_metadata"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("agents", sa.Column("agent_token_hash", sa.String(length=64), nullable=True))
    op.add_column("agents", sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("agents", sa.Column("agent_version", sa.String(length=40), nullable=True))
    op.create_index("ix_agents_agent_token_hash", "agents", ["agent_token_hash"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_agents_agent_token_hash", table_name="agents")
    op.drop_column("agents", "agent_version")
    op.drop_column("agents", "enrolled_at")
    op.drop_column("agents", "agent_token_hash")
