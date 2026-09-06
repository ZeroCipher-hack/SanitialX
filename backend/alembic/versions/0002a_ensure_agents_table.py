"""ensure agents table exists before vulnerability foreign keys

Revision ID: 0002a_ensure_agents_table
Revises: 0002_add_users_table
Create Date: 2026-09-06
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0002a_ensure_agents_table"
down_revision: Union[str, None] = "0002_add_users_table"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    # Alembic creates version_num as VARCHAR(32) by default. Some existing
    # SanitialX revision identifiers are longer, so widen it before Alembic
    # attempts to persist the next revision ID.
    op.alter_column(
        "alembic_version",
        "version_num",
        existing_type=sa.String(length=32),
        type_=sa.String(length=64),
        existing_nullable=False,
    )

    if inspector.has_table("agents"):
        return

    op.create_table(
        "agents",
        sa.Column("agent_id", sa.String(length=64), nullable=False),
        sa.Column("hostname", sa.String(length=100), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("os", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="ONLINE"),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("cpu_usage", sa.Float(), nullable=False, server_default="0"),
        sa.Column("memory_usage", sa.Float(), nullable=False, server_default="0"),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("events_count", sa.Integer(), nullable=False, server_default="0"),
        sa.PrimaryKeyConstraint("agent_id"),
    )
    op.create_index("ix_agents_hostname", "agents", ["hostname"], unique=False)
    op.create_index("ix_agents_status", "agents", ["status"], unique=False)


def downgrade() -> None:
    # Keep the widened Alembic revision column and do not drop agents because
    # both may predate this reconciliation migration in existing installs.
    pass
