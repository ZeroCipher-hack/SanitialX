"""Harden agent command delivery with uniqueness and lease metadata.

Revision ID: 0013_agent_command_hardening
Revises: 0012_agent_commands
"""
from alembic import op
import sqlalchemy as sa

revision = "0013_agent_command_hardening"
down_revision = "0012_agent_commands"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("agent_commands", sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True))
    op.add_column("agent_commands", sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"))
    op.create_index("ix_agent_commands_lease_until", "agent_commands", ["lease_until"], unique=False)
    op.create_unique_constraint("uq_agent_commands_action_id", "agent_commands", ["action_id"])


def downgrade() -> None:
    op.drop_constraint("uq_agent_commands_action_id", "agent_commands", type_="unique")
    op.drop_index("ix_agent_commands_lease_until", table_name="agent_commands")
    op.drop_column("agent_commands", "attempt_count")
    op.drop_column("agent_commands", "lease_until")
