"""add approved agent command queue

Revision ID: 0012_agent_commands
Revises: 0011_soar_approval
Create Date: 2026-09-06
"""
from alembic import op
import sqlalchemy as sa

revision = "0012_agent_commands"
down_revision = "0011_soar_approval"
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table(
        "agent_commands",
        sa.Column("command_id", sa.String(length=36), primary_key=True),
        sa.Column("agent_id", sa.String(length=64), sa.ForeignKey("agents.agent_id", ondelete="CASCADE"), nullable=False),
        sa.Column("action_id", sa.String(length=36), sa.ForeignKey("soar_actions.action_id", ondelete="CASCADE"), nullable=False),
        sa.Column("command_type", sa.String(length=64), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False, server_default="QUEUED"),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_agent_commands_agent_id", "agent_commands", ["agent_id"])
    op.create_index("ix_agent_commands_action_id", "agent_commands", ["action_id"])
    op.create_index("ix_agent_commands_command_type", "agent_commands", ["command_type"])
    op.create_index("ix_agent_commands_status", "agent_commands", ["status"])

def downgrade() -> None:
    op.drop_index("ix_agent_commands_status", table_name="agent_commands")
    op.drop_index("ix_agent_commands_command_type", table_name="agent_commands")
    op.drop_index("ix_agent_commands_action_id", table_name="agent_commands")
    op.drop_index("ix_agent_commands_agent_id", table_name="agent_commands")
    op.drop_table("agent_commands")
