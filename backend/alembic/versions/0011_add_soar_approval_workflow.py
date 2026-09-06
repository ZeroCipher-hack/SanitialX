"""add approval-based SOAR workflow

Revision ID: 0011_soar_approval
Revises: 0010_agent_enrollment
Create Date: 2026-09-06
"""
from alembic import op
import sqlalchemy as sa

revision = "0011_soar_approval"
down_revision = "0010_agent_enrollment"
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table(
        "soar_actions",
        sa.Column("action_id", sa.String(length=36), primary_key=True),
        sa.Column("incident_id", sa.String(length=36), sa.ForeignKey("incidents.incident_id", ondelete="CASCADE"), nullable=False),
        sa.Column("action_type", sa.String(length=64), nullable=False),
        sa.Column("target_type", sa.String(length=32), nullable=False),
        sa.Column("target_value", sa.String(length=255), nullable=False),
        sa.Column("parameters", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False, server_default="PENDING"),
        sa.Column("risk_level", sa.String(length=16), nullable=False, server_default="MEDIUM"),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("requested_by", sa.String(length=255), nullable=False),
        sa.Column("approved_by", sa.String(length=255), nullable=True),
        sa.Column("rejected_by", sa.String(length=255), nullable=True),
        sa.Column("execution_result", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_index("ix_soar_actions_incident_id", "soar_actions", ["incident_id"])
    op.create_index("ix_soar_actions_action_type", "soar_actions", ["action_type"])
    op.create_index("ix_soar_actions_status", "soar_actions", ["status"])
    op.create_table(
        "soar_audit_log",
        sa.Column("audit_id", sa.String(length=36), primary_key=True),
        sa.Column("action_id", sa.String(length=36), sa.ForeignKey("soar_actions.action_id", ondelete="CASCADE"), nullable=False),
        sa.Column("actor", sa.String(length=255), nullable=False),
        sa.Column("event", sa.String(length=32), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_soar_audit_log_action_id", "soar_audit_log", ["action_id"])
    op.create_index("ix_soar_audit_log_event", "soar_audit_log", ["event"])

def downgrade() -> None:
    op.drop_index("ix_soar_audit_log_event", table_name="soar_audit_log")
    op.drop_index("ix_soar_audit_log_action_id", table_name="soar_audit_log")
    op.drop_table("soar_audit_log")
    op.drop_index("ix_soar_actions_status", table_name="soar_actions")
    op.drop_index("ix_soar_actions_action_type", table_name="soar_actions")
    op.drop_index("ix_soar_actions_incident_id", table_name="soar_actions")
    op.drop_table("soar_actions")
