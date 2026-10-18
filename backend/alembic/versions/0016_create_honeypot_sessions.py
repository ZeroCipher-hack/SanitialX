"""create honeypot_sessions table

The HoneypotSessionModel and its API shipped without a migration, so the
table only existed under the test suite's create_all — never on a real
Alembic-migrated database. This creates it for real deployments.

Revision ID: 0016_create_honeypot_sessions
Revises: 0015_add_exposure_active_threat
"""

from alembic import op
import sqlalchemy as sa

revision = "0016_create_honeypot_sessions"
down_revision = "0015_add_exposure_active_threat"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "honeypot_sessions" in inspector.get_table_names():
        # Tolerate databases where create_all already made the table.
        return
    op.create_table(
        "honeypot_sessions",
        sa.Column("session_id", sa.String(length=64), primary_key=True),
        sa.Column("attacker_ip", sa.String(length=45), nullable=False),
        sa.Column("service", sa.String(length=50), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_seconds", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("credentials_attempted", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("commands_executed", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("files_accessed", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="50"),
        sa.Column("notes", sa.Text(), nullable=True),
    )
    op.create_index("ix_honeypot_sessions_attacker_ip", "honeypot_sessions", ["attacker_ip"])
    op.create_index("ix_honeypot_sessions_service", "honeypot_sessions", ["service"])
    op.create_index("ix_honeypot_sessions_started_at", "honeypot_sessions", ["started_at"])


def downgrade() -> None:
    op.drop_index("ix_honeypot_sessions_started_at", table_name="honeypot_sessions")
    op.drop_index("ix_honeypot_sessions_service", table_name="honeypot_sessions")
    op.drop_index("ix_honeypot_sessions_attacker_ip", table_name="honeypot_sessions")
    op.drop_table("honeypot_sessions")
