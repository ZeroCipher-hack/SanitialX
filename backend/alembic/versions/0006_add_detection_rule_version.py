"""add detection rule version

Revision ID: 0006_add_detection_rule_version
Revises: 0005_add_vulnerability_alerts
"""

from alembic import op
import sqlalchemy as sa

revision = "0006_add_detection_rule_version"
down_revision = "0005_add_vulnerability_alerts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "detection_rules",
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
    )


def downgrade() -> None:
    op.drop_column("detection_rules", "version")
