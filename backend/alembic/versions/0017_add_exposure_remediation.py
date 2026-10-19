"""add remediation workflow fields to asset exposures

Revision ID: 0017_add_exposure_remediation
Revises: 0016_create_honeypot_sessions
"""

from alembic import op
import sqlalchemy as sa

revision = "0017_add_exposure_remediation"
down_revision = "0016_create_honeypot_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "asset_vulnerabilities",
        sa.Column("remediation_status", sa.String(length=20), nullable=False, server_default="OPEN"),
    )
    op.add_column(
        "asset_vulnerabilities",
        sa.Column("remediation_note", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column(
        "asset_vulnerabilities",
        sa.Column("remediation_updated_by", sa.String(length=120), nullable=True),
    )
    op.add_column(
        "asset_vulnerabilities",
        sa.Column("remediation_updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_asset_vulnerabilities_remediation_status",
        "asset_vulnerabilities",
        ["remediation_status"],
    )


def downgrade() -> None:
    op.drop_index("ix_asset_vulnerabilities_remediation_status", table_name="asset_vulnerabilities")
    op.drop_column("asset_vulnerabilities", "remediation_updated_at")
    op.drop_column("asset_vulnerabilities", "remediation_updated_by")
    op.drop_column("asset_vulnerabilities", "remediation_note")
    op.drop_column("asset_vulnerabilities", "remediation_status")
