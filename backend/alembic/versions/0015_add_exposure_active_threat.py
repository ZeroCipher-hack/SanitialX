"""add active-threat (honeypot local signal) flag to asset exposures

Revision ID: 0015_add_exposure_active_threat
Revises: 0014_add_epss_scoring
"""

from alembic import op
import sqlalchemy as sa

revision = "0015_add_exposure_active_threat"
down_revision = "0014_add_epss_scoring"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "asset_vulnerabilities",
        sa.Column("active_threat", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_index(
        "ix_asset_vulnerabilities_active_threat",
        "asset_vulnerabilities",
        ["active_threat"],
    )


def downgrade() -> None:
    op.drop_index("ix_asset_vulnerabilities_active_threat", table_name="asset_vulnerabilities")
    op.drop_column("asset_vulnerabilities", "active_threat")
