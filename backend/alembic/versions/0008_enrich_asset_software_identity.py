"""Enrich asset software identity with ecosystem, purl, and cpe.

Revision ID: 0008_enrich_asset_software_identity
Revises: 0007_add_asset_management_metadata
"""

from alembic import op
import sqlalchemy as sa

revision = "0008_enrich_asset_software_identity"
down_revision = "0007_add_asset_management_metadata"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("asset_software", sa.Column("ecosystem", sa.String(length=40), nullable=True))
    op.add_column("asset_software", sa.Column("purl", sa.String(length=512), nullable=True))
    op.add_column("asset_software", sa.Column("cpe", sa.String(length=512), nullable=True))
    op.create_index("ix_asset_software_ecosystem", "asset_software", ["ecosystem"], unique=False)
    op.create_index("ix_asset_software_purl", "asset_software", ["purl"], unique=False)
    op.create_index("ix_asset_software_cpe", "asset_software", ["cpe"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_asset_software_cpe", table_name="asset_software")
    op.drop_index("ix_asset_software_purl", table_name="asset_software")
    op.drop_index("ix_asset_software_ecosystem", table_name="asset_software")
    op.drop_column("asset_software", "cpe")
    op.drop_column("asset_software", "purl")
    op.drop_column("asset_software", "ecosystem")
