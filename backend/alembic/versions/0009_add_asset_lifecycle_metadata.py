"""Add asset lifecycle status and inventory freshness metadata.

Revision ID: 0009_add_asset_lifecycle_metadata
Revises: 0008_enrich_asset_software_identity
"""

from alembic import op
import sqlalchemy as sa

revision = "0009_add_asset_lifecycle_metadata"
down_revision = "0008_enrich_asset_software_identity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "agents",
        sa.Column("lifecycle_status", sa.String(length=24), nullable=False, server_default="DISCOVERED"),
    )
    op.add_column(
        "agents",
        sa.Column("inventory_updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_agents_lifecycle_status", "agents", ["lifecycle_status"], unique=False)
    op.create_index("ix_agents_inventory_updated_at", "agents", ["inventory_updated_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_agents_inventory_updated_at", table_name="agents")
    op.drop_index("ix_agents_lifecycle_status", table_name="agents")
    op.drop_column("agents", "inventory_updated_at")
    op.drop_column("agents", "lifecycle_status")
