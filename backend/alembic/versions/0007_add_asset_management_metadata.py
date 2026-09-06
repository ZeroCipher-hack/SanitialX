"""add asset-management metadata to agents

Revision ID: 0007_add_asset_management_metadata
Revises: 0006_add_detection_rule_version
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0007_add_asset_management_metadata"
down_revision = "0006_add_detection_rule_version"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("agents", sa.Column("asset_type", sa.String(length=32), nullable=False, server_default="ENDPOINT"))
    op.add_column("agents", sa.Column("criticality", sa.String(length=20), nullable=False, server_default="MEDIUM"))
    op.add_column("agents", sa.Column("environment", sa.String(length=32), nullable=False, server_default="UNKNOWN"))
    op.add_column("agents", sa.Column("owner", sa.String(length=160), nullable=True))
    op.add_column("agents", sa.Column("internet_exposed", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("agents", sa.Column("tags", sa.JSON(), nullable=False, server_default="[]"))
    op.add_column("agents", sa.Column("source", sa.String(length=40), nullable=False, server_default="agent"))
    op.add_column("agents", sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")))

    op.create_index("ix_agents_asset_type", "agents", ["asset_type"])
    op.create_index("ix_agents_criticality", "agents", ["criticality"])
    op.create_index("ix_agents_environment", "agents", ["environment"])
    op.create_index("ix_agents_internet_exposed", "agents", ["internet_exposed"])
    op.create_index("ix_agents_risk_score", "agents", ["risk_score"])
    op.create_index("ix_agents_last_seen", "agents", ["last_seen"])
    op.create_index("ix_agents_ip_address", "agents", ["ip_address"])


def downgrade() -> None:
    for name in (
        "ix_agents_ip_address",
        "ix_agents_last_seen",
        "ix_agents_risk_score",
        "ix_agents_internet_exposed",
        "ix_agents_environment",
        "ix_agents_criticality",
        "ix_agents_asset_type",
    ):
        op.drop_index(name, table_name="agents")

    for column in (
        "first_seen",
        "source",
        "tags",
        "internet_exposed",
        "owner",
        "environment",
        "criticality",
        "asset_type",
    ):
        op.drop_column("agents", column)
