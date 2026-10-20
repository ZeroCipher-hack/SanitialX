"""add EPSS exploit-prediction scoring to vulnerabilities

Revision ID: 0014_add_epss_scoring
Revises: 0013_agent_command_hardening
"""

from alembic import op
import sqlalchemy as sa

revision = "0014_add_epss_scoring"
down_revision = "0013_agent_command_hardening"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vulnerabilities",
        sa.Column("epss_score", sa.Float(), nullable=True),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("epss_percentile", sa.Float(), nullable=True),
    )
    op.create_index(
        "ix_vulnerabilities_epss_score",
        "vulnerabilities",
        ["epss_score"],
    )


def downgrade() -> None:
    op.drop_index("ix_vulnerabilities_epss_score", table_name="vulnerabilities")
    op.drop_column("vulnerabilities", "epss_percentile")
    op.drop_column("vulnerabilities", "epss_score")
