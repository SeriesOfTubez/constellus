"""whois cache table

Revision ID: 0014
Revises: 0013
Create Date: 2026-05-23
"""

from alembic import op
import sqlalchemy as sa

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "whois_cache",
        sa.Column("ip", sa.Text, primary_key=True),
        sa.Column("org", sa.Text, nullable=True),
        sa.Column("asn", sa.Text, nullable=True),
        sa.Column("looked_up_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )


def downgrade() -> None:
    op.drop_table("whois_cache")
