"""domain whois cache table

Revision ID: 0015
Revises: 0014
Create Date: 2026-05-23
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "domain_whois_cache",
        sa.Column("domain", sa.Text, primary_key=True),
        sa.Column("registrar", sa.Text, nullable=True),
        sa.Column("registrant_org", sa.Text, nullable=True),
        sa.Column("registrant_country", sa.Text, nullable=True),
        sa.Column("creation_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expiration_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("name_servers", JSONB, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("status", JSONB, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("dnssec", sa.Text, nullable=True),
        sa.Column("looked_up_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )


def downgrade() -> None:
    op.drop_table("domain_whois_cache")
