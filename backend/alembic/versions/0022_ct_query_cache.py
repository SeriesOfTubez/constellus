"""Cache table for Certificate Transparency API responses

Certspotter's free tier is 100 req/hr — a single monitoring tick with a few
hundred targets blows past that and every target gets retried with backoff.
Caching successful responses for several hours flattens the call volume to
"once per target per refresh window" regardless of how many runs fire.

Failures are also cached (shorter TTL) so a bogus target value or transient
upstream outage doesn't get hammered every chunk.

Revision ID: 0022
Revises: 0021
Create Date: 2026-05-27
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ct_query_cache",
        sa.Column("domain", sa.String(length=253), primary_key=True),
        sa.Column("payload", JSONB(), nullable=False),
        sa.Column("success", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column(
            "fetched_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("ct_query_cache")
