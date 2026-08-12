"""domain verifications table and asset ignored flag

Revision ID: 0005
Revises: 0004
Create Date: 2026-05-04
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "domain_verifications",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("domain", sa.String(253), nullable=False),
        sa.Column("verified", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("method", sa.String(20), nullable=True),
        sa.Column("connector_id", sa.String(50), nullable=True),
        sa.Column("token", sa.String(64), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_domain_verifications_domain", "domain_verifications", ["domain"])
    op.create_unique_constraint("uq_domain_verifications_domain", "domain_verifications", ["domain"])

    op.add_column("assets", sa.Column("ignored", sa.Boolean(), nullable=False, server_default="false"))


def downgrade() -> None:
    op.drop_column("assets", "ignored")
    op.drop_table("domain_verifications")
