"""replace domain_verifications with targets

Revision ID: 0006
Revises: 0005
Create Date: 2026-05-07
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "targets",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("type", sa.String(10), nullable=False),
        sa.Column("value", sa.String(253), nullable=False),
        sa.Column("verified", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("verification_method", sa.String(20), nullable=True),
        sa.Column("connector_id", sa.String(50), nullable=True),
        sa.Column("token", sa.String(64), nullable=False),
        sa.Column("whois_org", sa.String(255), nullable=True),
        sa.Column("whois_asn", sa.String(50), nullable=True),
        sa.Column("verified_by_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("notes", sa.Text(), nullable=True),
    )
    op.create_index("ix_targets_value", "targets", ["value"])
    op.create_index("ix_targets_type", "targets", ["type"])
    op.create_unique_constraint("uq_targets_value", "targets", ["value"])

    # Migrate existing domain_verifications rows into targets
    op.execute("""
        INSERT INTO targets (id, type, value, verified, verification_method, connector_id, token, verified_at, created_at)
        SELECT id, 'domain', domain, verified, method, connector_id, token, verified_at, created_at
        FROM domain_verifications
        ON CONFLICT (value) DO NOTHING
    """)

    op.drop_table("domain_verifications")


def downgrade() -> None:
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
    op.execute("""
        INSERT INTO domain_verifications (id, domain, verified, method, connector_id, token, verified_at, created_at)
        SELECT id, value, verified, verification_method, connector_id, token, verified_at, created_at
        FROM targets WHERE type = 'domain'
        ON CONFLICT DO NOTHING
    """)
    op.drop_table("targets")
