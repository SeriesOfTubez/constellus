"""sso fields and saml config

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-03
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # SSO fields on users
    op.add_column("users", sa.Column("auth_provider", sa.String(50), nullable=False, server_default="local"))
    op.add_column("users", sa.Column("sso_subject", sa.String(512), nullable=True))
    op.create_index("ix_users_sso_subject", "users", ["sso_subject"])

    # hashed_password is now nullable (SSO-only accounts have no password)
    op.alter_column("users", "hashed_password", nullable=True)

    # SAML configuration table
    op.create_table(
        "saml_configs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("metadata_url", sa.String(1024), nullable=False),
        sa.Column("metadata_xml", sa.Text(), nullable=True),
        sa.Column("metadata_fetched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sp_entity_id", sa.String(512), nullable=False),
        sa.Column("sp_acs_url", sa.String(512), nullable=False),
        sa.Column("jit_provisioning", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("allow_local_fallback", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("saml_configs")
    op.drop_index("ix_users_sso_subject", "users")
    op.drop_column("users", "sso_subject")
    op.drop_column("users", "auth_provider")
    op.alter_column("users", "hashed_password", nullable=False)
