"""drop email_configs table (replaced by connector_configs)

Revision ID: 0009
Revises: 0008
Create Date: 2026-05-09
"""

from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_table("email_configs")


def downgrade() -> None:
    import sqlalchemy as sa
    from sqlalchemy.dialects.postgresql import UUID
    op.create_table(
        "email_configs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("from_email", sa.String(255), nullable=False),
        sa.Column("from_name", sa.String(100), nullable=True),
        sa.Column("config_encrypted", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
