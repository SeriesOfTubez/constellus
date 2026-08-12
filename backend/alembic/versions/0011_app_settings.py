"""add app_settings table

Revision ID: 0011
Revises: 0010
Create Date: 2026-05-09
"""

from alembic import op
import sqlalchemy as sa

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "app_settings",
        sa.Column("key", sa.String(100), primary_key=True),
        sa.Column("value", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    # Seed default log retention
    op.execute("INSERT INTO app_settings (key, value) VALUES ('log_retention_days', '15')")


def downgrade() -> None:
    op.drop_table("app_settings")
