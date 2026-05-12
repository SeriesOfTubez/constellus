"""add system_logs table

Revision ID: 0010
Revises: 0009
Create Date: 2026-05-09
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "system_logs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("level", sa.String(10), nullable=False),
        sa.Column("source", sa.String(100), nullable=False),
        sa.Column("logger_name", sa.String(255), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
    )
    op.create_index("ix_system_logs_created_at", "system_logs", ["created_at"])
    op.create_index("ix_system_logs_source", "system_logs", ["source"])
    op.create_index("ix_system_logs_level", "system_logs", ["level"])


def downgrade() -> None:
    op.drop_table("system_logs")
