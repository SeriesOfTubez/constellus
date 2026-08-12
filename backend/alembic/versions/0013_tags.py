"""add tags to targets/assets/findings; create tag_rules table

Revision ID: 0013
Revises: 0012
Create Date: 2026-05-21
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Tags column on all three entity tables
    op.add_column("targets", sa.Column("tags", JSONB, nullable=False, server_default=sa.text("'[]'")))
    op.add_column("assets", sa.Column("tags", JSONB, nullable=False, server_default=sa.text("'[]'")))
    op.add_column("findings", sa.Column("tags", JSONB, nullable=False, server_default=sa.text("'[]'")))

    op.create_table(
        "tag_rules",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("entity_type", sa.Text, nullable=False),   # target | asset | finding
        sa.Column("condition", JSONB, nullable=False),
        sa.Column("tag", sa.Text, nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("created_by_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("tag_rules")
    op.drop_column("findings", "tags")
    op.drop_column("assets", "tags")
    op.drop_column("targets", "tags")
