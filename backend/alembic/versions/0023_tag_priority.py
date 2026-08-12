"""Add tag_priority to scan_templates for tag-based cadence overrides

The default monitoring template runs daily and covers every target. To
support tiered cadences ("critical" tagged targets scanned hourly,
"archived" weekly, etc.) we let admins create additional scan_templates
with target_tag_filter set + tag_priority populated.

tag_priority = NULL  → not a cadence tier (the default monitoring template
                       and any ad-hoc / manual templates fall here)
tag_priority = N     → cadence tier. Lower N wins when a target carries
                       multiple matching tags.

At scope-resolution time the executor iterates tier templates in priority
order; each target is owned by the first matching tier (or by the default
template if no tier matches).

Revision ID: 0023
Revises: 0022
Create Date: 2026-05-28
"""

from alembic import op
import sqlalchemy as sa


revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scan_templates",
        sa.Column("tag_priority", sa.Integer(), nullable=True),
    )
    op.create_index(
        "ix_scan_templates_tag_priority",
        "scan_templates",
        ["tag_priority"],
        postgresql_where=sa.text("tag_priority IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_scan_templates_tag_priority", table_name="scan_templates")
    op.drop_column("scan_templates", "tag_priority")
