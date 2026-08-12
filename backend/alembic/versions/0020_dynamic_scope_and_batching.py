"""Dynamic scope + batched runs on scan_templates

Adds the foundational columns for the Wiz-model continuous-monitoring rebuild:

  scan_templates.dynamic_scope        — when true, executor resolves scope from
                                        the targets table at run start instead
                                        of reading template.scope.
  scan_templates.target_tag_filter    — when non-empty, only targets carrying
                                        at least one of these tags are included
                                        in the resolved scope. Empty = all targets.
  scan_templates.batch_size           — chunk size for the resolved scope. A
                                        single ScanRun processes the resolved
                                        targets in batches of this size.
  scan_templates.batch_delay_seconds  — sleep between batches.
  scan_runs.partial_failures          — per-chunk error log. Final status is
                                        COMPLETED even with partial failures;
                                        FAILED only on hard aborts.

Revision ID: 0020
Revises: 0019
Create Date: 2026-05-27
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scan_templates",
        sa.Column("dynamic_scope", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.add_column(
        "scan_templates",
        sa.Column("target_tag_filter", JSONB(), nullable=False, server_default=sa.text("'[]'")),
    )
    op.add_column(
        "scan_templates",
        sa.Column("batch_size", sa.Integer(), nullable=True),
    )
    op.add_column(
        "scan_templates",
        sa.Column("batch_delay_seconds", sa.Integer(), nullable=False, server_default=sa.text("0")),
    )
    op.add_column(
        "scan_runs",
        sa.Column("partial_failures", JSONB(), nullable=False, server_default=sa.text("'[]'")),
    )


def downgrade() -> None:
    op.drop_column("scan_runs", "partial_failures")
    op.drop_column("scan_templates", "batch_delay_seconds")
    op.drop_column("scan_templates", "batch_size")
    op.drop_column("scan_templates", "target_tag_filter")
    op.drop_column("scan_templates", "dynamic_scope")
