"""Add scan_runs.kind to classify run origin

Lets the Activity page filter scheduled / target-add runs (which users want
to see) from on-demand asset / finding rechecks (which should stay in logs,
not the Activity feed). Values:

  monitoring         — fired by APScheduler from a scheduled template
  initial_discovery  — one-off run kicked off when a target is added
  recheck            — single-asset or single-finding on-demand scan
  manual             — anything else (legacy /api/scans POST, hand-built runs)

Backfill is heuristic and inspects existing rows:

  - template_id IS NOT NULL                            → monitoring
  - name LIKE 'Initial discovery%'                     → initial_discovery
  - options ? 'skip_discovery'                         → recheck
  - otherwise                                          → manual

The column is NOT NULL with server default 'manual' for safe future inserts.

Revision ID: 0021
Revises: 0020
Create Date: 2026-05-27
"""

from alembic import op
import sqlalchemy as sa


revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scan_runs",
        sa.Column(
            "kind",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'manual'"),
        ),
    )
    op.create_index("ix_scan_runs_kind", "scan_runs", ["kind"])

    op.execute(
        """
        UPDATE scan_runs
        SET kind = CASE
            WHEN template_id IS NOT NULL                   THEN 'monitoring'
            WHEN name LIKE 'Initial discovery%'            THEN 'initial_discovery'
            WHEN options ? 'skip_discovery'                THEN 'recheck'
            ELSE 'manual'
        END
        """
    )


def downgrade() -> None:
    op.drop_index("ix_scan_runs_kind", table_name="scan_runs")
    op.drop_column("scan_runs", "kind")
