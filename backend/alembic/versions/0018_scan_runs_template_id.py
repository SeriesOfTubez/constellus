"""Add template_id to scan_runs

Splits scan identity (templates) from scan observations (runs). Each run
references the template it was launched from, enabling rerun, schedule-
driven runs (APScheduler), and edit-then-rerun workflows.

Backfills: existing scan_runs get a synthetic ScanTemplate created from
their scope/options so historical runs remain rerunnable.

Revision ID: 0018
Revises: 0017
Create Date: 2026-05-25
"""

from alembic import op
import sqlalchemy as sa


revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scan_runs",
        sa.Column("template_id", sa.dialects.postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_scan_runs_template_id",
        "scan_runs",
        "scan_templates",
        ["template_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_scan_runs_template_id_created_at",
        "scan_runs",
        ["template_id", sa.text("created_at DESC")],
    )

    # Backfill: every existing run gets a one-shot template that mirrors its
    # scope/options. Future runs from the same template are then possible.
    op.execute("""
        DO $$
        DECLARE
            run_row RECORD;
            new_template_id UUID;
        BEGIN
            FOR run_row IN SELECT * FROM scan_runs WHERE template_id IS NULL LOOP
                new_template_id := gen_random_uuid();
                INSERT INTO scan_templates
                    (id, name, scope, options, schedule_cron, enabled,
                     created_at, created_by_id, tags)
                VALUES (
                    new_template_id,
                    COALESCE(run_row.name, 'Backfilled scan'),
                    run_row.scope,
                    COALESCE(run_row.options, '{}'::jsonb),
                    NULL,
                    false,
                    run_row.created_at,
                    run_row.created_by_id,
                    '[]'::jsonb
                );
                UPDATE scan_runs SET template_id = new_template_id
                WHERE id = run_row.id;
            END LOOP;
        END $$;
    """)


def downgrade() -> None:
    op.drop_index("ix_scan_runs_template_id_created_at", table_name="scan_runs")
    op.drop_constraint("fk_scan_runs_template_id", "scan_runs", type_="foreignkey")
    op.drop_column("scan_runs", "template_id")
