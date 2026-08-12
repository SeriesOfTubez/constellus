"""Per-target aggressiveness override + allow scan_runs.aggressiveness='mixed'.

Adds a nullable `aggressiveness` column to `targets` so individual targets
can override the global tier (e.g. scanme.nmap.org needs to run aggressive
even when the rest of the fleet runs polite). NULL = inherit from the
template / global default.

Also widens the scan_runs.aggressiveness CHECK constraint to accept
'mixed' — a single run can now contain targets at multiple tiers, in
which case the audit field records 'mixed' and a per-chunk breakdown
lives in the partial_failures-style log.

Revision ID: 0028
Revises: 0027
Create Date: 2026-05-30
"""

from alembic import op
import sqlalchemy as sa


revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None


_TIERS = ("stealth", "polite", "standard", "aggressive")
_RUN_VALUES = _TIERS + ("mixed",)


def upgrade() -> None:
    op.add_column(
        "targets",
        sa.Column("aggressiveness", sa.String(20), nullable=True),
    )
    op.create_check_constraint(
        "ck_targets_aggressiveness",
        "targets",
        f"aggressiveness IS NULL OR aggressiveness IN ({', '.join(repr(t) for t in _TIERS)})",
    )

    op.drop_constraint("ck_scan_runs_aggressiveness", "scan_runs", type_="check")
    op.create_check_constraint(
        "ck_scan_runs_aggressiveness",
        "scan_runs",
        f"aggressiveness IN ({', '.join(repr(t) for t in _RUN_VALUES)})",
    )


def downgrade() -> None:
    op.drop_constraint("ck_scan_runs_aggressiveness", "scan_runs", type_="check")
    op.create_check_constraint(
        "ck_scan_runs_aggressiveness",
        "scan_runs",
        f"aggressiveness IN ({', '.join(repr(t) for t in _TIERS)})",
    )

    op.drop_constraint("ck_targets_aggressiveness", "targets", type_="check")
    op.drop_column("targets", "aggressiveness")
