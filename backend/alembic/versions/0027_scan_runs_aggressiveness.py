"""Add aggressiveness column to scan_runs.

Denormalised from the global app_settings (or per-run override) at run
start so audit logs can answer "why did this scan generate so many
requests" without having to time-travel through app_settings history.

The global default lives in app_settings under key 'aggressiveness';
no schema change there — that table is generic key/value.

Revision ID: 0027
Revises: 0026
Create Date: 2026-05-30
"""

from alembic import op
import sqlalchemy as sa


revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None


_TIERS = ("stealth", "polite", "standard", "aggressive")


def upgrade() -> None:
    op.add_column(
        "scan_runs",
        sa.Column(
            "aggressiveness",
            sa.String(20),
            nullable=False,
            server_default="polite",
        ),
    )
    op.create_check_constraint(
        "ck_scan_runs_aggressiveness",
        "scan_runs",
        f"aggressiveness IN ({', '.join(repr(t) for t in _TIERS)})",
    )


def downgrade() -> None:
    op.drop_constraint("ck_scan_runs_aggressiveness", "scan_runs", type_="check")
    op.drop_column("scan_runs", "aggressiveness")
