"""Add scan_runs.port_scan_unauthorised_count (planning#204).

## The problem this surfaces

An asset the probe-authorisation gate declined to authorise for `ip`
addressing (port scanning) is visually identical, both on the asset itself
and on the run that touched it, to an asset that WAS port-scanned and had
nothing open. For a security tool those are opposite conclusions — one says
"we looked and found nothing", the other says "we did not look". This
column is the run-level half of closing that gap (the asset-level half is
`probe_class`, already projected onto `asset_state.attributes` and now
serialized top-level by `api/assets.py`, no migration needed there since it
reads an existing JSONB key).

## What it counts, and what it deliberately does not

The count is `probe_class`-derived only: the canonical asset ids, among the
assets a run's `authorise_probes()` calls evaluated, whose `probe_class` cap
did not license `ip` addressing (see `GateResult.
port_scan_unauthorised_ids`'s docstring in `app/services/
probe_authorisation.py` for the exact derivation). Scope denials and
posture denials (`posture:ma_pre_close`) are NOT included — the issue this
migration serves rejected a decision-log read surface (a query over
`authorisation_decisions` computed at request time) in favour of a
plain stamped counter, and a counter that mixed three denial reasons into
one number would need that read surface to be interpretable anyway. A
future issue that wants the full breakdown reads the decision log directly;
this column answers only the "was this run's port scan short-handed"
question the Activity feed asks.

## Reading 0 on a pre-migration run

Every run that completed before this migration reads back `0` under
`server_default`, which is indistinguishable from "the gate denied nothing
that run". That ambiguity is accepted, not resolved, the same way
`asset_count`/`finding_count` accept it for runs older than migration 0025 —
it is safe here specifically because the UI (`Activity.tsx`) only renders
the line for `count > 0`, never renders the bare number unconditionally, so
a stale `0` reads as silence rather than as a false claim.

No data migration: existing rows get the server default, and nothing here
could backfill a real count retroactively — `authorisation_decisions` rows
for old runs may not exist or may already be orphaned (0056).

Revision ID: 0057
Revises: 0056
Create Date: 2026-09-21
"""

from alembic import op
import sqlalchemy as sa

revision = "0057"
down_revision = "0056"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scan_runs",
        sa.Column(
            "port_scan_unauthorised_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )


def downgrade() -> None:
    op.drop_column("scan_runs", "port_scan_unauthorised_count")
