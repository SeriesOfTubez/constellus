"""Temporal layer — score_history + hygiene_history (planning#131, slice 1).

Constellus recomputes `risk_score`/`risk_band`/`building_velocity` on
`findings_canonical` and `score`/`band` on `asset_hygiene_score` in place —
every write overwrites the prior value, so there is no way to answer "when
did this finding cross into High" or "did this asset's hygiene improve
after last month's remediation push" without re-deriving it from scratch.
This migration adds the two append-only change logs that make those
questions answerable: `score_history` (per-finding risk-score changes) and
`hygiene_history` (per-asset hygiene-score changes).

Both are natively RANGE-partitioned, monthly, exactly like `claim_history`
(migration 0039) — same hot-window convention so partition maintenance
stays ONE pattern across all three tables (see
`app.services.partition_maintenance`, this same commit) rather than a
second bespoke scheme. As with `claim_history`, `PARTITION BY` cannot be
expressed via `op.create_table`, so the table + partition DDL below is raw
`op.execute(...)` SQL, with partition bounds computed at migration-run time
(current month / next month) rather than hardcoded, plus a DEFAULT
catch-all partition (`<table>_default`) that absorbs anything outside the
seeded range until the next partition-maintenance tick provisions ahead.

Scope of THIS slice (do not re-litigate without a real reason — see
planning#131):
  * `score_history` captures per-FINDING change-only rows (see
    `app.services.score_history`'s module docstring for why this deviates
    from the issue's literal "one row per finding per scored_at" — it is a
    deliberate, load-bearing design decision, not an oversight).
  * `hygiene_history` captures per-ASSET change-only rows only — NO roll-up
    grain (the epic mentions "asset and roll-up grain"). Roll-up is blocked
    on planning#120 (no org/business-unit graph exists yet), the same
    reason planning#130 L1 excluded roll-up from `asset_hygiene_score`
    itself. Asset grain only, here and now.
  * The summariser / archive tier that would eventually read these tables
    and collapse old partitions into a durable rollup is explicitly OUT OF
    SCOPE — it's blocked on a decision the user hasn't made yet (what an
    archive snapshot even contains). This is exactly why partition DROP is
    disabled for both tables in `partition_maintenance` (`drop_expired=
    False`): dropping a hot partition before a summariser exists to
    receive its rows is data loss, not cleanup. A follow-up issue will be
    filed by the reviewer once the summariser design is settled.

No foreign keys on either table — mirrors `claim_history`, which
deliberately has none: history must outlive the entity it describes (a
finding or an asset can be deleted; the record of what its score used to be
should not vanish with it), and an FK would make a future partition
DROP/DETACH more expensive by forcing Postgres to validate referential
integrity across a detach boundary. `score_history.asset_canonical_id` is
denormalised onto the table for the same underlying reason: an asset- (and,
later, business-unit-) grain trend query must not have to join through a
`findings_canonical` row that may since have been deleted just to find out
which asset a historical score belonged to.

CHECK constraints: `risk_score BETWEEN 0 AND 100` on `score_history`,
`score BETWEEN 0 AND 100` on `hygiene_history` — both real integer columns
real queries will sort/filter on, so it's worth failing at the DB boundary
on an out-of-range value the way `asset_hygiene_score.score` already does
(migration 0045). Deliberately NOT adding a CHECK on either table's band
column (`risk_band` / `band`): `findings_canonical.risk_band` has no CHECK
constraint today, so adding one only on its history log would be an
inconsistency, not a tightening — the two would drift the moment
`risk_scorer.BANDS` gains or renames a tier and only one of the two places
got updated. `hygiene_history.band` mirrors `asset_hygiene_score.band`,
which IS already CHECK-constrained at its source (migration 0045); enforcing
the same vocabulary a second time on the history log would just be
duplicated validation of a value that's already guaranteed valid by the
time it's copied in. Same reasoning `asset_hygiene_score`'s own migration
used for not CHECK-constraining the grade strings inside its `dimensions`
JSONB — validate once, at the column that's the actual source of truth.

Indexes are declared on the partitioned PARENT table; Postgres
automatically propagates a matching index to every existing and future
partition (native partitioned-index support) — no per-partition index
creation needed here or in `partition_maintenance`.

`uuidv7()` is a core PostgreSQL 18 built-in (no extension required) — see
test_database_requirements.py, which asserts no extension beyond `plpgsql`
is installed.

`downgrade()` drops both tables outright; dropping a partitioned parent
drops all of its partitions (including the DEFAULT one) in one statement.

Revision ID: 0046
Revises: 0045
Create Date: 2026-08-22
"""

from alembic import op


revision = "0046"
down_revision = "0045"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── score_history (data — append-only, natively partitioned) ────────────
    op.execute("""
        CREATE TABLE score_history (
            id uuid NOT NULL DEFAULT uuidv7(),
            finding_canonical_id uuid NOT NULL,
            asset_canonical_id uuid NOT NULL,
            scored_at timestamptz NOT NULL,
            risk_score integer NOT NULL,
            risk_band text NOT NULL,
            building_velocity boolean NOT NULL,
            inputs jsonb NOT NULL DEFAULT '{}',
            PRIMARY KEY (scored_at, id),
            CONSTRAINT ck_score_history_risk_score_range CHECK (risk_score >= 0 AND risk_score <= 100)
        ) PARTITION BY RANGE (scored_at);
    """)

    # Seed current-month + next-month partitions, computed at migration-run
    # time so this doesn't drift into a hardcoded date — same idiom as
    # migration 0039's claim_history.
    op.execute("""
        DO $$
        DECLARE
            this_month date := date_trunc('month', now())::date;
            next_month date := (date_trunc('month', now()) + interval '1 month')::date;
            month_after date := (date_trunc('month', now()) + interval '2 month')::date;
        BEGIN
            EXECUTE format(
                'CREATE TABLE %I PARTITION OF score_history FOR VALUES FROM (%L) TO (%L)',
                'score_history_' || to_char(this_month, 'YYYY_MM'), this_month, next_month
            );
            EXECUTE format(
                'CREATE TABLE %I PARTITION OF score_history FOR VALUES FROM (%L) TO (%L)',
                'score_history_' || to_char(next_month, 'YYYY_MM'), next_month, month_after
            );
        END $$;
    """)
    op.execute("CREATE TABLE score_history_default PARTITION OF score_history DEFAULT;")
    op.execute(
        "CREATE INDEX ix_score_history_finding "
        "ON score_history (finding_canonical_id, scored_at DESC);"
    )

    # ── hygiene_history (data — append-only, natively partitioned) ──────────
    op.execute("""
        CREATE TABLE hygiene_history (
            id uuid NOT NULL DEFAULT uuidv7(),
            asset_canonical_id uuid NOT NULL,
            computed_at timestamptz NOT NULL,
            score integer NOT NULL,
            band text NOT NULL,
            dimensions jsonb NOT NULL DEFAULT '{}',
            PRIMARY KEY (computed_at, id),
            CONSTRAINT ck_hygiene_history_score_range CHECK (score >= 0 AND score <= 100)
        ) PARTITION BY RANGE (computed_at);
    """)

    op.execute("""
        DO $$
        DECLARE
            this_month date := date_trunc('month', now())::date;
            next_month date := (date_trunc('month', now()) + interval '1 month')::date;
            month_after date := (date_trunc('month', now()) + interval '2 month')::date;
        BEGIN
            EXECUTE format(
                'CREATE TABLE %I PARTITION OF hygiene_history FOR VALUES FROM (%L) TO (%L)',
                'hygiene_history_' || to_char(this_month, 'YYYY_MM'), this_month, next_month
            );
            EXECUTE format(
                'CREATE TABLE %I PARTITION OF hygiene_history FOR VALUES FROM (%L) TO (%L)',
                'hygiene_history_' || to_char(next_month, 'YYYY_MM'), next_month, month_after
            );
        END $$;
    """)
    op.execute("CREATE TABLE hygiene_history_default PARTITION OF hygiene_history DEFAULT;")
    op.execute(
        "CREATE INDEX ix_hygiene_history_asset "
        "ON hygiene_history (asset_canonical_id, computed_at DESC);"
    )


def downgrade() -> None:
    # Dropping a partitioned parent drops all of its partitions (including
    # the DEFAULT one) — no need to drop them individually.
    op.execute("DROP TABLE hygiene_history")
    op.execute("DROP TABLE score_history")
