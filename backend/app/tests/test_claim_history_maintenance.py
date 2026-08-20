"""Tests for the claim_history partition-maintenance job (L2 sub-slice D,
planning#143).

Migration 0039 seeds only the current-month + next-month partitions plus
claim_history_default. claim_history_maintenance.run() is the ongoing
scheduler job that (a) keeps a next-month partition provisioned ahead of
`now()`, idempotently, and (b) drops partitions older than the 24-month
retention horizon, never touching claim_history_default.

Requires a live DB connection with migration 0039 applied — same style as
test_claims_schema.py / test_database_requirements.py.

Run with:  python -m app.tests.test_claim_history_maintenance
       or: pytest app/tests/test_claim_history_maintenance.py
"""

from datetime import datetime, timezone

from sqlalchemy import text

from app.core.database import SessionLocal
from app.services import claim_history_maintenance
from app.services.claim_history_maintenance import (
    RETENTION_MONTHS,
    _add_months,
    _month_start,
    _partition_name,
)


def _existing_partitions(db) -> set[str]:
    rows = db.execute(text(
        "SELECT child.relname "
        "FROM pg_inherits i "
        "JOIN pg_class parent ON parent.oid = i.inhparent "
        "JOIN pg_class child ON child.oid = i.inhrelid "
        "WHERE parent.relname = 'claim_history'"
    )).scalars().all()
    return set(rows)


def _create_partition_for_months_ago(db, months_ago: int) -> str:
    """Manually create a claim_history partition for a month in the past,
    bypassing the maintenance job — simulates an old partition that should
    (or should not) be swept by retention."""
    now = datetime.now(timezone.utc)
    month_start = _add_months(_month_start(now), -months_ago)
    next_month = _add_months(month_start, 1)
    name = _partition_name(month_start)
    db.execute(text(
        f"CREATE TABLE IF NOT EXISTS {name} "
        "PARTITION OF claim_history FOR VALUES FROM (:from_bound) TO (:to_bound)"
    ), {"from_bound": month_start, "to_bound": next_month})
    db.commit()
    return name


def _drop_partition_if_exists(db, name: str) -> None:
    db.rollback()
    db.execute(text(f"DROP TABLE IF EXISTS {name}"))
    db.commit()


def test_run_creates_next_month_partition():
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        next_month_name = _partition_name(_add_months(_month_start(now), 1))

        claim_history_maintenance.run(db)

        existing = _existing_partitions(db)
        assert next_month_name in existing, (
            f"expected {next_month_name} to exist after run(), got {sorted(existing)}"
        )
    finally:
        db.close()


def test_run_creates_current_month_partition_too():
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        this_month_name = _partition_name(_month_start(now))

        claim_history_maintenance.run(db)

        existing = _existing_partitions(db)
        assert this_month_name in existing
    finally:
        db.close()


def test_run_is_idempotent():
    db = SessionLocal()
    try:
        claim_history_maintenance.run(db)
        before = _existing_partitions(db)

        # Second call must not error and must not duplicate/change anything.
        claim_history_maintenance.run(db)
        after = _existing_partitions(db)

        assert before == after, f"idempotent run() changed partition set: {before} -> {after}"
    finally:
        db.close()


def test_retention_drops_partition_older_than_cutoff():
    db = SessionLocal()
    old_name = None
    try:
        old_name = _create_partition_for_months_ago(db, RETENTION_MONTHS + 6)
        assert old_name in _existing_partitions(db), "setup failed: old partition wasn't created"

        claim_history_maintenance.run(db)

        existing = _existing_partitions(db)
        assert old_name not in existing, f"{old_name} should have been dropped by retention, still present"
    finally:
        _drop_partition_if_exists(db, old_name) if old_name else None
        db.close()


def test_retention_keeps_recent_partition_and_default():
    db = SessionLocal()
    recent_name = None
    try:
        # Well inside the retention window (a few months back).
        recent_name = _create_partition_for_months_ago(db, 3)

        claim_history_maintenance.run(db)

        existing = _existing_partitions(db)
        assert recent_name in existing, f"{recent_name} is inside retention and must survive"
        assert "claim_history_default" in existing, "claim_history_default must never be dropped"
    finally:
        db.close()


def test_retention_boundary_is_first_of_month_24_months_back():
    """Sanity-check the cutoff math independent of the DB: a partition dated
    exactly RETENTION_MONTHS ago is at the boundary and should NOT survive
    once one more month passes (i.e. the cutoff excludes it going forward),
    while RETENTION_MONTHS - 1 months ago must survive."""
    now = datetime.now(timezone.utc)
    cutoff = _add_months(_month_start(now), -RETENTION_MONTHS)

    just_outside = _add_months(_month_start(now), -(RETENTION_MONTHS + 1))
    just_inside = _add_months(_month_start(now), -(RETENTION_MONTHS - 1))

    assert just_outside < cutoff
    assert just_inside >= cutoff


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
