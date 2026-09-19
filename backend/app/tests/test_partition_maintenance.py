"""Tests for the partitioned-table maintenance job (originally L2
sub-slice D, planning#143, `claim_history`-only; generalised to
`score_history`/`hygiene_history` in planning#131, temporal layer slice 1).

Renamed from `test_claim_history_maintenance.py` alongside the service
module's own rename (`claim_history_maintenance.py` ->
`partition_maintenance.py`) — every original assertion's intent is kept,
just parameterised by `table` the same way the service itself now is.
New tests below cover the actual point of the generalisation: that
`score_history`/`hygiene_history` get next-month partitions provisioned
exactly like `claim_history` always has, and that their `drop_expired=
False` config is genuinely honoured — an aged partition on either of them
must survive a `run()` call that, in the SAME call, still drops
`claim_history`'s aged partition.

Requires a live DB connection with migrations 0039 and 0046 applied — same
style as test_claims_schema.py / test_database_requirements.py.

Run with:  python -m app.tests.test_partition_maintenance
       or: pytest app/tests/test_partition_maintenance.py
"""

from datetime import datetime, timezone

from sqlalchemy import text

from app.core.database import SessionLocal
from app.services import partition_maintenance
from app.services.partition_maintenance import (
    _TABLES,
    _add_months,
    _assert_partition_name,
    _month_start,
    _partition_name,
)

_RETENTION_BY_TABLE = {t.name: t.retention_months for t in _TABLES}
_DROP_EXPIRED_BY_TABLE = {t.name: t.drop_expired for t in _TABLES}


def _existing_partitions(db, table: str) -> set[str]:
    rows = db.execute(
        text(
            "SELECT child.relname "
            "FROM pg_inherits i "
            "JOIN pg_class parent ON parent.oid = i.inhparent "
            "JOIN pg_class child ON child.oid = i.inhrelid "
            "WHERE parent.relname = :table"
        ),
        {"table": table},
    ).scalars().all()
    return set(rows)


def _create_partition_for_months_ago(db, table: str, months_ago: int) -> str:
    """Manually create a partition for `table` dated a month in the past,
    bypassing the maintenance job — simulates an old partition that should
    (or should not, depending on drop_expired) be swept by retention."""
    now = datetime.now(timezone.utc)
    month_start = _add_months(_month_start(now), -months_ago)
    next_month = _add_months(month_start, 1)
    name = _partition_name(table, month_start)
    db.execute(
        text(
            f"CREATE TABLE IF NOT EXISTS {name} "
            f"PARTITION OF {table} FOR VALUES FROM (:from_bound) TO (:to_bound)"
        ),
        {"from_bound": month_start, "to_bound": next_month},
    )
    db.commit()
    return name


def _drop_partition_if_exists(db, name: str) -> None:
    db.rollback()
    db.execute(text(f"DROP TABLE IF EXISTS {name}"))
    db.commit()


# ── claim_history: unchanged behaviour ──────────────────────────────────────

def test_run_creates_next_month_partition_for_claim_history():
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        next_month_name = _partition_name("claim_history", _add_months(_month_start(now), 1))

        partition_maintenance.run(db)

        existing = _existing_partitions(db, "claim_history")
        assert next_month_name in existing, (
            f"expected {next_month_name} to exist after run(), got {sorted(existing)}"
        )
    finally:
        db.close()


def test_run_creates_current_month_partition_too_for_claim_history():
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        this_month_name = _partition_name("claim_history", _month_start(now))

        partition_maintenance.run(db)

        existing = _existing_partitions(db, "claim_history")
        assert this_month_name in existing
    finally:
        db.close()


def test_run_is_idempotent():
    db = SessionLocal()
    try:
        partition_maintenance.run(db)
        before = {t.name: _existing_partitions(db, t.name) for t in _TABLES}

        # Second call must not error and must not duplicate/change anything
        # for ANY of the three maintained tables.
        partition_maintenance.run(db)
        after = {t.name: _existing_partitions(db, t.name) for t in _TABLES}

        assert before == after, f"idempotent run() changed partition set: {before} -> {after}"
    finally:
        db.close()


def test_retention_drops_claim_history_partition_older_than_cutoff():
    db = SessionLocal()
    old_name = None
    try:
        old_name = _create_partition_for_months_ago(db, "claim_history", _RETENTION_BY_TABLE["claim_history"] + 6)
        assert old_name in _existing_partitions(db, "claim_history"), "setup failed: old partition wasn't created"

        partition_maintenance.run(db)

        existing = _existing_partitions(db, "claim_history")
        assert old_name not in existing, f"{old_name} should have been dropped by retention, still present"
    finally:
        _drop_partition_if_exists(db, old_name) if old_name else None
        db.close()


def test_retention_keeps_recent_claim_history_partition_and_default():
    db = SessionLocal()
    recent_name = None
    try:
        # Well inside the retention window (a few months back).
        recent_name = _create_partition_for_months_ago(db, "claim_history", 3)

        partition_maintenance.run(db)

        existing = _existing_partitions(db, "claim_history")
        assert recent_name in existing, f"{recent_name} is inside retention and must survive"
        assert "claim_history_default" in existing, "claim_history_default must never be dropped"
    finally:
        db.close()


def test_retention_boundary_is_first_of_month_24_months_back():
    """Sanity-check the cutoff math independent of the DB: a partition dated
    exactly claim_history's retention window ago is at the boundary and
    should NOT survive once one more month passes (i.e. the cutoff excludes
    it going forward), while one month less must survive."""
    retention = _RETENTION_BY_TABLE["claim_history"]
    now = datetime.now(timezone.utc)
    cutoff = _add_months(_month_start(now), -retention)

    just_outside = _add_months(_month_start(now), -(retention + 1))
    just_inside = _add_months(_month_start(now), -(retention - 1))

    assert just_outside < cutoff
    assert just_inside >= cutoff


# ── score_history / hygiene_history: the planning#131 generalisation ───────

def test_run_creates_next_and_current_month_partitions_for_score_and_hygiene_history():
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        expected = {
            table: {
                _partition_name(table, _month_start(now)),
                _partition_name(table, _add_months(_month_start(now), 1)),
            }
            for table in ("score_history", "hygiene_history")
        }

        partition_maintenance.run(db)

        for table, names in expected.items():
            existing = _existing_partitions(db, table)
            assert names <= existing, (
                f"expected {names} to exist for {table} after run(), got {sorted(existing)}"
            )
    finally:
        db.close()


def test_drop_expired_is_false_for_score_and_hygiene_history():
    assert _DROP_EXPIRED_BY_TABLE["score_history"] is False
    assert _DROP_EXPIRED_BY_TABLE["hygiene_history"] is False
    assert _DROP_EXPIRED_BY_TABLE["claim_history"] is True


def test_aged_partition_not_dropped_for_score_and_hygiene_history_but_is_for_claim_history():
    """The core generalisation assertion, proven within a SINGLE run() call
    so this isn't "two features that happen to both work in isolation" —
    claim_history's aged partition is dropped, score_history's and
    hygiene_history's aged partitions (each equally past their own 6-month
    retention window) survive, all from the same maintenance pass."""
    db = SessionLocal()
    old_names: dict[str, str] = {}
    try:
        for table in ("claim_history", "score_history", "hygiene_history"):
            retention = _RETENTION_BY_TABLE[table]
            old_names[table] = _create_partition_for_months_ago(db, table, retention + 6)
            assert old_names[table] in _existing_partitions(db, table), f"setup failed for {table}"

        partition_maintenance.run(db)

        assert old_names["claim_history"] not in _existing_partitions(db, "claim_history"), (
            "claim_history must still drop expired partitions (drop_expired=True)"
        )
        assert old_names["score_history"] in _existing_partitions(db, "score_history"), (
            "score_history must NOT drop expired partitions (drop_expired=False)"
        )
        assert old_names["hygiene_history"] in _existing_partitions(db, "hygiene_history"), (
            "hygiene_history must NOT drop expired partitions (drop_expired=False)"
        )
    finally:
        for name in old_names.values():
            _drop_partition_if_exists(db, name)
        db.close()


# ── identifier safety ────────────────────────────────────────────────────────

def test_assert_partition_name_accepts_this_modules_own_names():
    """The generated name for any month must pass its own barrier —
    otherwise maintenance would refuse to run at some future date. Checked
    for every maintained table, not just claim_history."""
    now = datetime.now(timezone.utc)
    for table in _RETENTION_BY_TABLE:
        for months in (-36, -1, 0, 1, 13):
            name = _partition_name(table, _add_months(_month_start(now), months))
            assert _assert_partition_name(table, name) == name, (table, name)


def test_assert_partition_name_rejects_non_partition_identifiers():
    """CREATE/DROP TABLE take the partition name as an IDENTIFIER, which
    Postgres will not bind-parameter, so it is composed via
    psycopg2.sql.Identifier. This barrier is the second, independent check
    that nothing but this module's own naming convention for THAT table
    ever reaches that composition — including the DEFAULT partition, which
    must never be dropped, and another maintained table's own valid name,
    which must never be accepted for a DIFFERENT table's barrier.
    """
    hostile = [
        "claim_history_default",            # real, but must never be dropped
        "claim_history",                     # the parent table itself
        "assets_canonical",                  # an unrelated table
        "claim_history_2026_08; DROP TABLE assets_canonical",
        'claim_history_2026_08" ; DROP TABLE assets_canonical --',
        "claim_history_26_08",               # wrong year width
        "claim_history_2026_8",              # wrong month width
        "claim_history_2026_08_extra",
        "score_history_2026_08",             # valid for a DIFFERENT table
        "",
    ]
    for name in hostile:
        try:
            _assert_partition_name("claim_history", name)
        except ValueError:
            continue
        raise AssertionError(f"barrier accepted a non-partition identifier: {name!r}")


def test_retained_counts_partitions_actually_remaining():
    """`retained` must equal the number of partitions the table actually has
    left after the run — including `<table>_default`.

    Regression test for arithmetic that predates planning#131 and survived
    the rename: `retained` was `len(existing) - len(dropped)` where
    `existing` is queried AFTER the drops commit, so the dropped partitions
    were subtracted from a set they were already absent from and every run
    that dropped anything undercounted by exactly `len(dropped)`. The bug
    was invisible precisely because no test asserted on this field, and it
    only misreported on the runs where the job actually did something —
    hence the aged partition created below, so this run has a real drop to
    get wrong.
    """
    db = SessionLocal()
    aged = _create_partition_for_months_ago(
        db, "claim_history", _RETENTION_BY_TABLE["claim_history"] + 6
    )
    try:
        stats = partition_maintenance.run(db)

        assert aged in stats["claim_history"]["dropped"], (
            "test precondition: this run must actually drop something for the "
            "count to be able to go wrong"
        )
        for table in _RETENTION_BY_TABLE:
            actual = len(_existing_partitions(db, table))
            assert stats[table]["retained"] == actual, (
                f"{table}: retained={stats[table]['retained']} but {actual} "
                f"partitions actually remain"
            )
    finally:
        _drop_partition_if_exists(db, aged)
        db.close()


def test_retention_never_drops_the_default_partition():
    """<table>_default has no month to parse and holds anything outside the
    seeded range — sweeping it would silently discard rows. Checked for
    every maintained table."""
    db = SessionLocal()
    try:
        partition_maintenance.run(db)
        for table in _RETENTION_BY_TABLE:
            assert f"{table}_default" in _existing_partitions(db, table)
    finally:
        db.close()


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
