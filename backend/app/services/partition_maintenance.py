"""
Partitioned-table maintenance (L2 sub-slice D, planning#143; generalised to
multiple tables in planning#131, temporal layer slice 1).

Migration 0039 declared `claim_history` as a native RANGE-partitioned table
on `changed_at`, seeding only the current-month and next-month partitions
plus a DEFAULT catch-all (`claim_history_default`). Without ongoing
maintenance, every month after that lands in the DEFAULT partition —
correctness holds (the row still lands somewhere) but the whole point of
partitioning (pruning, sequential scans bounded to a month) degrades over
time. This job keeps one month of partition "runway" ahead of `now()` and,
where the table's config says so, drops partitions that have aged out of
their retention window.

This module originally maintained `claim_history` alone, as
`claim_history_maintenance.py`. Migration 0046 (planning#131) adds two more
natively partitioned tables — `score_history`, `hygiene_history` — that need
exactly the same ahead-of-time partition provisioning. Rather than duplicate
this whole module three times, it is renamed to `partition_maintenance.py`
and parameterised by table via the `PartitionedTable` config below. This is
a RENAME + PARAMETERISE, not a rewrite: the identifier-safety design
described below (psycopg2 `sql.Identifier`, the `_assert_partition_name`
barrier, discovery via `pg_inherits`) is unchanged from the original
`claim_history`-only version — only the table name now flows through as a
parameter instead of being hardcoded. `claim_history`'s existing behaviour
(24-month retention, drops enabled) is unchanged in effect by this refactor.

Retention and drop-eligibility are now PER TABLE (`PartitionedTable.
retention_months` / `.drop_expired`) rather than one module-wide constant —
`claim_history`'s 24-month audit horizon ("how far back can an investigator
reconstruct what an observer claimed and when") and `score_history`/
`hygiene_history`'s 6-month hot window (chosen to match `claim_history`'s
existing MONTHLY PARTITIONING CONVENTION, not its retention policy, so this
job stays one pattern rather than growing a second one) are unrelated
numbers that only ever shared a constant because there used to be only one
table.

`drop_expired=False` on `score_history` and `hygiene_history` is LOUD on
purpose, not a quiet default — see the `_TABLES` config below. Partition
DROP is disabled for those two tables until the archive summariser / roll-up
tier exists (planning#131, deliberately deferred out of this slice — the
reviewer will file a follow-up issue once the summariser's design is
settled): dropping a hot partition with nothing built yet to summarise its
rows into is outright data loss, not routine cleanup. `retention_months=6`
is still recorded on both tables now, so the intended hot window is
declared in exactly one place, ready for the summariser to read once it
lands — this module simply never ACTS on it by dropping anything for those
two tables today.

Concurrency: this mirrors the note on `_register_epss_refresher` in
scheduler.py — Constellus runs a single uvicorn worker with one in-process
APScheduler, so there is at most one caller of `run()` at a time. No
advisory lock is taken. A multi-worker deployment would need one (or a
shared job store) before this assumption holds.

Partition identification is defensive on purpose: this job never hardcodes
or guesses partition names for the table it's maintaining. Every partition
to inspect is discovered by querying `pg_inherits`/`pg_class` for the actual
children of that table, and `<table>_default` is recognized by name and
excluded from both the "already exists" and "drop if expired" logic — it
has no month to parse and must never be dropped.

DDL and identifier safety: CREATE/DROP TABLE take the partition name as an
IDENTIFIER, and Postgres does not accept bind parameters in that position —
so these two statements cannot be parameterized the way every other query in
this codebase is. They are issued through `psycopg2.sql.Identifier`, which
quotes and escapes the identifier in the driver, instead of formatting it
into a `text()` string. That makes them injection-safe by CONSTRUCTION
rather than by argument: it no longer depends on `_partition_name` only ever
emitting strftime digits, or on each table's own `_PARTITION_NAME_RE` having
been applied at the call site. `_assert_partition_name(table, name)`
re-checks the name against that table's own regex immediately before either
statement as a second, independent barrier, so a name that somehow reached
here from anywhere but this module's own naming convention for that table
raises instead of executing. The maintained TABLE name itself (as opposed to
the partition name) is never externally supplied — it only ever comes from
the fixed `_TABLES` tuple below, never from user input or a DB read — so it
does not need its own barrier the way a partition name discovered via
`pg_inherits` does.
"""

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from psycopg2 import sql
from sqlalchemy import text
from sqlalchemy.orm import Session

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class PartitionedTable:
    name: str
    retention_months: int
    drop_expired: bool


# The tables this job maintains. claim_history keeps its original 24-month,
# drop-enabled behaviour (planning#143). score_history/hygiene_history
# (planning#131, migration 0046) get the same monthly-partition convention
# and a 6-month hot window declared now, but drops disabled — see the
# module docstring's "drop_expired=False is loud" paragraph before ever
# flipping this to True for either.
_TABLES: tuple[PartitionedTable, ...] = (
    PartitionedTable("claim_history", 24, True),
    PartitionedTable("score_history", 6, False),
    PartitionedTable("hygiene_history", 6, False),
)


def _default_partition_name(table: str) -> str:
    return f"{table}_default"


def _partition_name_re(table: str) -> re.Pattern:
    return re.compile(rf"^{re.escape(table)}_(\d{{4}})_(\d{{2}})$")


# ── Public API ────────────────────────────────────────────────────────────────

def run(db: Session) -> dict:
    """Maintain every table in `_TABLES`: ensure the current + next month's
    partitions exist, and — only where `drop_expired=True` — drop
    partitions that have aged out of that table's retention window.

    Returns `{"<table>": {"created": [...names...], "dropped": [...names...],
    "retained": <int>}, ...}` for every table in `_TABLES`, and logs one
    summary line per table (never per-partition).

    `retained` is simply how many partitions the table has left, counted
    AFTER `_apply_retention` has already committed its drops — including
    `<table>_default`. It is deliberately NOT `len(existing) - len(dropped)`:
    that was the arithmetic here until planning#131 and it undercounted by
    exactly `len(dropped)` on any run that dropped anything, because the
    dropped partitions are already absent from the post-drop query it was
    subtracting them from. Stats/log only — nothing ever branched on the
    value — but it made the one log line that reports this job's effect
    wrong precisely on the runs where the job did something. Covered by
    `test_retained_counts_partitions_actually_remaining`.
    """
    now = datetime.now(timezone.utc)
    stats: dict[str, dict] = {}
    for table in _TABLES:
        created = _ensure_ahead(db, table, now)
        dropped = _apply_retention(db, table, now) if table.drop_expired else []
        existing = _existing_partitions(db, table.name)
        table_stats = {
            "created": created,
            "dropped": dropped,
            "retained": len(existing),
        }
        stats[table.name] = table_stats
        log.info(
            "%s maintenance: created=%s dropped=%s retained=%d",
            table.name, created, dropped, table_stats["retained"],
        )
    return stats


# ── Internal ──────────────────────────────────────────────────────────────────

def _month_start(dt: datetime) -> datetime:
    """First-of-month, midnight UTC, tz-aware — matches how the partition
    bounds were computed in migration 0039 / 0046."""
    return dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _add_months(dt: datetime, months: int) -> datetime:
    total = dt.year * 12 + (dt.month - 1) + months
    year, month = divmod(total, 12)
    return dt.replace(year=year, month=month + 1)


def _partition_name(table: str, month_start: datetime) -> str:
    return f"{table}_{month_start.strftime('%Y_%m')}"


def _assert_partition_name(table: str, name: str) -> str:
    """Barrier for the two statements that interpolate an identifier.

    Everything reaching CREATE/DROP below must match `table`'s own
    `<table>_YYYY_MM` convention. Independent of where the name came from —
    `_partition_name`'s strftime, or a relname read out of pg_class — so
    neither of those has to be trusted on its own.
    """
    if not _partition_name_re(table).match(name):
        raise ValueError(f"refusing to run DDL against non-partition identifier {name!r} (table={table!r})")
    return name


def _execute_ddl(db: Session, statement: sql.Composable, params: tuple = ()) -> None:
    """Run one DDL statement carrying a psycopg2-quoted identifier.

    Postgres won't bind-parameter an identifier, so partition DDL has to
    interpolate the table name. Going through psycopg2's own
    `sql.Identifier` composition (rather than an f-string into `text()`)
    puts the quoting/escaping in the driver. Uses the session's existing
    DBAPI connection, so this stays inside the caller's transaction and the
    caller's `db.commit()` still applies.
    """
    cursor = db.connection().connection.cursor()
    try:
        cursor.execute(statement, params)
    finally:
        cursor.close()


def _existing_partitions(db: Session, table: str) -> set[str]:
    """Children of `table`, discovered via pg_inherits/pg_class — never
    guessed or hardcoded. `table` is parameterized as a bind value here
    (a data comparison, not a DDL identifier), so this query itself needs
    no `sql.Identifier` handling."""
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


def _ensure_partition_exists(db: Session, table: str, month_start: datetime, existing: set[str]) -> str | None:
    """Create the partition for the month starting at `month_start` if it's
    not already among `existing`. Returns the partition name if created,
    else None. Idempotent: uses CREATE TABLE IF NOT EXISTS."""
    name = _partition_name(table, month_start)
    if name in existing:
        return None
    next_month = _add_months(month_start, 1)
    _execute_ddl(
        db,
        sql.SQL(
            "CREATE TABLE IF NOT EXISTS {} "
            "PARTITION OF {} FOR VALUES FROM (%s) TO (%s)"
        ).format(sql.Identifier(_assert_partition_name(table, name)), sql.Identifier(table)),
        (month_start, next_month),
    )
    db.commit()
    log.info("%s: created partition %s", table, name)
    return name


def _ensure_ahead(db: Session, table: PartitionedTable, now: datetime) -> list[str]:
    """Ensure the current month and next month both have partitions for
    `table`."""
    existing = _existing_partitions(db, table.name)
    created: list[str] = []

    this_month = _month_start(now)
    created_name = _ensure_partition_exists(db, table.name, this_month, existing)
    if created_name:
        created.append(created_name)
        existing.add(created_name)

    next_month = _add_months(this_month, 1)
    created_name = _ensure_partition_exists(db, table.name, next_month, existing)
    if created_name:
        created.append(created_name)
        existing.add(created_name)

    return created


def _apply_retention(db: Session, table: PartitionedTable, now: datetime) -> list[str]:
    """Drop every dated partition of `table` whose month is older than that
    table's retention cutoff. Only called when `table.drop_expired` is True
    (see `run()`). `<table>_default` is never touched — it doesn't match
    the `<table>_YYYY_MM` name pattern in the first place."""
    cutoff = _add_months(_month_start(now), -table.retention_months)
    dropped: list[str] = []
    default_name = _default_partition_name(table.name)
    name_re = _partition_name_re(table.name)

    for name in sorted(_existing_partitions(db, table.name)):
        if name == default_name:
            continue
        match = name_re.match(name)
        if not match:
            # Unexpected partition name (e.g. hand-created outside this
            # job's naming convention) — leave it alone rather than guess.
            log.warning("%s: skipping unrecognized partition %s during retention", table.name, name)
            continue
        year, month = int(match.group(1)), int(match.group(2))
        partition_month = now.replace(year=year, month=month, day=1, hour=0, minute=0, second=0, microsecond=0)
        if partition_month < cutoff:
            _execute_ddl(
                db,
                sql.SQL("DROP TABLE {}").format(sql.Identifier(_assert_partition_name(table.name, name))),
            )
            db.commit()
            dropped.append(name)
            log.info("%s: dropped expired partition %s (cutoff=%s)", table.name, name, cutoff.date())

    return dropped
