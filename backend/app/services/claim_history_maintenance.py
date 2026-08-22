"""
claim_history partition maintenance (L2 sub-slice D, planning#143).

Migration 0039 declared `claim_history` as a native RANGE-partitioned table
on `changed_at`, seeding only the current-month and next-month partitions
plus a DEFAULT catch-all (`claim_history_default`). Without ongoing
maintenance, every month after that lands in the DEFAULT partition —
correctness holds (the row still lands somewhere) but the whole point of
partitioning (pruning, sequential scans bounded to a month) degrades over
time. This job keeps one month of partition "runway" ahead of `now()` and
drops partitions that have aged out of the retention window.

RETENTION_MONTHS = 24 is the "why did we probe that IP" audit horizon: how
far back an investigator can expect to reconstruct what an observer claimed
about an asset and when. It's a tunable operational constant, not a
compliance-driven number — adjust it here if the audit requirement changes.

Concurrency: this mirrors the note on `_register_epss_refresher` in
scheduler.py — Constellus runs a single uvicorn worker with one in-process
APScheduler, so there is at most one caller of `run()` at a time. No
advisory lock is taken. A multi-worker deployment would need one (or a
shared job store) before this assumption holds.

Partition identification is defensive on purpose: we never hardcode or
guess partition names. Every partition to inspect is discovered by querying
`pg_inherits`/`pg_class` for the actual children of `claim_history`, and
`claim_history_default` is recognized by name and excluded from both the
"already exists" and "drop if expired" logic — it has no month to parse and
must never be dropped.

DDL and identifier safety: CREATE/DROP TABLE take the partition name as an
IDENTIFIER, and Postgres does not accept bind parameters in that position —
so these two statements cannot be parameterized the way every other query in
this codebase is. They are issued through `psycopg2.sql.Identifier`, which
quotes and escapes the identifier in the driver, instead of formatting it
into a `text()` string. That makes them injection-safe by CONSTRUCTION
rather than by argument: it no longer depends on `_partition_name` only ever
emitting strftime digits, or on `_PARTITION_NAME_RE` having been applied at
the call site. `_assert_partition_name` re-checks the name against that
regex immediately before either statement as a second, independent barrier,
so a name that somehow reached here from anywhere but this module's own
naming convention raises instead of executing.
"""

import logging
import re
from datetime import datetime, timezone

from psycopg2 import sql
from sqlalchemy import text
from sqlalchemy.orm import Session

log = logging.getLogger(__name__)

RETENTION_MONTHS = 24

_DEFAULT_PARTITION_NAME = "claim_history_default"
_PARTITION_NAME_RE = re.compile(r"^claim_history_(\d{4})_(\d{2})$")


# ── Public API ────────────────────────────────────────────────────────────────

def run(db: Session) -> dict:
    """Ensure upcoming partitions exist and drop partitions past retention.

    Returns a small stats dict suitable for logging:
      {"created": [...names...], "dropped": [...names...], "retained": <int>}
    """
    now = datetime.now(timezone.utc)
    created = _ensure_ahead(db, now)
    dropped = _apply_retention(db, now)
    existing = _existing_partitions(db)
    stats = {
        "created": created,
        "dropped": dropped,
        "retained": len(existing) - len(dropped),
    }
    log.info(
        "claim_history maintenance: created=%s dropped=%s retained=%d",
        created, dropped, stats["retained"],
    )
    return stats


# ── Internal ──────────────────────────────────────────────────────────────────

def _month_start(dt: datetime) -> datetime:
    """First-of-month, midnight UTC, tz-aware — matches how the partition
    bounds were computed in migration 0039."""
    return dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _add_months(dt: datetime, months: int) -> datetime:
    total = dt.year * 12 + (dt.month - 1) + months
    year, month = divmod(total, 12)
    return dt.replace(year=year, month=month + 1)


def _partition_name(month_start: datetime) -> str:
    return f"claim_history_{month_start.strftime('%Y_%m')}"


def _assert_partition_name(name: str) -> str:
    """Barrier for the two statements that interpolate an identifier.

    Everything reaching CREATE/DROP below must match this module's own
    `claim_history_YYYY_MM` convention. Independent of where the name came
    from — `_partition_name`'s strftime, or a relname read out of pg_class —
    so neither of those has to be trusted on its own.
    """
    if not _PARTITION_NAME_RE.match(name):
        raise ValueError(f"refusing to run DDL against non-partition identifier {name!r}")
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


def _existing_partitions(db: Session) -> set[str]:
    """Children of claim_history, discovered via pg_inherits/pg_class —
    never guessed or hardcoded."""
    rows = db.execute(text(
        "SELECT child.relname "
        "FROM pg_inherits i "
        "JOIN pg_class parent ON parent.oid = i.inhparent "
        "JOIN pg_class child ON child.oid = i.inhrelid "
        "WHERE parent.relname = 'claim_history'"
    )).scalars().all()
    return set(rows)


def _ensure_partition_exists(db: Session, month_start: datetime, existing: set[str]) -> str | None:
    """Create the partition for the month starting at `month_start` if it's
    not already among `existing`. Returns the partition name if created,
    else None. Idempotent: uses CREATE TABLE IF NOT EXISTS."""
    name = _partition_name(month_start)
    if name in existing:
        return None
    next_month = _add_months(month_start, 1)
    _execute_ddl(
        db,
        sql.SQL(
            "CREATE TABLE IF NOT EXISTS {} "
            "PARTITION OF claim_history FOR VALUES FROM (%s) TO (%s)"
        ).format(sql.Identifier(_assert_partition_name(name))),
        (month_start, next_month),
    )
    db.commit()
    log.info("claim_history: created partition %s", name)
    return name


def _ensure_ahead(db: Session, now: datetime) -> list[str]:
    """Ensure the current month and next month both have partitions."""
    existing = _existing_partitions(db)
    created: list[str] = []

    this_month = _month_start(now)
    created_name = _ensure_partition_exists(db, this_month, existing)
    if created_name:
        created.append(created_name)
        existing.add(created_name)

    next_month = _add_months(this_month, 1)
    created_name = _ensure_partition_exists(db, next_month, existing)
    if created_name:
        created.append(created_name)
        existing.add(created_name)

    return created


def _apply_retention(db: Session, now: datetime) -> list[str]:
    """Drop every dated partition whose month is older than the retention
    cutoff. claim_history_default is never touched — it doesn't match the
    YYYY_MM name pattern in the first place."""
    cutoff = _add_months(_month_start(now), -RETENTION_MONTHS)
    dropped: list[str] = []

    for name in sorted(_existing_partitions(db)):
        if name == _DEFAULT_PARTITION_NAME:
            continue
        match = _PARTITION_NAME_RE.match(name)
        if not match:
            # Unexpected partition name (e.g. hand-created outside this
            # job's naming convention) — leave it alone rather than guess.
            log.warning("claim_history: skipping unrecognized partition %s during retention", name)
            continue
        year, month = int(match.group(1)), int(match.group(2))
        partition_month = now.replace(year=year, month=month, day=1, hour=0, minute=0, second=0, microsecond=0)
        if partition_month < cutoff:
            _execute_ddl(
                db,
                sql.SQL("DROP TABLE {}").format(sql.Identifier(_assert_partition_name(name))),
            )
            db.commit()
            dropped.append(name)
            log.info("claim_history: dropped expired partition %s (cutoff=%s)", name, cutoff.date())

    return dropped
