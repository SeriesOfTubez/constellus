"""Enforces the documented database baseline: Constellus runs on stock
PostgreSQL and requires no extensions.

This is a real constraint, not a preference. Every managed PostgreSQL speaks
the same wire protocol and moves between providers with a dump and restore —
the one thing that does not move is extensions, which each provider allowlists
differently and sometimes at a different licence tier. A schema that quietly
starts depending on a non-core extension is locked to whichever providers ship
it, and nobody finds out until a deploy fails.

Constellus previously required TimescaleDB. Removing it is only durable if
something fails when it creeps back, so this test is that something. It runs
against the CI service container, which is deliberately stock `postgres` and
not the timescaledb image — a reintroduced `create_hypertable()` fails the
migration there rather than passing unnoticed.

Requires a live database (DATABASE_URL). Mirrors the integration-test style
already used by test_target_scope.py and friends.

See docs/getting-started/database-requirements.md.
"""

from sqlalchemy import text

from app.core.database import SessionLocal

# plpgsql ships enabled in every stock PostgreSQL template database. Anything
# else present means a migration installed it — which is the thing being
# prevented. Adding an entry here is a deliberate portability decision and
# must be reflected in the requirements doc, not a quick fix to unbreak CI.
ALLOWED_EXTENSIONS = {"plpgsql"}

# Floor from the requirements doc. Below this, features the schema relies on
# are not guaranteed to exist.
MINIMUM_MAJOR_VERSION = 14


def test_no_extensions_beyond_the_documented_baseline():
    db = SessionLocal()
    try:
        installed = {
            row[0] for row in db.execute(text("SELECT extname FROM pg_extension")).all()
        }
    finally:
        db.close()

    unexpected = installed - ALLOWED_EXTENSIONS
    assert not unexpected, (
        f"Schema installed non-core extension(s): {sorted(unexpected)}. "
        "Constellus must run on stock PostgreSQL — see "
        "docs/getting-started/database-requirements.md. If this is intentional, "
        "the portability cost has to be accepted explicitly and documented."
    )


def test_timescaledb_is_not_required():
    """Named separately from the general check so the failure message points at
    the specific regression this codebase actually had."""
    db = SessionLocal()
    try:
        present = db.execute(
            text("SELECT count(*) FROM pg_extension WHERE extname = 'timescaledb'")
        ).scalar()
    finally:
        db.close()

    assert present == 0, (
        "TimescaleDB is installed. It was removed in favour of native partitioning "
        "because compression and continuous aggregates are unavailable on every "
        "managed PostgreSQL anyway, and Cloud SQL / AlloyDB do not offer the "
        "extension at all. Do not reintroduce create_hypertable() or "
        "add_retention_policy()."
    )


def test_server_version_meets_the_documented_floor():
    db = SessionLocal()
    try:
        num = db.execute(text("SHOW server_version_num")).scalar()
    finally:
        db.close()

    major = int(num) // 10000
    assert major >= MINIMUM_MAJOR_VERSION, (
        f"PostgreSQL {major} is below the documented minimum of "
        f"{MINIMUM_MAJOR_VERSION}."
    )
