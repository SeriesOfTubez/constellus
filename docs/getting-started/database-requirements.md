# Database Requirements

Constellus stores everything in a single PostgreSQL database. There is no second
datastore — no Redis, no document store, no separate time-series engine.

## Requirements

| Requirement | Value |
|---|---|
| Engine | PostgreSQL |
| Minimum version | 14 |
| Recommended version | 18 |
| Required extensions | **None** |
| Character encoding | UTF-8 |
| Timezone handling | All timestamps are `TIMESTAMP WITH TIME ZONE`, stored UTC |

Any PostgreSQL that meets the above will run Constellus — a container, a VM, or a
managed service from any provider. The reference deployment in `docker-compose.yml`
uses the stock `postgres:18` image.

PostgreSQL has no long-term-support release. Every major version receives five
years of support from its initial release, then a final minor and end-of-life, so
"newer" carries no extra risk beyond ordinary maturity — 18 simply has a longer
remaining runway than 17.

### Upgrading to 18 in Docker

From version 18 the official images store data in major-version-specific
subdirectories (`/var/lib/postgresql/18/docker`) so `pg_upgrade --link` works
without crossing a mount boundary. Mount the volume at **`/var/lib/postgresql`**,
not `/var/lib/postgresql/data`. An existing 17-or-earlier volume mounted at the old
path will make the container refuse to start rather than silently orphan the data.

## No extensions required

This is a deliberate constraint, not an accident of the current schema.

Every managed PostgreSQL speaks the same wire protocol and moves between providers
with a dump and restore. The one thing that does *not* move is extensions: providers
each allowlist a different set, sometimes at a different licence tier. A schema that
depends on a non-core extension is silently locked to whichever providers happen to
ship it.

So the rule is: **nothing load-bearing may depend on a non-core extension.**

Constellus previously required TimescaleDB. Three tables were hypertables and one
retention policy used `add_retention_policy`. That dependency has been removed:

- Hypertables are now plain or natively partitioned tables.
- Retention is enforced by scheduled jobs in the application, not by database policies.

The features that would have justified keeping TimescaleDB at scale — columnar
compression and continuous aggregates — are unavailable on managed PostgreSQL
anyway. Google Cloud SQL and AlloyDB do not offer TimescaleDB at all, and Azure
Database for PostgreSQL Flexible Server ships the Apache-2 edition, which excludes
both by licence.

### Optional extensions

Some extensions are used as optimisations when present, always behind a working
fallback. Constellus must run correctly without them:

| Extension | Used for | Fallback |
|---|---|---|
| `pg_partman` | Partition lifecycle on history tables | Built-in partition helper |
| `pg_cron` | In-database scheduled maintenance | APScheduler jobs |
| `pg_ivm` | Incrementally maintained roll-up views | Scheduled refresh job |
| `vector` | Similarity search for AI-assisted features | Feature degrades, does not fail |

Never promote one of these to a hard requirement without changing this document
and accepting the portability cost.

### How this is enforced

A statement in a document is not a guarantee, so two things enforce it:

- CI runs the backend test suite against a **stock `postgres` service container**,
  not one carrying extra extensions. Anything the schema needs but stock PostgreSQL
  lacks fails the migration step.
- `backend/app/tests/test_database_requirements.py` asserts that `pg_extension`
  contains nothing beyond `plpgsql`, that TimescaleDB specifically is absent, and
  that the server meets the version floor.

Widening `ALLOWED_EXTENSIONS` in that test is a deliberate portability decision, not
a way to unbreak a build.

## Sizing

Volumes are modest for the workload. At roughly 500,000 assets with ten claim
sources:

- Current-state tables are bounded — a few gigabytes, updated in place rather than
  appended to.
- History tables are written **only when a value actually changes**, which is the
  main scale lever. Most assets do not change day to day, so expect low hundreds of
  thousands of rows per day rather than millions.
- Full-fidelity history is kept for a configurable hot window, then summarised into
  archive snapshots. Durable facts (an asset's first-seen date, an acquisition date)
  live on the entity rather than in history, so retention never removes them.

A general-purpose managed instance is sufficient. Storage grows predictably; CPU is
driven by scan orchestration rather than query load.

## Connection handling

The backend, the scheduler, and each scan engine hold connections. Use a pooler —
either the provider's built-in one or PgBouncer — rather than raising `max_connections`.
Constellus uses SQLAlchemy's own pool per process, so the pooler should run in
session or transaction mode, not statement mode.

## Backups

Standard PostgreSQL practice applies; Constellus adds no special requirements. Note
that scan data is reproducible by rescanning, but the following are not, and are the
reason to keep backups:

- Targets, their verification tokens and verification state
- Connector configuration and credentials
- Users, roles and SSO configuration
- Audit logs
- Analyst decisions: acknowledgements, suppressions, and verification verdicts
