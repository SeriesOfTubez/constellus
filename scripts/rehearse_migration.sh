#!/usr/bin/env bash
# Rehearse a branch's migration on a COPY of the dev data: pg_dump dev into a
# throwaway database, then upgrade -> downgrade -> upgrade with the
# worktree's alembic, running an optional check query after each step. The
# copy is always dropped on exit. Dev itself is only read (pg_dump).
#
#     scripts/rehearse_migration.sh ../constellus-wt240 0067 check.sql
#
#   <worktree>       the branch checkout whose alembic/versions to run
#   <down-revision>  what to downgrade to (the revision before yours)
#   [check.sql]      optional; its output is printed after every step. Keep it
#                    to COUNTS and shapes — the copy holds real data, and this
#                    output lands in a transcript.
#
# The copy's name ends in `_test`, and it is NOT constellus_test, so a
# concurrent test.sh run is not clobbered.
set -euo pipefail

if [ $# -lt 2 ] || [ $# -gt 3 ]; then
    echo "usage: $0 <worktree> <down-revision> [check.sql]" >&2
    exit 2
fi
WT="$(cd "$1" && pwd)"
DOWN="$2"
CHECK="${3:-}"

DB=constellus_rehearse_test
PGUSER="${CONSTELLUS_DB_USER:-constellus}"
PGPASS="${CONSTELLUS_DB_PASSWORD:-constellus}"
PGHOST="${CONSTELLUS_DB_HOST:-localhost}"
PGPORT="${CONSTELLUS_DB_PORT:-5432}"
export MSYS_NO_PATHCONV=1

psql_in() { docker exec -i constellus-db-1 psql -U "$PGUSER" "$@"; }

cleanup() { psql_in -d postgres -qc "DROP DATABASE IF EXISTS $DB WITH (FORCE);" >/dev/null 2>&1 || true; }
trap cleanup EXIT

check() {
    echo "-- $1: revision $(psql_in -d "$DB" -Atc 'select version_num from alembic_version')"
    if [ -n "$CHECK" ]; then
        psql_in -d "$DB" -At < "$CHECK"
    fi
}

cleanup
psql_in -d postgres -qc "CREATE DATABASE $DB;"
docker exec constellus-db-1 sh -c "pg_dump -U $PGUSER -d constellus | psql -U $PGUSER -d $DB -q >/dev/null 2>&1"
check "copy of dev"

export DATABASE_URL="postgresql://${PGUSER}:${PGPASS}@${PGHOST}:${PGPORT}/${DB}"
case "$DATABASE_URL" in *_test) ;; *) echo "refusing: $DATABASE_URL is not a _test database" >&2; exit 1 ;; esac
cd "$WT/backend"
PY=".venv/Scripts/python.exe"

# Quiet alembic's INFO lines, but never its failure: a rehearsal that hides a
# failed migration is worse than none.
alembic_q() {
    local out rc=0
    out="$("$PY" -m alembic "$@" 2>&1)" || rc=$?
    printf '%s
' "$out" | grep -v "^INFO" || true
    if [ "$rc" -ne 0 ]; then
        echo "alembic $* FAILED (exit $rc)" >&2
        exit "$rc"
    fi
}

alembic_q upgrade head
check "after upgrade"
alembic_q downgrade "$DOWN"
check "after downgrade to $DOWN"
alembic_q upgrade head
check "after re-upgrade"

echo "-- dev untouched: revision $(psql_in -d constellus -Atc 'select version_num from alembic_version')"
echo "-- $DB dropped on exit"
