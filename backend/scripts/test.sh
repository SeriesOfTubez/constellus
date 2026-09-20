#!/usr/bin/env bash
# Run the backend test suite against a throwaway database.
#
# The suite mutates and deletes rows in whatever database it is pointed at, so
# it runs against a disposable one that is recreated from scratch every time.
# `app/tests/__init__.py` enforces that with a hard failure if the database
# name does not end in `_test` — see its header for the six-issue history that
# rule exists to close.
#
# Recreating is cheap: all migrations from empty take ~5s, and the full suite
# ~40s. There is deliberately no "reuse the database if it exists" flag — that
# option is how residue accumulated in the first place.
#
# Any arguments are passed through to pytest:
#     scripts/test.sh                                  # everything
#     scripts/test.sh app/tests/test_probe_authorisation.py -x
set -euo pipefail

DB_NAME="${CONSTELLUS_TEST_DB:-constellus_test}"
PGUSER="${CONSTELLUS_DB_USER:-constellus}"
PGPASS="${CONSTELLUS_DB_PASSWORD:-constellus}"
PGHOST="${CONSTELLUS_DB_HOST:-localhost}"
PGPORT="${CONSTELLUS_DB_PORT:-5432}"

cd "$(dirname "$0")/.."
REPO_ROOT="$(cd .. && pwd)"

# Prefer the repo venv over whatever `python` happens to be on PATH. The
# backend container cannot run pytest at all — its runtime image uninstalls
# pip and carries no dev dependencies — so the venv is the only local
# interpreter with the test dependencies installed.
if [ -x ".venv/Scripts/python.exe" ]; then
    PY=".venv/Scripts/python.exe"      # Windows
elif [ -x ".venv/bin/python" ]; then
    PY=".venv/bin/python"              # POSIX
else
    PY="python"                        # CI, or an already-activated venv
fi

echo "==> Recreating $DB_NAME"
# WITH (FORCE) terminates lingering connections (PG13+; the stack is PG18).
# Without it a stray psql session from a previous debugging run blocks the drop.
docker compose -f "$REPO_ROOT/docker-compose.yml" exec -T db \
    psql -U "$PGUSER" -d postgres \
    -c "DROP DATABASE IF EXISTS $DB_NAME WITH (FORCE);" \
    -c "CREATE DATABASE $DB_NAME OWNER $PGUSER;" >/dev/null

export DATABASE_URL="postgresql://${PGUSER}:${PGPASS}@${PGHOST}:${PGPORT}/${DB_NAME}"

echo "==> Migrating"
"$PY" -m alembic upgrade head >/dev/null

echo "==> Running pytest against $DB_NAME"
"$PY" -m pytest "${@:-app/tests}" -q
