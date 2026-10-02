#!/usr/bin/env bash
# Run a read-only probe script with a BRANCH's backend code inside the
# running backend container, against constellus_test — never dev.
#
#     scripts/live_probe.sh ../constellus-wt240 probe.py [org-entity-id]
#
#   <worktree>         the branch checkout; its backend/app is copied in
#   <probe.py>         your script (scratchpad, not the repo). It runs with
#                      PYTHONPATH pointing at the branch code. It MUST itself
#                      assert `select current_database()` ends in _test.
#   [org-entity-id]    optional: the CIK of this dev-DB org_entities row is
#                      read at run time and passed as $PROBE_CIK. It is never
#                      printed or written to a file, and 10-digit numbers are
#                      masked in the output.
#
# constellus_test must exist and be migrated: run backend/scripts/test.sh
# from the worktree first. The container's /tmp copy is removed on exit;
# drop the database yourself when finished:
#     docker exec constellus-db-1 psql -U constellus -d postgres -c "DROP DATABASE constellus_test WITH (FORCE);"
set -euo pipefail

if [ $# -lt 2 ] || [ $# -gt 3 ]; then
    echo "usage: $0 <worktree> <probe.py> [org-entity-id]" >&2
    exit 2
fi
WT="$(cd "$1" && pwd)"
PROBE="$2"
ENTITY="${3:-}"
export MSYS_NO_PATHCONV=1

DEST=/tmp/live_probe
cleanup() { docker exec constellus-backend-1 rm -rf "$DEST" || true; }
trap cleanup EXIT

if [ "$(docker exec constellus-db-1 psql -U constellus -d postgres -Atc "select count(*) from pg_database where datname='constellus_test'")" != "1" ]; then
    echo "refusing: constellus_test does not exist — run backend/scripts/test.sh from the worktree first" >&2
    exit 1
fi

TESTURL="$(docker exec constellus-backend-1 sh -c 'echo "$DATABASE_URL"' | sed -E 's#/[^/?]+$#/constellus_test#')"
case "$TESTURL" in *_test) ;; *) echo "refusing: could not point DATABASE_URL at constellus_test" >&2; exit 1 ;; esac

CIK=""
if [ -n "$ENTITY" ]; then
    CIK="$(docker exec constellus-db-1 psql -U constellus -d constellus -Atc "select cik from org_entities where id='$ENTITY'")"
    [ -n "$CIK" ] || { echo "refusing: no CIK for entity $ENTITY" >&2; exit 1; }
fi

cleanup
docker exec constellus-backend-1 mkdir -p "$DEST"
# Host-side paths must be Windows paths: MSYS_NO_PATHCONV (needed for the
# container-side /tmp paths) also stops Git Bash converting these.
docker cp "$(cygpath -w "$WT/backend/app")" "constellus-backend-1:$DEST/app" >/dev/null
docker cp "$(cygpath -w "$PROBE")" "constellus-backend-1:$DEST/probe.py" >/dev/null

docker exec -e PYTHONPATH="$DEST" -e DATABASE_URL="$TESTURL" -e PROBE_CIK="$CIK" -w "$DEST" \
    constellus-backend-1 python probe.py 2>&1 \
    | grep -vE '^INFO|HTTP Request' \
    | sed -E 's/\b[0-9]{10}\b/<n>/g'
