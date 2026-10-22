#!/usr/bin/env bash
# Create a worktree for one issue: ../constellus-wt<N> on a new branch cut from
# a freshly fetched origin/dev, with backend/.venv and frontend/node_modules
# symlinked from the main checkout and .env copied in.
#
#     scripts/wt-new.sh 240 feat/240-company-relationship
#
# macOS/Linux. The symlink targets are ABSOLUTE so they do not depend on
# where the link sits.
#
# Remove with scripts/wt-remove.sh <N>, never with a bare `git worktree
# remove`: the links must go first, so nothing can follow them into the main
# checkout's venv.
set -euo pipefail

if [ $# -ne 2 ]; then
    echo "usage: $0 <issue-number> <branch-name>" >&2
    exit 2
fi
N="$1"
BRANCH="$2"

MAIN="$(cd "$(dirname "$0")/.." && pwd)"
WT="$(dirname "$MAIN")/constellus-wt$N"

if [ -e "$WT" ]; then
    echo "refusing: $WT already exists" >&2
    exit 1
fi
for dir in backend/.venv frontend/node_modules; do
    if [ ! -d "$MAIN/$dir" ]; then
        echo "refusing: $MAIN/$dir does not exist (nothing to link)" >&2
        exit 1
    fi
done

git -C "$MAIN" fetch -q origin dev
git -C "$MAIN" worktree add -q --no-track -b "$BRANCH" "$WT" origin/dev

cp "$MAIN/.env" "$WT/.env"
for dir in backend/.venv frontend/node_modules; do
    ln -s "$MAIN/$dir" "$WT/$dir"
done

if [ ! -x "$WT/backend/.venv/bin/python" ]; then
    echo "link check FAILED: $WT/backend/.venv/bin/python not found" >&2
    exit 1
fi

echo "worktree: $WT"
echo "branch:   $BRANCH (from origin/dev @ $(git -C "$WT" rev-parse --short HEAD))"
echo "tests:    cd $WT && COMPOSE_PROJECT_NAME=constellus bash backend/scripts/test.sh"
