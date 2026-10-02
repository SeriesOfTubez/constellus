#!/usr/bin/env bash
# Create a worktree for one issue: ../constellus-wt<N> on a new branch cut from
# a freshly fetched origin/dev, with backend/.venv and frontend/node_modules
# junctioned from the main checkout and .env copied in.
#
#     scripts/wt-new.sh 240 feat/240-company-relationship
#
# Windows (Git Bash) only: the junctions are made with `mklink /J`. Their
# targets are ABSOLUTE on purpose — a relative junction target resolves
# against the shell's working directory, not the link's, and silently points
# at a path that does not exist.
#
# Remove with scripts/wt-remove.sh <N>, never with a bare `git worktree
# remove`: the junctions must go first, or the removal can follow them into
# the main checkout's venv.
set -euo pipefail

if [ $# -ne 2 ]; then
    echo "usage: $0 <issue-number> <branch-name>" >&2
    exit 2
fi
N="$1"
BRANCH="$2"

MAIN="$(cd "$(dirname "$0")/.." && pwd)"
WT="$(dirname "$MAIN")/constellus-wt$N"

case "$MAIN$WT" in *" "*) echo "refusing: a path contains a space (junction commands are unquoted)" >&2; exit 1 ;; esac
if [ -e "$WT" ]; then
    echo "refusing: $WT already exists" >&2
    exit 1
fi
for dir in backend/.venv frontend/node_modules; do
    if [ ! -d "$MAIN/$dir" ]; then
        echo "refusing: $MAIN/$dir does not exist (nothing to junction)" >&2
        exit 1
    fi
done

git -C "$MAIN" fetch -q origin dev
git -C "$MAIN" worktree add -q --no-track -b "$BRANCH" "$WT" origin/dev

cp "$MAIN/.env" "$WT/.env"
for dir in backend/.venv frontend/node_modules; do
    link="$(cygpath -w "$WT/$dir")"
    target="$(cygpath -w "$MAIN/$dir")"
    # No inner quotes: escaped quotes do not survive MSYS -> cmd. Paths with
    # spaces are refused above instead.
    cmd //c "mklink /J $link $target" >/dev/null
done

if [ ! -x "$WT/backend/.venv/Scripts/python.exe" ]; then
    echo "junction check FAILED: $WT/backend/.venv/Scripts/python.exe not found" >&2
    exit 1
fi

echo "worktree: $WT"
echo "branch:   $BRANCH (from origin/dev @ $(git -C "$WT" rev-parse --short HEAD))"
echo "tests:    cd $WT && COMPOSE_PROJECT_NAME=constellus bash backend/scripts/test.sh"
