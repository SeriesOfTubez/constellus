#!/usr/bin/env bash
# Remove a worktree made by scripts/wt-new.sh: junctions first, then the
# worktree, then the local branch IF it is merged into origin/dev (a squash
# merge is not detected that way, so pass --delete-branch to force it once
# the PR is confirmed merged).
#
#     scripts/wt-remove.sh 240
#     scripts/wt-remove.sh 240 --delete-branch
set -euo pipefail

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "usage: $0 <issue-number> [--delete-branch]" >&2
    exit 2
fi
N="$1"
FORCE_BRANCH="${2:-}"

MAIN="$(cd "$(dirname "$0")/.." && pwd)"
WT="$(dirname "$MAIN")/constellus-wt$N"

case "$WT" in *" "*) echo "refusing: path contains a space" >&2; exit 1 ;; esac
if [ ! -d "$WT" ]; then
    echo "nothing to do: $WT does not exist" >&2
    exit 1
fi
BRANCH="$(git -C "$WT" branch --show-current)"

# `rmdir` (no /s) removes a junction without touching its target, and FAILS
# on a real non-empty directory — so it can never delete the main venv.
for dir in backend/.venv frontend/node_modules; do
    if [ -e "$WT/$dir" ]; then
        cmd //c "rmdir $(cygpath -w "$WT/$dir")" || {
            echo "refusing: $WT/$dir is not a junction (rmdir failed); remove it by hand" >&2
            exit 1
        }
    fi
done

if [ ! -x "$MAIN/backend/.venv/Scripts/python.exe" ]; then
    echo "WARNING: the main checkout's venv is missing — investigate before continuing" >&2
    exit 1
fi

git -C "$MAIN" worktree remove --force "$WT"
echo "removed: $WT"

git -C "$MAIN" fetch -q origin dev
if [ "$FORCE_BRANCH" = "--delete-branch" ]; then
    git -C "$MAIN" branch -D "$BRANCH"
elif git -C "$MAIN" branch -d "$BRANCH" 2>/dev/null; then
    :
else
    echo "kept branch $BRANCH (not merged by ancestry; rerun with --delete-branch once the squash merge is confirmed)"
fi
