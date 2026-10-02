"""Shared loader + matcher for the local, never-committed denylists that keep
real data out of this public repo and its planning issues.

Two snapshots live in the git COMMON dir (never trackable, see
refresh_target_denylist.py), both written by refresh_target_denylist.py from
the live dev DB:

  target-denylist.txt  — Target domains/IPs/CIDRs, one per line, matched as
                         case-insensitive substrings (the original rule).
  entity-denylist.txt  — real company data the entity graph holds (every
                         org_entities row in dev is real: the test suite runs
                         on constellus_test). Lines are `name<TAB>value` or
                         `cik<TAB>value`. Names match as whole words,
                         case-insensitive, any run of whitespace equal to any
                         other; a CIK matches as a whole number with or
                         without its leading zeros.

Used by check_target_domains.py (git pre-commit / commit-msg hooks) and
check_outbound_text.py (the Claude Code PreToolUse hook on gh/git commands).
"""

from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

STALE_AFTER_SECONDS = 24 * 3600
MIN_NAME_LENGTH = 6


def git_common_dir() -> Path:
    # The SHARED git dir, not `<repo>/.git`: in a `git worktree` checkout
    # `.git` is a file. Still inside git's own directory, so never tracked.
    out = subprocess.run(
        ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
        cwd=Path(__file__).resolve().parent, capture_output=True, text=True, check=True,
    )
    return Path(out.stdout.strip())


TARGET_PATH = git_common_dir() / "target-denylist.txt"
ENTITY_PATH = git_common_dir() / "entity-denylist.txt"
REFRESH_HINT = "backend/.venv/Scripts/python.exe scripts/refresh_target_denylist.py"


class DenylistMissing(Exception):
    pass


@dataclass
class Denylist:
    targets: list[str] = field(default_factory=list)
    names: list[str] = field(default_factory=list)
    ciks: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def find(self, text: str) -> list[str]:
        """Every denylisted value that occurs in `text`, deduplicated."""
        hits: list[str] = []
        lower = text.lower()
        hits += [t for t in self.targets if t.lower() in lower]
        hits += [n for n in self.names if _name_re(n).search(text)]
        hits += [c for c in self.ciks if _cik_re(c).search(text)]
        return sorted(set(hits))


def _name_re(name: str) -> re.Pattern[str]:
    words = [re.escape(w) for w in name.split()]
    return re.compile(r"(?<!\w)" + r"\s+".join(words) + r"(?!\w)", re.IGNORECASE)


def _cik_re(cik: str) -> re.Pattern[str]:
    return re.compile(r"(?<!\d)0*" + re.escape(cik.lstrip("0") or "0") + r"(?!\d)")


def _read(path: Path, warnings: list[str]) -> list[str]:
    if not path.exists():
        raise DenylistMissing(f"no snapshot at {path}. Run: {REFRESH_HINT} (needs the dev DB reachable)")
    age = time.time() - path.stat().st_mtime
    if age > STALE_AFTER_SECONDS:
        warnings.append(
            f"{path.name} is {int(age // 3600)}h old; values added to dev since then are not caught. "
            f"Run {REFRESH_HINT}."
        )
    return [line.rstrip("\r\n") for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load() -> Denylist:
    """Both snapshots; raises DenylistMissing if either is absent (callers
    fail CLOSED on that — the snapshot existing is the load-bearing part)."""
    dl = Denylist()
    dl.targets = [line.strip() for line in _read(TARGET_PATH, dl.warnings)]
    for line in _read(ENTITY_PATH, dl.warnings):
        kind, _, value = line.partition("\t")
        value = value.strip()
        if kind == "name" and len(value) >= MIN_NAME_LENGTH:
            dl.names.append(value)
        elif kind == "cik" and value.isdigit():
            dl.ciks.append(value)
    return dl
