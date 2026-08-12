"""Snapshot the live dev DB's Target values into a local, never-committed
denylist that pre-commit hooks check new commits against.

Why this exists: planning#125's incident (2026-08) leaked a real customer's
domain, subdomains, and IPs into this public repo — copied out of a planning
doc into new code without anyone recognizing they were live target data.
There's no reliable way to detect "a customer's domain" by pattern alone
(nothing distinguishes it from a legitimate third-party SaaS domain already
used correctly throughout this codebase) — but the *actual, current* set of
domains/IPs/CIDRs this deployment has added as Targets is a precise, known
ground truth. Anything in that set showing up in a diff or commit message is
unambiguously wrong.

The output file lives under .git/ specifically because git can never track
its own directory, regardless of .gitignore correctness — the list itself
is exactly as sensitive as the data it's protecting against leaking, so it
must never be committable even by accident.

Run this after adding/removing targets in the dev environment; the
pre-commit hook (scripts/check_target_domains.py) warns if the snapshot
looks stale.

Usage: backend/.venv/Scripts/python.exe scripts/refresh_target_denylist.py
(needs SQLAlchemy — run it with the backend venv's interpreter, not system Python)
Requires DATABASE_URL (defaults to the standard local docker-compose value).
"""

import os
import sys
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "postgresql://constellus:constellus@localhost:5432/constellus")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from sqlalchemy import create_engine, text  # noqa: E402

OUTPUT_PATH = Path(__file__).resolve().parent.parent / ".git" / "target-denylist.txt"


def main() -> None:
    engine = create_engine(os.environ["DATABASE_URL"])
    try:
        with engine.connect() as conn:
            rows = conn.execute(
                text("SELECT value FROM targets WHERE type IN ('domain', 'ip', 'cidr') ORDER BY value")
            ).scalars().all()
    except Exception as exc:
        print(f"refresh_target_denylist: could not reach the dev DB ({exc}).", file=sys.stderr)
        print("Leaving any existing snapshot untouched — see README note on staleness.", file=sys.stderr)
        sys.exit(1)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text("\n".join(rows) + ("\n" if rows else ""), encoding="utf-8")
    print(f"refresh_target_denylist: wrote {len(rows)} value(s) to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
