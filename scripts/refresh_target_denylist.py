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

Since 2026-10-01 it also writes `entity-denylist.txt` beside it: every
company name and CIK in the dev entity graph (`org_entities`). All of those
are real (the test suite runs on constellus_test, never dev), and the same
leak shape applies to them: a real filer's former name or subsidiary copied
into a test table or an issue comment. scripts/denylist.py describes the
format and how each list is matched.

Run this after adding/removing targets OR mapping a company in the dev
environment; the git hooks (scripts/check_target_domains.py) and the Claude
Code hook (scripts/check_outbound_text.py) warn if a snapshot looks stale.

Usage: backend/.venv/Scripts/python.exe scripts/refresh_target_denylist.py
(needs SQLAlchemy — run it with the backend venv's interpreter, not system Python)
Requires DATABASE_URL (defaults to the standard local docker-compose value).
"""

import os
import sys
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "postgresql://constellus:constellus@localhost:5432/constellus")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from sqlalchemy import create_engine, text  # noqa: E402

from denylist import ENTITY_PATH, TARGET_PATH  # noqa: E402

OUTPUT_PATH = TARGET_PATH


def _write(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def main() -> None:
    engine = create_engine(os.environ["DATABASE_URL"])
    try:
        with engine.connect() as conn:
            rows = conn.execute(
                text("SELECT value FROM targets WHERE type IN ('domain', 'ip', 'cidr') ORDER BY value")
            ).scalars().all()
            # planning#241 follow-up (2026-10-01): the entity graph is real
            # data too — every org_entities row in dev is a real company,
            # former name or subsidiary (tests run on constellus_test). Its
            # names and CIKs feed check_outbound_text.py and the git hooks.
            entities = conn.execute(
                text("SELECT legal_name, cik FROM org_entities ORDER BY legal_name")
            ).all()
    except Exception as exc:
        print(f"refresh_target_denylist: could not reach the dev DB ({exc}).", file=sys.stderr)
        print("Leaving any existing snapshot untouched — see README note on staleness.", file=sys.stderr)
        sys.exit(1)

    _write(TARGET_PATH, list(rows))
    entity_lines = sorted(
        {"name\t" + " ".join(name.split()) for name, _ in entities if name and name.strip()}
        | {f"cik\t{cik}" for _, cik in entities if cik}
    )
    _write(ENTITY_PATH, entity_lines)
    print(f"refresh_target_denylist: wrote {len(rows)} target value(s) to {TARGET_PATH}")
    print(f"refresh_target_denylist: wrote {len(entity_lines)} entity value(s) to {ENTITY_PATH}")


if __name__ == "__main__":
    main()
