"""
Re-enrichment management command.

Replays the post-scan enrichment chain over existing canonical findings without
running a scan — for when enrichment logic changes (new signals, new captured
fields like detail.cve_intel) and the stored corpus needs to catch up.

Mirrors the chain in scan_executor:
    cve → vulncheck → vulnx → score
Each step is fail-soft and takes (db, scan_run_id, canonical_ids); a synthetic
scan_run_id is used since there's no real run. Secrets overrides are primed from
DB connector config first (the app does this at startup; a bare process must too,
or VULNCHECK_API_KEY/PDCP_API_KEY won't resolve).

Lives inside the `app` package because the dev bind mount is `./backend/app:/app/app`
— a top-level scripts/ dir isn't visible in the container.

Usage (from the backend container):
    docker compose exec backend python -m app.scripts.reenrich
        → vulncheck+vulnx+score over all CVE findings
    docker compose exec backend python -m app.scripts.reenrich --steps cve,vulncheck,vulnx,score
    docker compose exec backend python -m app.scripts.reenrich --cve CVE-2021-40438 --cve CVE-2014-0160
    docker compose exec backend python -m app.scripts.reenrich --steps score --include-noncve   # rescore everything
    docker compose exec backend python -m app.scripts.reenrich --limit 50
"""

import argparse
import importlib
import logging
import uuid

from app.core.database import SessionLocal
from app.models.finding_canonical import FindingCanonical

log = logging.getLogger("reenrich")

# step name → (module path, callable name). All share (db, scan_run_id, canonical_ids).
STEPS: dict[str, tuple[str, str]] = {
    "cve":       ("app.services.cve_enrichment", "enrich_scan_findings"),
    "vulncheck": ("app.services.vulncheck_enrichment", "enrich_scan_findings"),
    "vulnx":     ("app.services.vulnx_enrichment", "enrich_scan_findings"),
    "score":     ("app.services.risk_scorer", "score_scan_findings"),
}
DEFAULT_STEPS = ["vulncheck", "vulnx", "score"]


def _resolve(step: str):
    mod_path, fn_name = STEPS[step]
    return getattr(importlib.import_module(mod_path), fn_name)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay enrichment over existing findings.")
    parser.add_argument("--steps", default=",".join(DEFAULT_STEPS),
                        help=f"comma-separated subset of {list(STEPS)} (default: {','.join(DEFAULT_STEPS)})")
    parser.add_argument("--cve", action="append", default=[],
                        help="limit to specific CVE id(s); repeatable")
    parser.add_argument("--include-noncve", action="store_true",
                        help="include findings without a CVE (e.g. exposures) — useful for a full rescore")
    parser.add_argument("--limit", type=int, default=None, help="cap the finding set (for testing)")
    args = parser.parse_args(argv)

    steps = [s.strip() for s in args.steps.split(",") if s.strip()]
    unknown = [s for s in steps if s not in STEPS]
    if unknown:
        parser.error(f"unknown step(s): {unknown}; valid: {list(STEPS)}")

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    db = SessionLocal()
    try:
        # Prime the secrets override layer from DB connector config (startup parity).
        from app.api.connectors import REGISTRY
        from app.services.connector_config import load_overrides_from_db
        load_overrides_from_db(db, REGISTRY)

        q = db.query(FindingCanonical.id)
        if not args.include_noncve:
            q = q.filter(FindingCanonical.cve_id.isnot(None))
        if args.cve:
            q = q.filter(FindingCanonical.cve_id.in_([c.upper() for c in args.cve]))
        if args.limit:
            q = q.limit(args.limit)
        ids = {r[0] for r in q.all()}

        if not ids:
            log.warning("no matching findings — nothing to do")
            return 0

        run_id = uuid.uuid4()
        log.info("re-enriching %d findings | steps=%s | synthetic run %s", len(ids), steps, run_id)

        for step in steps:
            fn = _resolve(step)
            try:
                fn(db, run_id, canonical_ids=ids)
                log.info("step '%s' complete", step)
            except Exception:
                log.exception("step '%s' failed — continuing", step)

        log.info("re-enrichment done")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
