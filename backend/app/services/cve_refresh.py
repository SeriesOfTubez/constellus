"""Rolling CVE refresh (planning#360): published dates and KEV, oldest-due first.

One run (hourly, see `scheduler._register_cve_refresh`) reads the CVEs that are
due and refreshes them oldest first until it runs out of due CVEs, out of time,
or VulnCheck stops answering. The CVEs considered are every distinct CVE id on a
finding in ANY state (a resolved finding's timeline still wants the published
date), joined to `cve_records`.

Due: no `cve_records` row, or never stamped, or a success older than the refresh
interval, or a failure older than the failed-retry interval
(`cve_refresh_pacing`). Pacing is read once per run.

Per CVE: network first (a fresh VulnCheck lookup, no write open), then one unit
of work that mirrors CISA KEV and the VulnCheck signals onto the findings and
upserts `cve_records`, and commits. A failed unit rolls back alone. The findings
the mirrors touched are re-scored after the loop through
`nightly_rescore.rescore_and_notify`, so a CVE newly in KEV re-scores, writes
score history and notifies on promotion.

Guard (code, not a setting): 5 consecutive VulnCheck lookups that returned
nothing stop the run, because VulnCheck is then down or refusing and the batch
would only be stamped failed.

This opens its own session; never call it inside a request.
"""

import logging
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.cve_record import CveRecord
from app.models.finding_canonical import FindingCanonical
from app.services import connector_instances, cve_records, nightly_rescore
from app.services import cve_refresh_pacing as pacing_mod
from app.services.cve_enrichment import _get_kev_dict, mirror_cisa_kev
from app.services.vulncheck_enrichment import _lookup_cve, mirror_signals

log = logging.getLogger(__name__)

_monotonic = time.monotonic  # tests patch it

CONSECUTIVE_LOOKUP_FAILURES_STOP = 5


@dataclass(frozen=True)
class CveRefreshResult:
    due: int = 0
    refreshed: int = 0  # units committed with a successful (or keyless) refresh
    failed: int = 0  # VulnCheck returned nothing
    errors: int = 0  # an unexpected exception in a unit
    kev_rows_set: int = 0  # findings the CISA mirror touched
    rescored: int = 0
    promotions: int = 0
    vulncheck_configured: bool = False
    cisa_feed_ok: bool = False
    out_of_time: bool = False
    stopped_on_lookup: bool = False


def _read_due(db: Session, now: datetime, pacing: pacing_mod.CveRefreshPacing) -> list[str]:
    """The due CVE ids (upper-case), never-refreshed first, then oldest."""
    cid = func.upper(FindingCanonical.cve_id).label("cid")
    cves = select(cid).where(FindingCanonical.cve_id.isnot(None)).distinct().subquery()
    due = or_(
        CveRecord.cve_id.is_(None),
        CveRecord.refreshed_at.is_(None),
        and_(CveRecord.refresh_failed.is_(False), CveRecord.refreshed_at <= now - pacing.refresh_interval),
        and_(CveRecord.refresh_failed.is_(True), CveRecord.refreshed_at <= now - pacing.failed_retry_after),
    )
    rows = db.execute(
        select(cves.c.cid)
        .select_from(cves.outerjoin(CveRecord, CveRecord.cve_id == cves.c.cid))
        .where(due)
        .order_by(CveRecord.refreshed_at.asc().nulls_first(), cves.c.cid)
        .limit(pacing.due_batch)
    ).all()
    return [r[0] for r in rows]


def run_cve_refresh_tick() -> CveRefreshResult:
    start = _monotonic()
    counts = {"refreshed": 0, "failed": 0, "errors": 0, "kev_rows_set": 0, "rescored": 0, "promotions": 0}
    out_of_time = stopped_on_lookup = False
    finding_ids: set[uuid.UUID] = set()
    db = SessionLocal()
    try:
        pacing = pacing_mod.read(db)
        api_key = (connector_instances.enabled_config(db, "vulncheck") or {}).get("api_key")
        due_ids = _read_due(db, datetime.now(timezone.utc), pacing)
        db.rollback()  # end the read transaction before any network call
        headers = {"Accept": "application/json", "Authorization": f"Bearer {api_key}"} if api_key else None
        kev = _get_kev_dict()
        # `_get_kev_dict` returns {} when the CISA feed failed with no earlier
        # copy (the live list is never empty), so an empty dict means "no feed".
        cisa_feed_ok = bool(kev)

        streak = 0
        for cid in due_ids:
            if _monotonic() - start >= pacing.time_limit_s:
                out_of_time = True
                break
            try:
                sig = _lookup_cve(cid, headers, fresh=True) if headers else None
                if headers:
                    streak = 0 if sig else streak + 1
                now = datetime.now(timezone.utc)
                touched = mirror_cisa_kev(db, [cid], kev)
                counts["kev_rows_set"] += len(touched)
                if sig:
                    touched |= mirror_signals(db, {cid: sig})
                    cve_records.upsert_from_signals(db, {cid: sig}, now)
                elif headers:
                    cve_records.mark_failed(db, [cid], now)
                else:
                    cve_records.stamp_refreshed(db, [cid], now)
                db.commit()
            except Exception:
                db.rollback()
                counts["errors"] += 1
                log.exception("cve refresh unit failed cve=%s", cid)
                continue
            finding_ids |= touched
            if headers and not sig:
                counts["failed"] += 1
            else:
                counts["refreshed"] += 1
            if streak >= CONSECUTIVE_LOOKUP_FAILURES_STOP:
                stopped_on_lookup = True
                log.warning(
                    "cve refresh stopped: %d consecutive VulnCheck lookups returned nothing", streak
                )
                break

        if finding_ids:
            try:
                counts["promotions"] = nightly_rescore.rescore_and_notify(
                    db, finding_ids, datetime.now(timezone.utc)
                )
                db.commit()
                counts["rescored"] = len(finding_ids)
            except Exception:
                db.rollback()
                counts["errors"] += 1
                log.exception("cve refresh re-score failed")
    finally:
        db.close()
    result = CveRefreshResult(
        due=len(due_ids), vulncheck_configured=bool(api_key), cisa_feed_ok=cisa_feed_ok,
        out_of_time=out_of_time, stopped_on_lookup=stopped_on_lookup, **counts,
    )
    log.info(
        "cve refresh tick due=%d refreshed=%d failed=%d errors=%d kev_rows_set=%d rescored=%d promotions=%d "
        "vulncheck=%s cisa_feed_ok=%s out_of_time=%s stopped_on_lookup=%s",
        result.due, result.refreshed, result.failed, result.errors, result.kev_rows_set, result.rescored,
        result.promotions, result.vulncheck_configured, result.cisa_feed_ok, result.out_of_time,
        result.stopped_on_lookup,
    )
    return result
