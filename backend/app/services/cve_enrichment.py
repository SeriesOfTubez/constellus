"""
Post-scan CVE enrichment pipeline.

For all findings touched in a scan run that have a cve_id, this service:
  1. Fetches EPSS scores in bulk from FIRST.org
  2. Checks CISA KEV (cached, refreshed daily)
  3. Fetches CVSS from NVD only when the connector didn't provide it

Called synchronously after Phase 3 in scan_executor — the scan is already
running in a background task so blocking here is acceptable.

The executor passes the set of canonical finding IDs touched during the
run. Earlier versions of this module queried the legacy `findings`
hypertable by scan_run_id; that table is gone now.
"""

import logging
import time
import uuid
from datetime import date

from sqlalchemy.orm import Session

from app.connectors.http import connector_get
from app.core.secrets import get_secret
from app.models.finding_canonical import FindingCanonical

log = logging.getLogger(__name__)

_EPSS_URL = "https://api.first.org/data/v1/epss"
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Proactive pacing so we don't burn retry budget against NVD's free-tier
# limit (5 req / 30s). connector_get handles bursts that slip through
# via Retry-After-aware backoff — this is the floor, not the safety net.
_NVD_SLEEP = 7
_NVD_MAX_PER_SCAN = 10  # cap NVD lookups per scan to bound runtime

# Module-level KEV cache (CVE_ID_UPPER → ISO date string)
_kev_cache: dict[str, str] | None = None
_kev_fetched_at: float = 0.0
_KEV_TTL = 86_400  # 1 day


def enrich_scan_findings(
    db: Session,
    scan_run_id: uuid.UUID,
    canonical_ids: set[uuid.UUID] | None = None,
) -> set[uuid.UUID]:
    """Enrich the canonical findings touched by this scan run with EPSS,
    KEV, and (where needed) NVD CVSS data.

    canonical_ids is the set of finding_canonical IDs the executor touched
    in this run. EPSS/KEV/CVSS are CVE-level facts, so any *other*
    canonical row sharing one of the same CVE IDs gets the same update
    (the lookups are essentially free once they're in memory).

    Returns the IDs of every canonical row whose signals were mirrored
    (including the ones in canonical_ids), so the caller can re-run risk
    scoring over the full set — not just the rows touched by this run."""
    if not canonical_ids:
        return set()

    findings = (
        db.query(FindingCanonical)
        .filter(FindingCanonical.id.in_(canonical_ids))
        .filter(FindingCanonical.cve_id.isnot(None))
        .all()
    )
    if not findings:
        return set()

    cve_ids = list({f.cve_id.upper() for f in findings if f.cve_id})
    log.info("CVE enrichment: %d unique CVE IDs for scan %s", len(cve_ids), scan_run_id)

    epss = _fetch_epss_bulk(cve_ids)

    # Seed epss_history for any CVE not yet recorded; backfill 12 weekly
    # points so the trend chart has data on first sight, not just next refresh.
    from app.services import epss_history_service
    new_cves = epss_history_service.cves_without_history(db, cve_ids)
    if new_cves:
        epss_history_service.backfill(db, new_cves)
    # Always record today's sample (upsert is idempotent within the day).
    epss_history_service.upsert_current(db, cve_ids)

    kev = _get_kev_dict()

    # NVD direct is the slowest, least reliable CVSS source — it rate-limits us
    # to ~5 req/30s (hence the 7s/call sleep) and 503s frequently, adding up to
    # ~70s of dead time per scan. When VulnCheck is configured its NVD2 index
    # fills the same CVSS gaps right after this step (no per-scan cap, 1000
    # req/min), so the NVD fallback is pure overhead — skip it. Keep it only as
    # the last-resort CVSS source when no VulnCheck key is present.
    nvd: dict[str, dict] = {}
    if not get_secret("VULNCHECK_API_KEY"):
        nvd_needed = [cid for cid in cve_ids if _needs_nvd(findings, cid)][:_NVD_MAX_PER_SCAN]
        for cid in nvd_needed:
            result = _fetch_nvd_cvss(cid)
            if result:
                nvd[cid] = result

    # Mirror enrichment onto every canonical row sharing the touched CVE
    # IDs — not just the ones observed in this run.
    cve_ids_upper = list(epss.keys() | kev.keys() | nvd.keys())
    canonical_rows: list[FindingCanonical] = []
    if cve_ids_upper:
        canonical_rows = (
            db.query(FindingCanonical)
            .filter(FindingCanonical.cve_id.isnot(None))
            .filter(FindingCanonical.cve_id.in_(cve_ids_upper))
            .all()
        )
    # EPSS trend history is a CVE-level fact too: if a brand-new finding
    # shares a CVE with a row that already has a recorded epss_score_previous,
    # seed the new row from that — otherwise a freshly-discovered finding for
    # an already-trending CVE has no "previous" sample of its own and can
    # never show Building Velocity until its *next* scan.
    cve_prev_lookup: dict[str, float] = {}
    for c in canonical_rows:
        cid = (c.cve_id or "").upper()
        if cid not in cve_prev_lookup and c.epss_score_previous is not None:
            cve_prev_lookup[cid] = c.epss_score_previous

    for c in canonical_rows:
        cid = (c.cve_id or "").upper()
        if cid in epss:
            new_epss = epss[cid]["score"]
            # Snapshot the prior sample for Building Velocity trend detection —
            # but only when EPSS actually moved, so a no-change scan doesn't wipe
            # the history by setting previous == current. (Risk scorer reads the
            # delta; v1 sample-diff, see risk_scorer._building_velocity.)
            if c.epss_score is not None and c.epss_score != new_epss:
                c.epss_score_previous = c.epss_score
            elif c.epss_score is None and c.epss_score_previous is None:
                c.epss_score_previous = cve_prev_lookup.get(cid)
            c.epss_score = new_epss
            c.epss_percentile = epss[cid]["percentile"]
        if cid in kev:
            c.kev = True
            raw_date = kev[cid]
            if raw_date:
                try:
                    c.kev_date_added = date.fromisoformat(raw_date)
                except ValueError:
                    pass
        if c.cvss_score is None and cid in nvd:
            c.cvss_score = nvd[cid]["score"]
            c.cvss_vector = nvd[cid]["vector"]
            c.cvss_version = nvd[cid]["version"]

    db.commit()
    log.info(
        "CVE enrichment complete for scan %s — EPSS: %d, KEV hits: %d, NVD: %d",
        scan_run_id, len(epss), sum(1 for c in canonical_rows if c.kev), len(nvd),
    )
    return {c.id for c in canonical_rows}


# ── data fetchers ─────────────────────────────────────────────────────────────

def _fetch_epss_bulk(cve_ids: list[str]) -> dict[str, dict]:
    """Returns {CVE_ID_UPPER: {score: float, percentile: float}}."""
    try:
        result: dict[str, dict] = {}
        for i in range(0, len(cve_ids), 100):
            chunk = cve_ids[i : i + 100]
            resp = connector_get(
                _EPSS_URL,
                params={"cve": ",".join(chunk)},
                timeout=20,
            )
            resp.raise_for_status()
            for item in resp.json().get("data", []):
                cve = item.get("cve", "").upper()
                result[cve] = {
                    "score": float(item["epss"]),
                    "percentile": float(item["percentile"]),
                }
        return result
    except Exception:
        log.warning("EPSS fetch failed", exc_info=True)
        return {}


def _get_kev_dict() -> dict[str, str]:
    """Returns {CVE_ID_UPPER: date_added_iso}. Refreshed at most once per day."""
    global _kev_cache, _kev_fetched_at
    now = time.monotonic()
    if _kev_cache is None or (now - _kev_fetched_at) > _KEV_TTL:
        try:
            resp = connector_get(_KEV_URL, timeout=30)
            resp.raise_for_status()
            vulns = resp.json().get("vulnerabilities", [])
            _kev_cache = {
                v["cveID"].upper(): v.get("dateAdded", "")
                for v in vulns
                if "cveID" in v
            }
            _kev_fetched_at = now
            log.info("CISA KEV refreshed — %d entries", len(_kev_cache))
        except Exception:
            log.warning("CISA KEV fetch failed", exc_info=True)
            _kev_cache = _kev_cache or {}
    return _kev_cache or {}


def _fetch_nvd_cvss(cve_id: str) -> dict | None:
    """Returns {score, vector, version} for the highest available CVSS version, or None."""
    try:
        time.sleep(_NVD_SLEEP)
        resp = connector_get(_NVD_URL, params={"cveId": cve_id}, timeout=15)
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        if not vulns:
            return None
        metrics = vulns[0]["cve"].get("metrics", {})
        for key, version in [
            ("cvssMetricV40", "4.0"),
            ("cvssMetricV31", "3.1"),
            ("cvssMetricV30", "3.0"),
            ("cvssMetricV2", "2.0"),
        ]:
            entries = metrics.get(key, [])
            if entries:
                data = entries[0].get("cvssData", {})
                return {
                    "score": data.get("baseScore"),
                    "vector": data.get("vectorString"),
                    "version": version,
                }
        return None
    except Exception:
        log.warning("NVD fetch failed for %s", cve_id, exc_info=True)
        return None


def _needs_nvd(findings: list[FindingCanonical], cve_id: str) -> bool:
    return any(
        f.cve_id and f.cve_id.upper() == cve_id and f.cvss_score is None
        for f in findings
    )
