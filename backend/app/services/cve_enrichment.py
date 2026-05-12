"""
Post-scan CVE enrichment pipeline.

For all findings in a scan run that have a cve_id, this service:
  1. Fetches EPSS scores in bulk from FIRST.org
  2. Checks CISA KEV (cached, refreshed daily)
  3. Fetches CVSS from NVD only when the connector didn't provide it

Called synchronously after Phase 3 in scan_executor — the scan is already
running in a background task so blocking here is acceptable.
"""

import logging
import time
import uuid
from datetime import date

from sqlalchemy.orm import Session

from app.models.finding import Finding

log = logging.getLogger(__name__)

_EPSS_URL = "https://api.first.org/data/v1/epss"
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_SLEEP = 7  # seconds between NVD requests (free tier: 5 req / 30s)
_NVD_MAX_PER_SCAN = 10  # cap NVD lookups per scan to bound runtime

# Module-level KEV cache (CVE_ID_UPPER → ISO date string)
_kev_cache: dict[str, str] | None = None
_kev_fetched_at: float = 0.0
_KEV_TTL = 86_400  # 1 day


def enrich_scan_findings(db: Session, scan_run_id: uuid.UUID) -> None:
    findings = (
        db.query(Finding)
        .filter(Finding.scan_run_id == scan_run_id, Finding.cve_id.isnot(None))
        .all()
    )
    if not findings:
        return

    cve_ids = list({f.cve_id.upper() for f in findings if f.cve_id})
    log.info("CVE enrichment: %d unique CVE IDs for scan %s", len(cve_ids), scan_run_id)

    epss = _fetch_epss_bulk(cve_ids)
    kev = _get_kev_dict()

    # NVD only for findings missing CVSS — capped to avoid slow scans
    nvd_needed = [cid for cid in cve_ids if _needs_nvd(findings, cid)][:_NVD_MAX_PER_SCAN]
    nvd: dict[str, dict] = {}
    for cid in nvd_needed:
        result = _fetch_nvd_cvss(cid)
        if result:
            nvd[cid] = result

    for f in findings:
        cid = (f.cve_id or "").upper()
        if not cid:
            continue

        if cid in epss:
            f.epss_score = epss[cid]["score"]
            f.epss_percentile = epss[cid]["percentile"]

        if cid in kev:
            f.kev = True
            raw_date = kev[cid]
            if raw_date:
                try:
                    f.kev_date_added = date.fromisoformat(raw_date)
                except ValueError:
                    pass

        if f.cvss_score is None and cid in nvd:
            f.cvss_score = nvd[cid]["score"]
            f.cvss_vector = nvd[cid]["vector"]
            f.cvss_version = nvd[cid]["version"]

    db.commit()
    log.info(
        "CVE enrichment complete for scan %s — EPSS: %d, KEV hits: %d, NVD: %d",
        scan_run_id, len(epss), sum(1 for f in findings if f.kev), len(nvd),
    )


# ── data fetchers ─────────────────────────────────────────────────────────────

def _fetch_epss_bulk(cve_ids: list[str]) -> dict[str, dict]:
    """Returns {CVE_ID_UPPER: {score: float, percentile: float}}."""
    try:
        import httpx
        result: dict[str, dict] = {}
        for i in range(0, len(cve_ids), 100):
            chunk = cve_ids[i : i + 100]
            resp = httpx.get(
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
            import httpx
            resp = httpx.get(_KEV_URL, timeout=30)
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
        import httpx
        time.sleep(_NVD_SLEEP)
        resp = httpx.get(_NVD_URL, params={"cveId": cve_id}, timeout=15)
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


def _needs_nvd(findings: list[Finding], cve_id: str) -> bool:
    return any(
        f.cve_id and f.cve_id.upper() == cve_id and f.cvss_score is None
        for f in findings
    )
