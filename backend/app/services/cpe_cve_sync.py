"""CPE→CVE index sync — populate/refresh `cpe_cve_ranges` (#66 B0).

Single-source on VulnCheck (the one API key Constellus already requires for core
function — no second key) since S0 proved its online CPE→CVE lookup is paywalled:

  seed_from_vulncheck_backup — one-time historical seed from the nist-nvd2 backup
                    (`/v3/backup/nist-nvd2` → a zip of 182 gzipped NVD-2.0 feed
                    chunks). Streamed to a temp file, decompressed member-by-member
                    (≤15 MiB each), filtered to the D7 products → ~6 MB stored. The
                    344 MiB download is transient; the full corpus is never stored.
  delta_from_vulncheck — VulnCheck nist-nvd2 `lastMod` window. vcConfigurations
                    fills the NVD analysis backlog so freshly-disclosed CVEs on
                    supported (not just EOL) versions are caught.
  refresh         — seed once (if needed) then run the delta. Scheduler calls this
                    daily; also exposed for a manual trigger.

Each CVE's `configurations`/`vcConfigurations` enumerate every affected product, so
the parser emits all in-scope product rows per CVE and the delete-by-cve refresh
stays consistent across products. Fail-soft: outages abort the run and leave the
existing index in place; the next scheduled refresh retries. Everything is skipped
(not failed) when no VULNCHECK_API_KEY is configured.
"""

import gzip
import json
import logging
import os
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy.orm import Session

from app.connectors.http import connector_get
from app.core.secrets import get_secret
from app.models.app_settings import AppSetting
from app.models.cpe_cve_range import CpeCveRange
from app.services.cpe_cve_index import parse_configurations, replace_cve_ranges

log = logging.getLogger(__name__)

_VC_BACKUP_URL = "https://api.vulncheck.com/v3/backup/nist-nvd2"
_VC_NVD2_URL = "https://api.vulncheck.com/v3/index/nist-nvd2"
_VC_PAGE = 100
# NVD lastMod windows are capped at 120 days; stay well under it per delta.
_DELTA_MAX_DAYS = 110

_SEEDED_KEY = "cpe_index.seeded"
_CURSOR_KEY = "cpe_index.delta_cursor"          # ISO date, last lastMod processed
_LAST_REFRESH_KEY = "cpe_index.last_refresh_at"  # ISO timestamp


# ── app_settings helpers ──────────────────────────────────────────────────────

def _get_setting(db: Session, key: str) -> str | None:
    row = db.get(AppSetting, key)
    return row.value if row else None


def _set_setting(db: Session, key: str, value: str) -> None:
    row = db.get(AppSetting, key)
    if row is None:
        db.add(AppSetting(key=key, value=value))
    else:
        row.value = value
    db.commit()


def _vc_headers() -> dict | None:
    api_key = get_secret("VULNCHECK_API_KEY")
    if not api_key:
        return None
    return {"Accept": "application/json", "Authorization": f"Bearer {api_key}"}


# ── seed: VulnCheck nist-nvd2 backup zip ──────────────────────────────────────

def seed_from_vulncheck_backup(db: Session) -> int:
    """Seed the index from the VulnCheck nist-nvd2 backup (full history). Streams
    the zip to a temp file, parses each gzipped NVD-2.0 feed chunk, filters to the
    D7 products. Returns rows written. Idempotent; skipped without an API key."""
    headers = _vc_headers()
    if headers is None:
        log.warning("CPE index seed skipped — no VULNCHECK_API_KEY configured")
        return 0
    now = datetime.now(timezone.utc)

    resp = connector_get(_VC_BACKUP_URL, headers=headers, timeout=60, max_retries=3)
    if resp.status_code != 200:
        raise RuntimeError(f"VulnCheck backup index HTTP {resp.status_code}")
    entries = resp.json().get("data", [])
    if not entries:
        raise RuntimeError("VulnCheck backup index returned no entries")
    url = entries[0]["url"]

    fd, tmp_path = tempfile.mkstemp(suffix=".zip")
    os.close(fd)
    written = 0
    try:
        # zipfile needs random access, so stream the 344 MiB zip to disk (transient).
        with httpx.stream("GET", url, timeout=600) as r:
            r.raise_for_status()
            with open(tmp_path, "wb") as f:
                for chunk in r.iter_bytes(1 << 20):
                    f.write(chunk)

        with zipfile.ZipFile(tmp_path) as z:
            members = [n for n in z.namelist() if n.endswith(".json.gz")]
            for name in members:
                with z.open(name) as member:
                    feed = json.loads(gzip.decompress(member.read()))
                for v in feed.get("vulnerabilities", []) or []:
                    cve = v.get("cve", {})
                    cid = cve.get("id")
                    if not cid:
                        continue
                    configs = (cve.get("configurations") or []) + (cve.get("vcConfigurations") or [])
                    rows = parse_configurations(cid, configs, "vulncheck", now)
                    if rows:
                        written += replace_cve_ranges(db, cid, rows)
                db.commit()
            log.info("CPE seed: %d feed chunks processed, %d rows written", len(members), written)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    _set_setting(db, _SEEDED_KEY, "1")
    # First delta only needs to backfill the recent window (the seed has full
    # history); a week back covers anything modified right around seed time.
    _set_setting(db, _CURSOR_KEY, (now - timedelta(days=7)).date().isoformat())
    log.info("VulnCheck backup seed complete: %d rows written", written)
    return written


# ── delta: VulnCheck lastMod window ───────────────────────────────────────────

def delta_from_vulncheck(db: Session) -> int:
    """Refresh recently-modified CVEs from the VulnCheck nist-nvd2 `lastMod`
    window (parses both NVD `configurations` and VulnCheck `vcConfigurations`).
    Advances the cursor. Returns rows written. Skipped without an API key."""
    headers = _vc_headers()
    if headers is None:
        log.info("CPE index delta skipped — no VULNCHECK_API_KEY configured")
        return 0

    now = datetime.now(timezone.utc)
    cursor = _get_setting(db, _CURSOR_KEY)
    start_date = (
        datetime.fromisoformat(cursor).date() if cursor
        else (now - timedelta(days=_DELTA_MAX_DAYS)).date()
    )
    end_date = now.date()
    # Clamp the window so we never exceed the provider's max span.
    if (end_date - start_date).days > _DELTA_MAX_DAYS:
        start_date = end_date - timedelta(days=_DELTA_MAX_DAYS)

    processed: set[str] = set()
    written = 0
    page = 1
    while True:
        try:
            resp = connector_get(
                _VC_NVD2_URL, headers=headers, timeout=60, max_retries=3,
                params={"lastModStartDate": start_date.isoformat(),
                        "lastModEndDate": end_date.isoformat(),
                        "page": page, "limit": _VC_PAGE},
            )
        except Exception:
            log.warning("VulnCheck delta request failed (page %d)", page, exc_info=True)
            raise
        if resp.status_code != 200:
            log.warning("VulnCheck delta → HTTP %d (page %d)", resp.status_code, page)
            raise RuntimeError(f"VulnCheck HTTP {resp.status_code}")
        body = resp.json()
        data = body.get("data", []) or []
        for rec in data:
            cid = rec.get("id")
            if not cid or cid in processed:
                continue
            processed.add(cid)
            configs = (rec.get("configurations") or []) + (rec.get("vcConfigurations") or [])
            rows = parse_configurations(cid, configs, "vulncheck", now)
            if rows:
                written += replace_cve_ranges(db, cid, rows)
            elif db.query(CpeCveRange.id).filter(CpeCveRange.cve_id == cid.upper()).first():
                # No longer maps to a D7 product — clean up stale rows.
                db.query(CpeCveRange).filter(CpeCveRange.cve_id == cid.upper()).delete(
                    synchronize_session=False)
        db.commit()
        meta = body.get("_meta", {})
        total_pages = meta.get("total_pages") or 1
        if page >= total_pages or not data:
            break
        page += 1

    _set_setting(db, _CURSOR_KEY, end_date.isoformat())
    log.info("VulnCheck delta %s→%s complete: %d CVEs, %d rows written",
             start_date, end_date, len(processed), written)
    return written


# ── orchestration ─────────────────────────────────────────────────────────────

def refresh(db: Session) -> dict:
    """Seed once (if not yet seeded) then run the VulnCheck delta. Returns a
    small stats dict. Called by the scheduler and the manual trigger."""
    stats = {"seeded": 0, "delta": 0}
    if _get_setting(db, _SEEDED_KEY) != "1":
        stats["seeded"] = seed_from_vulncheck_backup(db)
    stats["delta"] = delta_from_vulncheck(db)
    _set_setting(db, _LAST_REFRESH_KEY, datetime.now(timezone.utc).isoformat())
    return stats
