"""CPE→CVE index sync — populate/refresh `cpe_cve_ranges` (#66 B0).

Single-source on VulnCheck (the one API key Constellus already requires for core
function — no second key) since S0 proved its online CPE→CVE lookup is paywalled:

  seed_from_vulncheck_backup — one-time historical seed from the nist-nvd2 backup
                    (`/v3/backup/nist-nvd2` → a zip of 182 gzipped NVD-2.0 feed
                    chunks). Streamed to a temp file, decompressed member-by-member
                    (≤15 MiB each), filtered to the D7 products → ~6 MB stored. The
                    344 MiB download is transient; the full corpus is never stored.
  delta_from_vulncheck — VulnCheck nist-nvd2 by `lastMod`, one day at a time,
                    oldest first (planning#369). vcConfigurations fills the NVD
                    analysis backlog so freshly-disclosed CVEs on supported (not
                    just EOL) versions are caught.
  refresh         — seed once (if needed) then run the delta. Scheduler calls this
                    daily; also exposed for a manual trigger.

Each CVE's `configurations`/`vcConfigurations` enumerate every affected product, so
the parser emits all in-scope product rows per CVE and the delete-by-cve refresh
stays consistent across products. Fail-soft: an outage or a refused request stops
the run and keeps the days already finished; the next scheduled refresh carries on
from the stored cursor. Everything is skipped (not failed) when no VULNCHECK_API_KEY
is configured.

The delta's rules (planning#369):
  - One day per slice. The stored cursor is the oldest day not yet finished; it
    moves only after a whole day is processed and never past an unprocessed one.
  - Inside a day the provider's cursor pagination is used. Page-number pagination
    is refused past 10,000 records and single days exceed that.
  - The per-run time limit is checked between days only. A day's provider cursor
    cannot be resumed, so a started day always finishes; checking mid-day would
    leave a day larger than the limit stuck forever.
"""

import gzip
import json
import logging
import os
import tempfile
import time
import zipfile
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone

import httpx
from sqlalchemy.orm import Session

from app.services import app_settings, connector_instances
from app.connectors.http import connector_get
from app.models.app_settings import AppSetting
from app.models.cpe_cve_range import CpeCveRange
from app.services.cpe_cve_index import parse_configurations, replace_cve_ranges

log = logging.getLogger(__name__)

_VC_BACKUP_URL = "https://api.vulncheck.com/v3/backup/nist-nvd2"
_VC_NVD2_URL = "https://api.vulncheck.com/v3/index/nist-nvd2"
# Where the delta starts when no cursor is stored (the seed always stores one).
_NO_CURSOR_LOOKBACK_DAYS = 110

# Admin settings (defaults in app_settings.DEFAULTS). A stored value that is
# missing, unparsable or out of bounds reads as the default.
PAGE_SIZE_KEY = "cpe_index.page_size"
PAGE_SIZE_MIN, PAGE_SIZE_MAX, DEFAULT_PAGE_SIZE = 50, 2000, 500
RUN_TIME_LIMIT_KEY = "cpe_index.run_time_limit_seconds"
RUN_TIME_LIMIT_MIN, RUN_TIME_LIMIT_MAX, DEFAULT_RUN_TIME_LIMIT = 60, 3600, 600

_SEEDED_KEY = "cpe_index.seeded"
_CURSOR_KEY = "cpe_index.delta_cursor"          # ISO date, oldest day not yet finished
_LAST_REFRESH_KEY = "cpe_index.last_refresh_at"  # ISO timestamp, last run that reached today


@dataclass(frozen=True)
class DeltaPacing:
    page_size: int
    time_limit_s: int


def pacing(db: Session) -> DeltaPacing:
    def bounded(key: str, lo: int, hi: int, default: int) -> int:
        value = app_settings.get_int(db, key)
        return value if value is not None and lo <= value <= hi else default

    return DeltaPacing(
        page_size=bounded(PAGE_SIZE_KEY, PAGE_SIZE_MIN, PAGE_SIZE_MAX, DEFAULT_PAGE_SIZE),
        time_limit_s=bounded(RUN_TIME_LIMIT_KEY, RUN_TIME_LIMIT_MIN, RUN_TIME_LIMIT_MAX,
                             DEFAULT_RUN_TIME_LIMIT),
    )


@dataclass(frozen=True)
class DeltaResult:
    written: int
    days_done: int
    days_left: int
    stopped: str  # a job_runs finish reason: done | time_limit | source_refused | not_configured


class _SourceRefused(Exception):
    """The provider answered a delta request with a non-200."""


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


def _vc_headers(db: Session) -> dict | None:
    api_key = (connector_instances.enabled_config(db, "vulncheck") or {}).get("api_key")
    if not api_key:
        return None
    return {"Accept": "application/json", "Authorization": f"Bearer {api_key}"}


# ── seed: VulnCheck nist-nvd2 backup zip ──────────────────────────────────────

def seed_from_vulncheck_backup(db: Session) -> int:
    """Seed the index from the VulnCheck nist-nvd2 backup (full history). Streams
    the zip to a temp file, parses each gzipped NVD-2.0 feed chunk, filters to the
    D7 products. Returns rows written. Idempotent; skipped without an API key."""
    headers = _vc_headers(db)
    if headers is None:
        log.warning("CPE index seed skipped — no enabled VulnCheck API key configured")
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

def _refresh_day(db: Session, headers: dict, day: date, page_size: int, now: datetime) -> int:
    """Process every CVE modified on `day` (parses both NVD `configurations` and
    VulnCheck `vcConfigurations`), walking the provider's cursor pagination.
    Commits per page. Returns rows written. Raises `_SourceRefused` on a non-200."""
    params = {"lastModStartDate": day.isoformat(), "lastModEndDate": day.isoformat(),
              "limit": page_size}
    page_params = {**params, "start_cursor": "true"}
    seen_cursors: set[str] = set()
    processed: set[str] = set()
    written = 0
    page = 1
    while True:
        try:
            resp = connector_get(_VC_NVD2_URL, headers=headers, timeout=60, max_retries=3,
                                 params=page_params)
        except Exception:
            log.warning("VulnCheck delta request failed (%s, page %d)", day, page, exc_info=True)
            raise
        if resp.status_code != 200:
            log.warning("VulnCheck delta → HTTP %d (%s, page %d): %s",
                        resp.status_code, day, page, resp.text[:300])
            raise _SourceRefused(f"VulnCheck HTTP {resp.status_code}")
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
        next_cursor = (body.get("_meta") or {}).get("next_cursor")
        if not next_cursor or not data:
            break
        # Guard, not a setting: a cursor handed back twice would loop forever.
        if next_cursor in seen_cursors:
            raise RuntimeError("VulnCheck delta cursor repeated")
        seen_cursors.add(next_cursor)
        page_params = {**params, "cursor": next_cursor}
        page += 1
    log.info("VulnCheck delta %s: %d CVEs, %d rows written", day, len(processed), written)
    return written


def delta_from_vulncheck(db: Session) -> DeltaResult:
    """Refresh CVEs modified since the stored cursor, one day at a time, oldest
    first, and move the cursor after each finished day. Stops between days at
    the time limit, or when the provider refuses a request (the unfinished day
    stays due). Skipped without an API key."""
    headers = _vc_headers(db)
    if headers is None:
        log.info("CPE index delta skipped — no enabled VulnCheck API key configured")
        return DeltaResult(0, 0, 0, "not_configured")

    pace = pacing(db)
    now = datetime.now(timezone.utc)
    today = now.date()
    cursor = _get_setting(db, _CURSOR_KEY)
    day = (
        datetime.fromisoformat(cursor).date() if cursor
        else today - timedelta(days=_NO_CURSOR_LOOKBACK_DAYS)
    )
    deadline = time.monotonic() + pace.time_limit_s

    written = 0
    days_done = 0
    stopped = "done"
    while day <= today:
        # Between days only, and never before the first: every run makes progress.
        if days_done and time.monotonic() >= deadline:
            stopped = "time_limit"
            break
        try:
            written += _refresh_day(db, headers, day, pace.page_size, now)
        except _SourceRefused:
            db.rollback()
            stopped = "source_refused"
            break
        days_done += 1
        # Today is never finished (more arrives), so the cursor rests on it.
        _set_setting(db, _CURSOR_KEY, min(day + timedelta(days=1), today).isoformat())
        day += timedelta(days=1)

    days_left = (today - day).days + 1 if stopped != "done" else 0
    log.info("VulnCheck delta %s: %d days done, %d left, %d rows written",
             stopped, days_done, days_left, written)
    return DeltaResult(written, days_done, days_left, stopped)


# ── orchestration ─────────────────────────────────────────────────────────────

def refresh(db: Session) -> dict:
    """Seed once (if not yet seeded) then run the VulnCheck delta. Returns a
    small stats dict (`stopped` is the run's finish reason). Called by the
    scheduler and the manual trigger."""
    stats = {"seeded": 0, "delta": 0, "days_done": 0, "days_left": 0, "stopped": "done"}
    if _get_setting(db, _SEEDED_KEY) != "1":
        stats["seeded"] = seed_from_vulncheck_backup(db)
    delta = delta_from_vulncheck(db)
    stats.update(delta=delta.written, days_done=delta.days_done,
                 days_left=delta.days_left, stopped=delta.stopped)
    # Only a run that reached today refreshed the index.
    if delta.stopped == "done":
        _set_setting(db, _LAST_REFRESH_KEY, datetime.now(timezone.utc).isoformat())
    return stats
