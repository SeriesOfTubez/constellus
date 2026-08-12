"""
EPSS score history service.

Maintains the epss_history hypertable — one row per (cve_id, calendar day).
Queried by:
  - cve_enrichment: seeds today's sample + backfills 12 weekly points for new CVEs
  - scheduler: 12h periodic refresh for all CVEs currently in active findings
  - findings API: GET /findings/{id}/epss-history (weekly chart + delta)

FIRST.org publishes one data set per calendar day. We poll every 12h to
catch same-day updates quickly; the PK deduplicates to one row per day.
"""

import logging
from datetime import date, datetime, time, timedelta, timezone
from typing import Sequence

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.connectors.http import connector_get

log = logging.getLogger(__name__)

_EPSS_URL = "https://api.first.org/data/v1/epss"
_BACKFILL_WEEKS = 12
_CHUNK = 100


# ── public API ────────────────────────────────────────────────────────────────

def upsert_current(db: Session, cve_ids: Sequence[str]) -> int:
    """Fetch today's EPSS for cve_ids and upsert into epss_history."""
    if not cve_ids:
        return 0
    rows = _fetch_for_date([c.upper() for c in cve_ids], target_date=None)
    return _upsert_rows(db, rows)


def backfill(db: Session, cve_ids: Sequence[str]) -> int:
    """Fetch 12 weekly-spaced historical dates and upsert. Safe to call
    multiple times — the PK deduplicates, so re-runs are cheap no-ops."""
    if not cve_ids:
        return 0
    cve_list = [c.upper() for c in cve_ids]
    today = date.today()
    total = 0
    for week in range(1, _BACKFILL_WEEKS + 1):
        target = today - timedelta(weeks=week)
        rows = _fetch_for_date(cve_list, target_date=target)
        total += _upsert_rows(db, rows)
    log.info(
        "EPSS backfill: %d rows for %d CVEs over %d weeks",
        total, len(cve_list), _BACKFILL_WEEKS,
    )
    return total


def refresh_all_active(db: Session) -> int:
    """Upsert today's sample for every CVE referenced by any finding.
    Called by the 12h scheduler job."""
    from app.models.finding_canonical import FindingCanonical

    cve_ids = [
        row[0]
        for row in db.query(FindingCanonical.cve_id)
        .filter(FindingCanonical.cve_id.isnot(None))
        .distinct()
        .all()
    ]
    if not cve_ids:
        return 0
    log.info("EPSS history refresh: %d unique CVEs", len(cve_ids))
    return upsert_current(db, cve_ids)


def cves_without_history(db: Session, cve_ids: Sequence[str]) -> list[str]:
    """Return the subset of cve_ids that have no rows in epss_history yet.
    Used by cve_enrichment to trigger backfill only for new CVEs."""
    upper = [c.upper() for c in cve_ids]
    if not upper:
        return []
    existing = {
        row[0]
        for row in db.execute(
            text("SELECT DISTINCT cve_id FROM epss_history WHERE cve_id = ANY(:ids)"),
            {"ids": upper},
        ).fetchall()
    }
    return [c for c in upper if c not in existing]


def get_history(db: Session, cve_id: str) -> dict:
    """Return weekly chart data + current score + daily delta for one CVE.

    Response shape:
      {cve_id, current_score, current_percentile, delta,
       history: [{week_start, epss_score, epss_percentile}]}

    history is ordered most-recent first (12 points max).
    delta is (current − previous daily sample), None if < 2 samples.
    """
    cve_upper = cve_id.upper()
    cutoff = datetime.now(timezone.utc) - timedelta(weeks=_BACKFILL_WEEKS)

    weekly = db.execute(
        text("""
            SELECT DISTINCT ON (DATE_TRUNC('week', recorded_date))
                DATE_TRUNC('week', recorded_date)::date AS week_start,
                epss_score,
                epss_percentile
            FROM epss_history
            WHERE cve_id = :cve_id AND recorded_date >= :cutoff
            ORDER BY DATE_TRUNC('week', recorded_date) DESC, recorded_date DESC
        """),
        {"cve_id": cve_upper, "cutoff": cutoff},
    ).fetchall()

    recent = db.execute(
        text("""
            SELECT epss_score, epss_percentile
            FROM epss_history
            WHERE cve_id = :cve_id
            ORDER BY recorded_date DESC
            LIMIT 2
        """),
        {"cve_id": cve_upper},
    ).fetchall()

    current_score = float(recent[0].epss_score) if recent else None
    current_percentile = float(recent[0].epss_percentile) if recent else None
    delta: float | None = None
    if len(recent) >= 2:
        delta = round(float(recent[0].epss_score) - float(recent[1].epss_score), 6)

    # Most recent date the score changed value (vs its preceding sample).
    # Unreliable on backfill-only data (weekly snapshots, not daily); resolves
    # naturally once daily samples accumulate past the weekly points.
    changed_row = db.execute(
        text("""
            WITH ranked AS (
                SELECT
                    recorded_date,
                    epss_score,
                    LAG(epss_score) OVER (ORDER BY recorded_date ASC) AS prev_score
                FROM epss_history
                WHERE cve_id = :cve_id
            )
            SELECT recorded_date::date AS changed_date
            FROM ranked
            WHERE prev_score IS NULL OR epss_score != prev_score
            ORDER BY recorded_date DESC
            LIMIT 1
        """),
        {"cve_id": cve_upper},
    ).fetchone()
    score_changed_date: str | None = str(changed_row.changed_date) if changed_row else None

    return {
        "cve_id": cve_upper,
        "current_score": current_score,
        "current_percentile": current_percentile,
        "delta": delta,
        "score_changed_date": score_changed_date,
        "history": [
            {
                "week_start": str(r.week_start),
                "epss_score": float(r.epss_score),
                "epss_percentile": float(r.epss_percentile),
            }
            for r in weekly
        ],
    }


# ── internals ─────────────────────────────────────────────────────────────────

def _fetch_for_date(cve_ids: list[str], target_date: date | None) -> list[dict]:
    """Fetch EPSS from FIRST.org for the given date (None = today).
    Returns list of row dicts ready for _upsert_rows."""
    base_params: dict = {}
    if target_date is not None:
        base_params["date"] = target_date.isoformat()

    results: list[dict] = []
    for i in range(0, len(cve_ids), _CHUNK):
        chunk = cve_ids[i : i + _CHUNK]
        try:
            resp = connector_get(
                _EPSS_URL,
                params={"cve": ",".join(chunk), **base_params},
                timeout=20,
            )
            resp.raise_for_status()
            payload = resp.json()
            for item in payload.get("data", []):
                raw_date = item.get("date") or (
                    target_date.isoformat() if target_date else date.today().isoformat()
                )
                results.append({
                    "cve_id": item["cve"].upper(),
                    "recorded_date": _midnight_utc(date.fromisoformat(raw_date)),
                    "epss_score": float(item["epss"]),
                    "epss_percentile": float(item["percentile"]),
                })
        except Exception:
            log.warning(
                "EPSS history fetch failed (chunk offset=%d, date=%s)",
                i, target_date,
                exc_info=True,
            )
    return results


def _midnight_utc(d: date) -> datetime:
    return datetime.combine(d, time.min, tzinfo=timezone.utc)


def _upsert_rows(db: Session, rows: list[dict]) -> int:
    if not rows:
        return 0
    db.execute(
        text("""
            INSERT INTO epss_history (cve_id, recorded_date, epss_score, epss_percentile)
            VALUES (:cve_id, :recorded_date, :epss_score, :epss_percentile)
            ON CONFLICT (cve_id, recorded_date) DO UPDATE
                SET epss_score      = EXCLUDED.epss_score,
                    epss_percentile = EXCLUDED.epss_percentile
        """),
        rows,
    )
    db.commit()
    return len(rows)
