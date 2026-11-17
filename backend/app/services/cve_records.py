"""Writes to `cve_records` (planning#360): CVE-level dates kept once per CVE.

Helpers here `flush()`; the caller owns the transaction. A stored date is never
overwritten with NULL (COALESCE on upsert), and a refresh attempt only moves
`refreshed_at` / `refresh_failed`.
"""

from datetime import datetime

from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.cve_record import CveRecord

PUBLISHED_SOURCE = "vulncheck_nvd2"


def upsert_from_signals(db: Session, signals: dict[str, dict], now: datetime) -> None:
    """Insert or update one row per CVE from fetched VulnCheck signal dicts."""
    for raw_id, sig in signals.items():
        published_at = sig.get("published_at")
        kev_added = sig.get("vulncheck_kev_date_added")
        values = {
            "cve_id": raw_id.upper(),
            "published_at": published_at,
            "published_source": PUBLISHED_SOURCE if published_at is not None else None,
            "vulncheck_kev_date_added": kev_added,
            "refreshed_at": now,
            "refresh_failed": False,
        }
        stmt = insert(CveRecord).values(**values)
        excluded = stmt.excluded
        stmt = stmt.on_conflict_do_update(
            index_elements=[CveRecord.cve_id],
            set_={
                # Date and source move together: both from the new value, or both kept.
                "published_at": func.coalesce(excluded.published_at, CveRecord.published_at),
                "published_source": func.coalesce(excluded.published_source, CveRecord.published_source),
                "vulncheck_kev_date_added": func.coalesce(
                    excluded.vulncheck_kev_date_added, CveRecord.vulncheck_kev_date_added
                ),
                "refreshed_at": excluded.refreshed_at,
                "refresh_failed": False,
            },
        )
        db.execute(stmt)
    db.flush()


def mark_failed(db: Session, cve_ids: list[str], now: datetime) -> None:
    """Record a failed refresh attempt without touching any stored date."""
    for raw_id in cve_ids:
        stmt = insert(CveRecord).values(cve_id=raw_id.upper(), refreshed_at=now, refresh_failed=True)
        stmt = stmt.on_conflict_do_update(
            index_elements=[CveRecord.cve_id],
            set_={"refreshed_at": stmt.excluded.refreshed_at, "refresh_failed": True},
        )
        db.execute(stmt)
    db.flush()


def stamp_refreshed(db: Session, cve_ids: list[str], now: datetime) -> None:
    """Record a refresh attempt that fetched nothing (no VulnCheck key): moves
    only `refreshed_at` / `refresh_failed`, never a stored date."""
    for raw_id in cve_ids:
        stmt = insert(CveRecord).values(cve_id=raw_id.upper(), refreshed_at=now, refresh_failed=False)
        stmt = stmt.on_conflict_do_update(
            index_elements=[CveRecord.cve_id],
            set_={"refreshed_at": stmt.excluded.refreshed_at, "refresh_failed": False},
        )
        db.execute(stmt)
    db.flush()
