"""A finding's exposure timeline (planning#360): the dates we hold, as events.

Schema and semantics in `schemas/finding_timeline.py`. Reads only what the
caller passes: the finding, its CVE record, the attribution the detail route
already built (never a second walk, so the read scope is the attribution's)
and the BOD due date from the same response.
"""

from datetime import date, datetime, time, timezone

from sqlalchemy.orm import Session

from app.models.cve_record import CveRecord
from app.models.finding_canonical import FindingCanonical
from app.schemas.attribution_chain import Attribution, EntityHop, RelationEvidence, ScopeHop
from app.schemas.finding_timeline import TimelineDate, TimelineEvent

# Higher is more precise. "unknown" is not here: a row without a known date
# gives no date.
_PRECISION_RANK = {"year": 0, "month": 1, "day": 2}


def cve_record_for(db: Session, finding: FindingCanonical) -> CveRecord | None:
    if not finding.cve_id:
        return None
    return db.get(CveRecord, finding.cve_id.strip().upper())


def _utc(at: datetime) -> datetime:
    return at.astimezone(timezone.utc) if at.tzinfo else at.replace(tzinfo=timezone.utc)


def _stamped(kind: str, at: datetime | None, source: str | None = None, **subject) -> TimelineEvent | None:
    if at is None:
        return None
    at = _utc(at)
    return TimelineEvent(kind=kind, date=at.date(), precision="day", at=at, source=source, **subject)


def _dated(kind: str, day: date | None, source: str) -> TimelineEvent | None:
    if day is None:
        return None
    return TimelineEvent(kind=kind, date=day, precision="day", source=source)


def _acquisitions(attribution: Attribution) -> list[TimelineEvent]:
    """One event per distinct acquisition on the chains: an entity hop whose
    relation to the hop above is `acquired`. Dated by its most precise row
    (ties: the earliest date); the other dated rows that differ ride along."""
    out: dict[tuple, TimelineEvent] = {}
    for chain in attribution.chains:
        for above, hop in zip(chain.hops, chain.hops[1:]):
            if not isinstance(hop, EntityHop) or hop.relation != "acquired":
                continue
            acquirer_id = getattr(above, "entity_id", None)
            key = (hop.entity_id, acquirer_id)
            if key in out:
                continue
            rows = [
                e for e in hop.evidence
                if isinstance(e, RelationEvidence)
                and e.relation == "acquired"
                and e.event_date is not None
                and e.event_date_precision in _PRECISION_RANK
            ]
            if not rows:
                continue
            rows.sort(key=lambda e: (-_PRECISION_RANK[e.event_date_precision], e.event_date, str(e.relation_id)))
            best = rows[0]
            others: list[TimelineDate] = []
            seen = {(best.event_date, best.event_date_precision)}
            for e in rows[1:]:
                if (e.event_date, e.event_date_precision) in seen:
                    continue
                seen.add((e.event_date, e.event_date_precision))
                others.append(TimelineDate(date=e.event_date, precision=e.event_date_precision, source=e.source))
            out[key] = TimelineEvent(
                kind="acquired",
                date=best.event_date,
                precision=best.event_date_precision,
                source=best.source,
                entity_id=hop.entity_id,
                entity_name=hop.name,
                acquirer_id=acquirer_id,
                other_dates=others,
            )
    return list(out.values())


def _claims(attribution: Attribution) -> list[TimelineEvent]:
    """One event per claimed scope on the chains."""
    out: dict = {}
    for chain in attribution.chains:
        for hop in chain.hops:
            if isinstance(hop, ScopeHop) and hop.claimed_at is not None and hop.target_id not in out:
                out[hop.target_id] = _stamped(
                    "claimed", hop.claimed_at, target_id=hop.target_id, target_value=hop.value
                )
    return list(out.values())


def _sort_key(event: TimelineEvent) -> tuple:
    at = event.at or datetime.combine(event.date, time.min, tzinfo=timezone.utc)
    return (event.date, at, event.kind, str(event.entity_id or event.target_id or ""))


def build_timeline(
    finding: FindingCanonical,
    cve_record: CveRecord | None,
    attribution: Attribution | None,
    due_date: str | None,
) -> list[TimelineEvent]:
    events = [
        _stamped(
            "cve_published",
            cve_record.published_at if cve_record else None,
            cve_record.published_source if cve_record else None,
        ),
        _dated("listed_exploited_cisa", finding.kev_date_added, "cisa_kev"),
        _dated(
            "listed_exploited_vulncheck",
            cve_record.vulncheck_kev_date_added if cve_record else None,
            "vulncheck_kev",
        ),
        _stamped("first_seen", finding.first_seen_at),
        _stamped("ownership_confirmed", finding.ownership_confirmed_at),
        _dated("due", date.fromisoformat(due_date) if due_date else None, "fix_window"),
    ]
    if attribution is not None:
        events += _acquisitions(attribution) + _claims(attribution)
    return sorted((e for e in events if e is not None), key=_sort_key)
