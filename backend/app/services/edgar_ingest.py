"""app.services.edgar_ingest — SEC EDGAR submissions ingest (planning#213,
L4 slice 1).

Given a CIK, pulls `data.sec.gov`'s submissions JSON (plus any paged
`filings.files[]` continuation) and writes two kinds of rows, EACH through
the one function that is allowed to write it:

  - `formerNames` entries become `formerly_named` `EntityRelation` rows,
    written ONLY through `entity_graph.assert_relation` — never a raw
    insert, so the "auto-confirm requires a granted observer, never a
    status set by the caller" invariant (migration 0061) holds here exactly
    as it does for every other writer of that table.
  - 8-K / 8-K/A filings whose item list intersects `LINEAGE_ITEMS` become
    `EntityFilingEvent` rows — an EVENT, never a relation. **Decided,
    2026-09-24 (see planning#213's decisions comment): the submissions JSON
    has no counterparty, and item 2.01 means "completion of acquisition OR
    disposition", so there is no object entity and no direction to assert.
    A person, or #214/#215, supplies the counterparty later.**

`www.sec.gov` is never fetched by this slice — only `data.sec.gov`, via
`app.services.sec_edgar`. Full-text search, the 10-K Business Combinations
footnote and the target's own EX-21 diff are explicitly OUT of scope here
(slice 2, an ungranted observer — a heuristic parse is proposed-only, never
auto-confirmed the way this slice's SEC-filing observer is).

## Former-name entity reuse is scoped and exact — read this before touching
   step 4 below

The object of a `formerly_named` relation is reused ONLY when a row already
exists with the EXACT tuple (this CIK's entity as subject, relation=
`formerly_named`, THIS observer, object's `legal_name` byte-identical to
the candidate name) — regardless of that row's `status` or `evidence_id`.
This is not a deduplication nicety; it is load-bearing. The submissions
JSON changes shape every time a new filing lands, so a naive
"insert-if-new-evidence" ingest would, on every re-ingest, see "new
evidence, no relation from THIS evidence yet" and insert a fresh
auto-confirmed row for a former name a person had already REJECTED —
silently undoing that person's decision every time SEC publishes a filing.
The scoped-existence check makes the object lookup keyed on the relation
tuple, not on the evidence, so a rejected row's mere existence (any status)
suppresses a repeat insert forever. `test_edgar_ingest.py`'s
`test_person_rejected_relation_survives_reingest` is written to FAIL if
this skip is removed (see mutation M1 in the spec's mutation table).

There is no OTHER name lookup anywhere in this module — no global
`legal_name` search, no cross-CIK matching. Two different CIKs sharing a
former name always get two distinct former-name `OrgEntity` rows.

## Posture — through `observer_permitted`, never around it

Both seeded observers are `noise_class = 'silent'` (the query goes to the
SEC, never the counterparty), so `posture.observer_permitted` never denies
either of them today. This module still calls it, per-observer, for every
ingest — not because today's answer is ever `False`, but because "AI raises
attention, never scope, never lowers" applies to code paths as much as to
individual decisions: a future noise-class change or a future posture value
must not have to be re-wired into this module to take effect. If BOTH
observers are denied, `ingest_cik` makes no HTTP request at all.

## `SEC_USER_AGENT` — required, validated here, never in `Settings`

`require_user_agent()` lives here rather than on `app.core.config.Settings`
so a missing/invalid value never blocks ordinary app startup (`Settings()`
constructs regardless) — it only blocks the one code path that needs it,
and it blocks it BEFORE any HTTP request, not after a wasted round trip.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.engagement import Engagement
from app.models.entity_filing_event import EntityFilingEvent
from app.models.entity_relation import EntityRelation
from app.models.observer import Observer
from app.models.org_entity import OrgEntity
from app.services import entity_graph, posture, sec_edgar

log = logging.getLogger(__name__)

# Module-level observer-name constants (this module IS the code the #198
# lesson says to seed observers alongside — see migration 0062's docstring).
# No existing `*_OBSERVERS` constant precedent was found elsewhere in this
# codebase for a module owning more than one observer, so these follow the
# established single-observer `_OBSERVER_NAME` pattern (e.g.
# `hosting_classifier._OBSERVER_NAME`), just two of them, public because the
# API layer (`app/api/entities.py`'s posture test hook) needs to name one.
OBSERVER_FORMER_NAMES = "edgar_former_names"
OBSERVER_8K_ITEMS = "edgar_8k_items"

# 2.01 = Completion of Acquisition or Disposition of Assets (covers BOTH
# directions — this is exactly why an 8-K becomes an event, not a labelled
# relation). 5.01 = Change in Control of Registrant — the FILER was the one
# absorbed or spun off. Item 1.01 (Entry into a Material Definitive
# Agreement) is deliberately excluded: material agreements include credit
# facilities and routine commercial contracts, so it is noise for lineage
# purposes (planning#213 decisions comment, 2026-09-24).
LINEAGE_ITEMS: frozenset[str] = frozenset({"2.01", "5.01"})

_CIK_INPUT_RE = re.compile(r"^[0-9]{1,10}$")
_ACCESSION_RE = re.compile(r"^[0-9]{10}-[0-9]{2}-[0-9]{6}$")

_UA_MAX_LEN = 200


class EdgarNotConfigured(Exception):
    """`SEC_USER_AGENT` is unset or fails validation. Raised before any I/O."""


class EdgarObserversMissing(Exception):
    """One or both seeded observers (migration 0062) are missing. Fails
    closed — this module never creates them on the fly."""


@dataclass
class IngestResult:
    entity_id: uuid.UUID | None
    pages_fetched: int = 0
    former_names_asserted: int = 0
    former_names_skipped: int = 0
    events_inserted: int = 0
    events_existing: int = 0
    malformed_skipped: int = 0
    denied: list[str] = field(default_factory=list)


def normalise_cik(cik: str) -> str:
    """`^[0-9]{1,10}$`, then zero-padded to 10 digits. Anything else raises
    `ValueError`. Public (not `_normalise_cik`) because `app/api/entities.py`
    validates synchronously before returning 422, and calling a private
    helper across a module boundary is worse than naming it properly."""
    if not isinstance(cik, str) or not _CIK_INPUT_RE.match(cik):
        raise ValueError(f"cik must be 1 to 10 digits, got {cik!r}")
    return cik.zfill(10)


def require_user_agent() -> None:
    """Valid means: set, non-empty after strip, contains '@', length <= 200,
    no CR/LF. Raises `EdgarNotConfigured` otherwise. Public for the same
    reason as `normalise_cik` — the API layer calls this synchronously
    before accepting a request."""
    ua = settings.sec_user_agent
    if ua is None:
        raise EdgarNotConfigured(
            "SEC_USER_AGENT is not set. SEC EDGAR ingest refuses to run without a "
            "descriptive contact string (SEC fair-access policy)."
        )
    if "\r" in ua or "\n" in ua:
        raise EdgarNotConfigured("SEC_USER_AGENT must not contain CR or LF.")
    stripped = ua.strip()
    if not stripped or "@" not in stripped or len(stripped) > _UA_MAX_LEN:
        raise EdgarNotConfigured(
            "SEC_USER_AGENT is set but invalid: it must be non-empty after "
            "stripping, contain '@', and be at most 200 characters."
        )


def _parse_event_date(raw: str | None) -> tuple[date | None, str]:
    if not raw:
        return None, "unknown"
    try:
        return datetime.strptime(raw, "%Y-%m-%d").date(), "day"
    except (ValueError, TypeError):
        return None, "unknown"


def _load_observer(db: Session, name: str) -> Observer | None:
    return db.execute(select(Observer).where(Observer.name == name)).scalar_one_or_none()


def _existing_entity_by_cik(db: Session, cik: str) -> OrgEntity | None:
    return db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one_or_none()


def _is_passive_only_for_entity(db: Session, entity: OrgEntity | None) -> bool:
    """`entity` may be `None` (the CIK has never been ingested before) —
    that is the ordinary case for a first ingest, and it means "nothing to
    restrict" (no engagement can point at an entity that does not exist
    yet), matching `posture.posture_restricts(None) == False`."""
    if entity is None:
        return False
    engagements: Iterable[Engagement] = db.execute(
        select(Engagement).where(Engagement.subject_entity_id == entity.id)
    ).scalars().all()
    return any(posture.posture_restricts(e.posture) for e in engagements)


def _process_former_names(
    db: Session,
    *,
    entity: OrgEntity,
    current_name: str,
    former_names: list[dict],
    observer: Observer,
    main_evidence_id: uuid.UUID,
    result: IngestResult,
) -> None:
    for entry in former_names:
        name = (entry.get("name") or "").strip()
        if not name or name == current_name:
            result.former_names_skipped += 1
            continue

        # ── the scoped, exact reuse lookup (see module docstring) ──────────
        # Load-bearing: ANY existing row on this exact tuple — regardless of
        # its status or evidence — suppresses a repeat insert. This is what
        # keeps a person's rejection from being silently re-proposed on the
        # next re-ingest (mutation M1 removes this and must fail a test).
        already = db.execute(
            select(EntityRelation.id)
            .join(OrgEntity, EntityRelation.object_id == OrgEntity.id)
            .where(
                EntityRelation.subject_id == entity.id,
                EntityRelation.relation == "formerly_named",
                EntityRelation.observer_id == observer.id,
                OrgEntity.legal_name == name,
            )
        ).first()
        if already is not None:
            result.former_names_skipped += 1
            continue

        former_entity = OrgEntity(id=uuid.uuid4(), legal_name=name, cik=None)
        db.add(former_entity)
        db.commit()

        event_date, precision = _parse_event_date(entry.get("to"))
        entity_graph.assert_relation(
            db,
            subject_id=entity.id,
            object_id=former_entity.id,
            relation="formerly_named",
            observer_id=observer.id,
            evidence_id=main_evidence_id,
            quote=json.dumps(entry, sort_keys=True, separators=(",", ":")),
            event_date=event_date,
            event_date_precision=precision,
        )
        result.former_names_asserted += 1


def _process_filing_array(
    db: Session,
    *,
    entity: OrgEntity,
    observer: Observer,
    evidence_id: uuid.UUID,
    array: dict,
    result: IngestResult,
) -> None:
    forms = array.get("form") or []
    accessions = array.get("accessionNumber") or []
    filing_dates = array.get("filingDate") or []
    items_list = array.get("items") or []
    n = min(len(forms), len(accessions), len(filing_dates), len(items_list))

    for i in range(n):
        form = forms[i]
        if form not in ("8-K", "8-K/A"):
            continue
        item_set = set((items_list[i] or "").split(","))
        if not (item_set & LINEAGE_ITEMS):
            continue

        accession = accessions[i]
        if not isinstance(accession, str) or not _ACCESSION_RE.match(accession):
            result.malformed_skipped += 1
            continue

        try:
            filing_date_val = datetime.strptime(filing_dates[i], "%Y-%m-%d").date()
        except (ValueError, TypeError):
            # Not spelled out in the spec's malformed-row handling, which
            # only names the accession CHECK — but `filing_date` is NOT
            # NULL with no CHECK of its own, so an unparseable date would
            # otherwise raise inside the INSERT rather than being counted
            # and skipped like every other malformed row. Same conservative
            # treatment as the accession check, documented in the report's
            # answer 3 (a decision the spec did not make).
            result.malformed_skipped += 1
            continue

        inserted_id = db.execute(
            pg_insert(EntityFilingEvent.__table__)
            .values(
                id=uuid.uuid4(),
                entity_id=entity.id,
                observer_id=observer.id,
                evidence_id=evidence_id,
                form=form,
                accession_number=accession,
                filing_date=filing_date_val,
                items=items_list[i],
            )
            .on_conflict_do_nothing(constraint="uq_entity_filing_events_entity_accession")
            .returning(EntityFilingEvent.id)
        ).scalar()
        db.commit()
        if inserted_id is not None:
            result.events_inserted += 1
        else:
            result.events_existing += 1


def ingest_cik(db: Session, cik: str) -> IngestResult:
    """Fetch and ingest one CIK's submissions JSON. Never touches
    `targets`, domains or scans, and never maps a name to an entity except
    the scoped lookup in `_process_former_names`."""
    normalised_cik = normalise_cik(cik)
    require_user_agent()

    former_names_observer = _load_observer(db, OBSERVER_FORMER_NAMES)
    events_observer = _load_observer(db, OBSERVER_8K_ITEMS)
    if former_names_observer is None or events_observer is None:
        raise EdgarObserversMissing(
            f"seeded observers {OBSERVER_FORMER_NAMES!r}/{OBSERVER_8K_ITEMS!r} not found "
            "(migration 0062 not applied?) — refusing rather than creating them on the fly."
        )

    existing_entity = _existing_entity_by_cik(db, normalised_cik)
    passive_only = _is_passive_only_for_entity(db, existing_entity)

    former_names_permitted = posture.observer_permitted(
        passive_only=passive_only, noise_class=former_names_observer.noise_class
    )
    events_permitted = posture.observer_permitted(
        passive_only=passive_only, noise_class=events_observer.noise_class
    )

    denied: list[str] = []
    if not former_names_permitted:
        denied.append(former_names_observer.name)
    if not events_permitted:
        denied.append(events_observer.name)

    result = IngestResult(entity_id=existing_entity.id if existing_entity else None, denied=denied)

    if not former_names_permitted and not events_permitted:
        # Both signals denied — no HTTP request at all.
        return result

    content, content_type, fetched_at, url = sec_edgar.fetch_submissions(normalised_cik)
    main_fetch = entity_graph.store_evidence(
        db, content=content, content_type=content_type, source_url=url, fetched_at=fetched_at
    )
    data = json.loads(content)
    current_name = data["name"]

    # ── entity upsert — never updates an existing row's legal_name ─────────
    db.execute(
        pg_insert(OrgEntity.__table__)
        .values(id=uuid.uuid4(), legal_name=current_name, cik=normalised_cik)
        .on_conflict_do_nothing(constraint="uq_org_entities_cik")
    )
    db.commit()
    entity = db.execute(select(OrgEntity).where(OrgEntity.cik == normalised_cik)).scalar_one()
    result.entity_id = entity.id

    # ── paged filings.files[] — fetched only if the events signal is
    # permitted: the pages exist solely to extend 8-K item coverage past
    # `filings.recent`, and formerNames never needs them. Not spelled out in
    # the spec (which says "fetch each files[] page" unconditionally except
    # when BOTH signals are denied) — a deliberate, more conservative
    # reading, documented in the report's answer 3.
    pages: list[tuple[dict, uuid.UUID]] = []
    if events_permitted:
        for file_entry in (data.get("filings", {}).get("files") or []):
            name = file_entry.get("name")
            page_content, page_content_type, page_fetched_at, page_url = sec_edgar.fetch_submissions_page(name)
            page_fetch = entity_graph.store_evidence(
                db, content=page_content, content_type=page_content_type, source_url=page_url, fetched_at=page_fetched_at
            )
            pages.append((json.loads(page_content), page_fetch.id))
            result.pages_fetched += 1

    if former_names_permitted:
        _process_former_names(
            db,
            entity=entity,
            current_name=current_name,
            former_names=data.get("formerNames") or [],
            observer=former_names_observer,
            main_evidence_id=main_fetch.id,
            result=result,
        )

    if events_permitted:
        recent = data.get("filings", {}).get("recent") or {}
        _process_filing_array(
            db, entity=entity, observer=events_observer, evidence_id=main_fetch.id, array=recent, result=result
        )
        for page_data, page_evidence_id in pages:
            _process_filing_array(
                db, entity=entity, observer=events_observer, evidence_id=page_evidence_id, array=page_data, result=result
            )

    return result
