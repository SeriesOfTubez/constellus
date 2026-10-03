"""Link a CIK-less acquired company to its SEC registrant (planning#236 S1).

The acquisition reader (#218) maps an acquired company by name only, with
no CIK (0061: never merge by name). If that company was ever an SEC
registrant, its own filings carry its website, its EX-21 subsidiaries and
its own acquisitions. This module lets a PERSON say which registrant it is.
Decisions (Jason, 2026-10-02, the two decisions comments on #236):

- **Never automatic**, not even on an exact name: the 2026-09-27 probe's
  name search returned unrelated registrants. Search results and the
  filing-date span are hints for the person deciding.
- **Gate:** ADMIN (at the API), and only on an entity that has no CIK and
  is the object of a CONFIRMED `acquired` edge. "The deal happened" and
  "this is that registrant" stay two separately audited decisions, and
  anything linked is accept-ready through #240's inheritance.
- **Shape:** the CIK is set on the EXISTING entity, so the confirmed edge
  still reaches it and the ingest (which resolves its entity by CIK)
  attaches its output there. A CIK already on another entity is refused
  and that entity named: merging entities is its own design.
- **Afterwards, automatically:** the EDGAR ingest (#213/#216), then the AI
  acquisition read (#218) if the ingest stored a Business Combinations
  section. The read takes its data policy from `entity_relationship.
  ai_scope` on THIS entity (it does so itself). It only proposes: each
  further level of recursion needs another person-confirmed link.
- **Undo:** `unlink`, refused while a run for the CIK is active or once a
  person has confirmed or accepted anything the link produced.

## What "the link produced" means — `unlink`

Before a link the entity has no CIK, so nothing can have run on it, and no
endpoint writes a relation directly. Everything below therefore came from
runs on the linked CIK, identified by the entity's ROLE in it:

- relations where the entity is the subject of `formerly_named` /
  `acquired` (its own former names and its own acquisitions), or the
  object of `subsidiary_of` (its EX-21 subsidiaries). Its INCOMING
  `acquired` edge (the deal) is the reverse role and is never touched.
- candidate domains on the entity with source `edgar_10k_website`. A
  domain a person added by hand (source `person`) is not the link's.
- its filing events, filing sections and subsidiary listings.

Proposed and SOURCE-confirmed relations (former names auto-confirm) are
rejected by the unlinking person; proposed candidates likewise. A
person-confirmed relation or an accepted candidate refuses the unlink:
someone decided on the strength of this registrant, and that decision must
be undone first. Rows a person already rejected stay as they are. Filing
rows are deleted so a later AI read cannot re-read the wrong company.
Evidence fetches stay (append-only evidence), and so do the run rows.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.candidate_domain import CandidateDomain
from app.models.entity_filing_event import EntityFilingEvent
from app.models.entity_filing_section import EntityFilingSection
from app.models.entity_ingest_run import INGEST_RUN_ACTIVE, EntityIngestRun
from app.models.entity_relation import EntityRelation
from app.models.entity_subsidiary_listing import EntitySubsidiaryListing
from app.models.org_entity import OrgEntity
from app.services import acquisition_reader, edgar_ingest, llm_connector, sec_edgar
from app.services.entity_names import split_defined_term, strip_legal_suffix

MAX_CANDIDATES = 10

_DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}")
WEBSITE_SOURCE = "edgar_10k_website"


class LinkError(Exception):
    pass


class LinkNotFound(LinkError):
    pass


class LinkConflict(LinkError):
    pass


class LinkInvalid(LinkError):
    pass


class CikTaken(LinkConflict):
    """The CIK is already on another entity (`uq_org_entities_cik`)."""

    def __init__(self, entity: OrgEntity):
        super().__init__("that CIK is already on another mapped company")
        self.entity_id = entity.id
        self.legal_name = entity.legal_name


@dataclass
class Deal:
    acquirer_id: uuid.UUID
    acquirer_name: str
    event_date: str | None
    precision: str


@dataclass
class LinkContext:
    eligible: bool
    reason: str | None
    linked: bool
    suggested_query: str
    deals: list[Deal] = field(default_factory=list)


@dataclass
class RegistrantFacts:
    """What a person sees before confirming, and what the audit records."""
    cik: str
    name: str
    state_of_incorporation: str | None
    sic: str | None
    sic_description: str | None
    former_names: list[dict]
    first_filing: str | None
    last_filing: str | None
    annual_reports: int
    first_annual_report: str | None
    last_annual_report: str | None
    # True when older filings live in paged files this summary did not
    # fetch: the annual-report count/range then covers recent filings only.
    annual_reports_partial: bool
    taken_by_id: uuid.UUID | None = None
    taken_by_name: str | None = None

    def as_dict(self) -> dict:
        d = asdict(self)
        d["taken_by_id"] = str(self.taken_by_id) if self.taken_by_id else None
        return d


# ── reading ──────────────────────────────────────────────────────────────────

def _date(value) -> str | None:
    return value[:10] if isinstance(value, str) and _DATE_RE.match(value) else None


def _text(value) -> str | None:
    return value.strip() or None if isinstance(value, str) else None


def summarise_submissions(data: dict) -> RegistrantFacts:
    """Facts from a submissions JSON, defensively: a missing or malformed
    field is None, never an exception. `fetch_submissions` has already
    checked the shape of `filings.recent`."""
    recent = (data.get("filings") or {}).get("recent") or {}
    forms = recent.get("form") or []
    dates = [_date(d) for d in (recent.get("filingDate") or [])]
    files = (data.get("filings") or {}).get("files") or []

    all_dates = [d for d in dates if d]
    for f in files:
        if isinstance(f, dict):
            all_dates.extend(d for d in (_date(f.get("filingFrom")), _date(f.get("filingTo"))) if d)
    annual = sorted(
        d for form, d in zip(forms, dates) if d and form in edgar_ingest.ANNUAL_REPORT_FORMS
    )
    former = []
    for entry in data.get("formerNames") or []:
        if isinstance(entry, dict) and _text(entry.get("name")):
            former.append({"name": _text(entry.get("name")), "from": _date(entry.get("from")), "to": _date(entry.get("to"))})

    cik_raw = data.get("cik")
    cik = str(cik_raw).zfill(10) if isinstance(cik_raw, (str, int)) and str(cik_raw).isdigit() else ""
    return RegistrantFacts(
        cik=cik,
        name=_text(data.get("name")) or "",
        state_of_incorporation=_text(data.get("stateOfIncorporation")),
        sic=_text(data.get("sic")),
        sic_description=_text(data.get("sicDescription")),
        former_names=former,
        first_filing=min(all_dates) if all_dates else None,
        last_filing=max(all_dates) if all_dates else None,
        annual_reports=len(annual),
        first_annual_report=annual[0] if annual else None,
        last_annual_report=annual[-1] if annual else None,
        annual_reports_partial=bool(files),
    )


def _incoming_deals(db: Session, entity_id: uuid.UUID) -> list[Deal]:
    rows = db.execute(
        select(EntityRelation, OrgEntity)
        .join(OrgEntity, OrgEntity.id == EntityRelation.subject_id)
        .where(
            EntityRelation.object_id == entity_id,
            EntityRelation.relation == "acquired",
            EntityRelation.status == "confirmed",
        )
        .order_by(EntityRelation.created_at.asc())
    ).all()
    return [
        Deal(
            acquirer_id=acquirer.id, acquirer_name=acquirer.legal_name,
            event_date=rel.event_date.isoformat() if rel.event_date else None, precision=rel.event_date_precision,
        )
        for rel, acquirer in rows
    ]


def suggested_query(legal_name: str) -> str:
    """The entity's name without a trailing defined term or legal suffix:
    EDGAR matches by prefix, and the suffix is where spellings differ."""
    base, _short = split_defined_term(legal_name)
    return (strip_legal_suffix(base) or base).strip()[:100]


def context(db: Session, entity_id: uuid.UUID) -> LinkContext:
    entity = db.get(OrgEntity, entity_id)
    if entity is None:
        raise LinkNotFound("entity not found")
    deals = _incoming_deals(db, entity_id)
    linked = entity.registrant_linked_at is not None
    reason = None
    if entity.cik is not None:
        reason = "this company already has a CIK"
    elif not deals:
        reason = "only a company whose acquisition has been confirmed can be linked to a registrant"
    return LinkContext(
        eligible=reason is None, reason=reason, linked=linked,
        suggested_query=suggested_query(entity.legal_name), deals=deals,
    )


def _require_eligible(db: Session, entity_id: uuid.UUID) -> None:
    ctx = context(db, entity_id)
    if not ctx.eligible:
        raise LinkConflict(ctx.reason)


def _facts_for(db: Session, cik10: str) -> RegistrantFacts:
    content, _ct, _at, _url = sec_edgar.fetch_submissions(cik10)
    facts = summarise_submissions(json.loads(content))
    facts.cik = cik10
    holder = db.query(OrgEntity).filter(OrgEntity.cik == cik10).one_or_none()
    if holder is not None:
        facts.taken_by_id, facts.taken_by_name = holder.id, holder.legal_name
    return facts


def search(db: Session, *, entity_id: uuid.UUID, query: str, contains: bool = False) -> list[RegistrantFacts]:
    """Up to `MAX_CANDIDATES` registrants for a name query, each with its
    facts (one submissions fetch each). A CIK EDGAR lists but no longer
    serves (404) is dropped; any other fetch failure propagates."""
    _require_eligible(db, entity_id)
    edgar_ingest.require_user_agent()
    try:
        ciks = sec_edgar.search_companies(query, contains=contains)
    except ValueError as exc:
        raise LinkInvalid(str(exc))
    out: list[RegistrantFacts] = []
    for cik in ciks[:MAX_CANDIDATES]:
        try:
            out.append(_facts_for(db, cik))
        except sec_edgar.SecNotFound:
            continue
    return out


def preview(db: Session, *, entity_id: uuid.UUID, cik: str) -> RegistrantFacts:
    _require_eligible(db, entity_id)
    edgar_ingest.require_user_agent()
    try:
        cik10 = edgar_ingest.normalise_cik(cik)
    except ValueError:
        raise LinkInvalid("cik must be 1 to 10 digits")
    try:
        return _facts_for(db, cik10)
    except sec_edgar.SecNotFound:
        raise LinkInvalid("SEC has no registrant with that CIK")


# ── the link ─────────────────────────────────────────────────────────────────

def _active_run(db: Session, cik10: str) -> bool:
    return db.query(EntityIngestRun.id).filter(
        EntityIngestRun.cik == cik10, EntityIngestRun.status.in_(INGEST_RUN_ACTIVE)
    ).first() is not None


def link(db: Session, *, entity_id: uuid.UUID, cik: str, user) -> tuple[OrgEntity, EntityIngestRun, RegistrantFacts]:
    """Set `cik` on the entity and queue its ingest, in one commit. The
    caller runs `EntityIngestRun` through the ingest and `followup_read`.
    The registrant's facts are re-fetched here, not taken from the client,
    so the audit records what SEC said at confirm time."""
    try:
        cik10 = edgar_ingest.normalise_cik(cik)
    except ValueError:
        raise LinkInvalid("cik must be 1 to 10 digits")
    edgar_ingest.require_user_agent()
    _require_eligible(db, entity_id)
    holder = db.query(OrgEntity).filter(OrgEntity.cik == cik10).one_or_none()
    if holder is not None:
        raise CikTaken(holder)
    try:
        facts = _facts_for(db, cik10)
    except sec_edgar.SecNotFound:
        raise LinkInvalid("SEC has no registrant with that CIK")
    db.rollback()  # end the read transaction before taking the row lock

    entity = db.execute(select(OrgEntity).where(OrgEntity.id == entity_id).with_for_update()).scalar_one_or_none()
    if entity is None:
        raise LinkNotFound("entity not found")
    try:
        _require_eligible(db, entity_id)  # again, under the lock
    except LinkError:
        db.rollback()
        raise
    entity.cik = cik10
    entity.registrant_linked_at = datetime.now(timezone.utc)
    entity.registrant_linked_by_id = user.id
    run = EntityIngestRun(cik=cik10, kind="edgar_ingest", status="queued", requested_by_id=user.id)
    db.add(run)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        holder = db.query(OrgEntity).filter(OrgEntity.cik == cik10).one_or_none()
        if holder is not None:
            raise CikTaken(holder)
        if _active_run(db, cik10):
            raise LinkConflict("an ingest for this CIK is already queued or running; link it when that finishes")
        raise
    db.refresh(entity)
    db.refresh(run)
    return entity, run, facts


def followup_read(db: Session, *, entity_id: uuid.UUID, cik10: str, user_id: uuid.UUID | None) -> tuple[EntityIngestRun | None, str | None]:
    """After the link's ingest succeeded: queue the AI acquisition read, or
    say why not. Under the entity's row lock, so an unlink cannot slip
    between the check and the queued run (unlink refuses an active run).
    Returns (run, None) or (None, reason)."""
    entity = db.execute(select(OrgEntity).where(OrgEntity.id == entity_id).with_for_update()).scalar_one_or_none()
    reason = None
    if entity is None or entity.cik != cik10 or entity.registrant_linked_at is None:
        reason = "the registrant link was removed before the read could start"
    elif not acquisition_reader.stored_sections(db, entity_id):
        reason = "the registrant's filings have no Business Combinations section to read"
    elif not llm_connector.is_configured(db):
        reason = "the OpenRouter connector is not configured or not enabled"
    if reason is not None:
        db.rollback()
        return None, reason
    run = EntityIngestRun(cik=cik10, kind="acquisition_read", status="queued", requested_by_id=user_id)
    db.add(run)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return None, "an AI read of this company was already queued or running"
    db.refresh(run)
    return run, None


# ── undo ─────────────────────────────────────────────────────────────────────

def _produced_relations(db: Session, entity_id: uuid.UUID) -> list[EntityRelation]:
    return db.execute(
        select(EntityRelation).where(
            or_(
                and_(EntityRelation.subject_id == entity_id, EntityRelation.relation.in_(("formerly_named", "acquired"))),
                and_(EntityRelation.object_id == entity_id, EntityRelation.relation == "subsidiary_of"),
            )
        ).with_for_update()
    ).scalars().all()


def unlink(db: Session, *, entity_id: uuid.UUID, user) -> tuple[OrgEntity, dict]:
    entity = db.execute(select(OrgEntity).where(OrgEntity.id == entity_id).with_for_update()).scalar_one_or_none()
    if entity is None:
        raise LinkNotFound("entity not found")
    try:
        if entity.registrant_linked_at is None or entity.cik is None:
            raise LinkConflict("this company's CIK was not set by a registrant link, so there is nothing to unlink")
        cik10 = entity.cik
        if _active_run(db, cik10):
            raise LinkConflict("an ingest or AI read for this registrant is queued or running; unlink when it finishes")

        relations = _produced_relations(db, entity_id)
        candidates = db.execute(
            select(CandidateDomain).where(
                CandidateDomain.entity_id == entity_id, CandidateDomain.source == WEBSITE_SOURCE
            ).with_for_update()
        ).scalars().all()
        person_confirmed = [r for r in relations if r.status == "confirmed" and r.decision_kind == "person"]
        accepted = [c for c in candidates if c.status == "accepted"]
        if person_confirmed or accepted:
            raise LinkConflict(
                f"a person has already decided on this registrant's output ({len(person_confirmed)} confirmed "
                f"relation(s), {len(accepted)} accepted domain(s)); undo those decisions first"
            )
    except LinkError:
        db.rollback()
        raise

    now = datetime.now(timezone.utc)
    rejected_relations = 0
    for r in relations:
        if r.status == "rejected":
            continue
        r.status, r.decision_kind, r.decided_by_id, r.decided_at = "rejected", "person", user.id, now
        rejected_relations += 1
    rejected_candidates = 0
    for c in candidates:
        if c.status == "proposed":
            c.status, c.decided_at, c.decided_by_id = "rejected", now, user.id
            rejected_candidates += 1

    deleted = {
        "filing_events": db.query(EntityFilingEvent).filter(EntityFilingEvent.entity_id == entity_id).delete(synchronize_session=False),
        "filing_sections": db.query(EntityFilingSection).filter(EntityFilingSection.entity_id == entity_id).delete(synchronize_session=False),
        "subsidiary_listings": db.query(EntitySubsidiaryListing).filter(
            EntitySubsidiaryListing.filer_entity_id == entity_id
        ).delete(synchronize_session=False),
    }
    entity.cik = None
    entity.registrant_linked_at = None
    entity.registrant_linked_by_id = None
    db.commit()
    db.refresh(entity)
    return entity, {
        "cik": cik10, "relations_rejected": rejected_relations, "candidates_rejected": rejected_candidates, **deleted,
    }
