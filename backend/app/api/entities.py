"""The corporate entity graph's API surface (planning#212, L3).

Mounted at `/api/entities` (`app/main.py`). Reads (`GET /`, `GET /{id}/
edges`, `GET /relations`) are open to any authenticated user, matching
`app/api/engagements.py`'s reasoning: an operator reviewing what this
system knows about a counterparty's corporate structure should not need
ADMIN to see it. Every WRITE is ADMIN-only — creating an entity seeds an
identity other data will attach to, and deciding a relation is exactly the
"a person confirms/rejects" act migration 0061's CHECK constraint exists to
require evidence of.

**No endpoint here creates a relation.** Ingestion (an SEC-filing fetcher,
a Wayback fetcher, an LLM extractor calling `entity_graph.assert_relation`)
is planning#213/#214/#215 — L4/L5, not this slice.
"""

import logging
import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_role
from app.core.database import SessionLocal, get_db
from app.models.entity_filing_event import EntityFilingEvent
from app.models.entity_filing_section import EntityFilingSection
from app.models.entity_relation import EntityRelation, RELATION_STATUSES
from app.models.entity_subsidiary_listing import EntitySubsidiaryListing
from app.models.evidence import EvidenceBlob, EvidenceFetch
from app.models.observer import Observer
from app.models.org_entity import OrgEntity
from app.models.user import User, UserRole
from app.services import audit, edgar_ingest, entity_graph

log = logging.getLogger(__name__)

router = APIRouter()


class EntityResponse(BaseModel):
    id: uuid.UUID
    legal_name: str
    cik: str | None
    lei: str | None
    created_at: str


class CreateEntityRequest(BaseModel):
    legal_name: str
    cik: str | None = None
    lei: str | None = None


class EdgeSource(BaseModel):
    observer: str | None
    trust: str | None
    status: str
    evidence_url: str | None
    fetched_at: str | None
    event_date: str | None
    precision: str


class EdgeResponse(BaseModel):
    subject: uuid.UUID
    object: uuid.UUID
    relation: str
    confirmed: bool
    sources: list[EdgeSource]


class RelationQueueItem(BaseModel):
    id: uuid.UUID
    subject_id: uuid.UUID
    object_id: uuid.UUID
    relation: str
    event_date: str | None
    event_date_precision: str
    status: str
    quote: str
    evidence_id: uuid.UUID
    evidence_url: str
    fetched_at: str
    observer_name: str | None
    observer_trust: str | None
    grounding: str | None


class DecisionRequest(BaseModel):
    status: str


class EdgarIngestRequest(BaseModel):
    cik: str


class EdgarIngestAccepted(BaseModel):
    status: str
    cik: str


class FilingEventResponse(BaseModel):
    id: uuid.UUID
    form: str
    accession_number: str
    filing_date: str
    items: str
    evidence_id: uuid.UUID
    observer_name: str | None


class SubsidiaryListingRow(BaseModel):
    name: str
    jurisdiction: str | None
    subsidiary_entity_id: uuid.UUID | None


class SubsidiaryListingGroup(BaseModel):
    accession_number: str
    filing_date: str
    report_date: str | None
    exhibit_type: str
    evidence_id: uuid.UUID
    rows: list[SubsidiaryListingRow]


class FilingSectionResponse(BaseModel):
    id: uuid.UUID
    accession_number: str
    form: str
    filing_date: str
    report_date: str | None
    section: str
    extraction: str
    heading: str
    heading_match_count: int
    start_line: int
    end_line: int
    text: str
    evidence_id: uuid.UUID


def _to_entity_response(e: OrgEntity) -> EntityResponse:
    return EntityResponse(id=e.id, legal_name=e.legal_name, cik=e.cik, lei=e.lei, created_at=e.created_at.isoformat())


@router.get("/", response_model=list[EntityResponse])
def list_entities(
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    entities = db.query(OrgEntity).order_by(OrgEntity.created_at.desc()).all()
    return [_to_entity_response(e) for e in entities]


@router.post("/", response_model=EntityResponse, status_code=201)
def create_entity(
    data: CreateEntityRequest,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN)),
):
    legal_name = data.legal_name.strip()
    if not legal_name:
        raise HTTPException(status_code=422, detail="legal_name is required")

    if data.cik is not None and db.query(OrgEntity).filter(OrgEntity.cik == data.cik).first() is not None:
        raise HTTPException(status_code=409, detail="an entity with this CIK already exists")

    entity = OrgEntity(id=uuid.uuid4(), legal_name=legal_name, cik=data.cik, lei=data.lei)
    db.add(entity)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="an entity with this CIK or LEI already exists")
    db.refresh(entity)
    return _to_entity_response(entity)


@router.get("/relations", response_model=list[RelationQueueItem])
def list_relations(
    status: str | None = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """The review queue. **Never returns blob content** — `evidence_url` and
    `fetched_at` only; `GET /evidence/{fetch_id}` is the separate,
    content-type-forced route for the bytes themselves."""
    if status is not None and status not in RELATION_STATUSES:
        raise HTTPException(status_code=422, detail=f"status must be one of {sorted(RELATION_STATUSES)}")

    query = db.query(EntityRelation)
    if status is not None:
        query = query.filter(EntityRelation.status == status)
    rows = query.order_by(EntityRelation.created_at.desc()).all()
    if not rows:
        return []

    observer_ids = {r.observer_id for r in rows}
    evidence_ids = {r.evidence_id for r in rows}
    observers_by_id = {o.id: o for o in db.query(Observer).filter(Observer.id.in_(observer_ids)).all()}
    fetches_by_id = {f.id: f for f in db.query(EvidenceFetch).filter(EvidenceFetch.id.in_(evidence_ids)).all()}

    items = []
    for r in rows:
        observer = observers_by_id.get(r.observer_id)
        fetch = fetches_by_id.get(r.evidence_id)
        items.append(
            RelationQueueItem(
                id=r.id,
                subject_id=r.subject_id,
                object_id=r.object_id,
                relation=r.relation,
                event_date=r.event_date.isoformat() if r.event_date else None,
                event_date_precision=r.event_date_precision,
                status=r.status,
                quote=r.quote,
                evidence_id=r.evidence_id,
                evidence_url=fetch.source_url if fetch else "",
                fetched_at=fetch.fetched_at.isoformat() if fetch else "",
                observer_name=observer.name if observer else None,
                observer_trust=observer.trust if observer else None,
                grounding=r.grounding,
            )
        )
    return items


@router.get("/evidence/{fetch_id}")
def get_evidence(
    fetch_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Returns the raw fetched bytes, `content-type` forced to
    `text/plain` — never render fetched HTML as HTML in our origin."""
    fetch = db.get(EvidenceFetch, fetch_id)
    if fetch is None:
        raise HTTPException(status_code=404, detail="Evidence fetch not found")
    blob = db.get(EvidenceBlob, fetch.sha256)
    if blob is None:  # pragma: no cover - FK RESTRICT makes this unreachable in practice
        raise HTTPException(status_code=404, detail="Evidence content not found")
    return Response(
        content=blob.content,
        media_type="text/plain",
        # No global security-header middleware exists, so this response
        # carries its own: no sniffing a fetched page back into HTML, and a
        # sandbox if a browser renders it anyway.
        headers={
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "sandbox; default-src 'none'",
        },
    )


@router.post("/relations/{relation_id}/decision", response_model=RelationQueueItem)
def decide_relation(
    request: Request,
    relation_id: uuid.UUID,
    data: DecisionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    if data.status not in ("confirmed", "rejected"):
        raise HTTPException(status_code=422, detail="status must be 'confirmed' or 'rejected'")

    relation = db.get(EntityRelation, relation_id)
    if relation is None:
        raise HTTPException(status_code=404, detail="Relation not found")

    before_status = relation.status
    try:
        relation = entity_graph.decide(db, relation_id=relation_id, status=data.status, user=current_user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="this decision is not permitted for this relation (see ck_entity_relations_decision)",
        )

    audit.record_detail(
        request,
        relation=str(relation.id),
        decision={"from": before_status, "to": relation.status},
    )

    observer = db.get(Observer, relation.observer_id)
    fetch = db.get(EvidenceFetch, relation.evidence_id)
    return RelationQueueItem(
        id=relation.id,
        subject_id=relation.subject_id,
        object_id=relation.object_id,
        relation=relation.relation,
        event_date=relation.event_date.isoformat() if relation.event_date else None,
        event_date_precision=relation.event_date_precision,
        status=relation.status,
        quote=relation.quote,
        evidence_id=relation.evidence_id,
        evidence_url=fetch.source_url if fetch else "",
        fetched_at=fetch.fetched_at.isoformat() if fetch else "",
        observer_name=observer.name if observer else None,
        observer_trust=observer.trust if observer else None,
        grounding=relation.grounding,
    )


def _run_edgar_ingest(cik: str) -> None:
    """The `BackgroundTasks` target. Opens its OWN `SessionLocal()` — the
    request's session is closed by the time this runs, since
    `BackgroundTasks` execute after the response is sent (synchronously,
    in-process, under `TestClient`). Always closes the session, whatever
    the outcome."""
    db = SessionLocal()
    try:
        result = edgar_ingest.ingest_cik(db, cik)
        log.info(
            "edgar ingest complete cik=%s entity_id=%s pages_fetched=%d "
            "former_names_asserted=%d former_names_skipped=%d events_inserted=%d "
            "events_existing=%d malformed_skipped=%d denied=%s",
            cik, result.entity_id, result.pages_fetched, result.former_names_asserted,
            result.former_names_skipped, result.events_inserted, result.events_existing,
            result.malformed_skipped, result.denied,
        )
    except Exception:
        log.exception("edgar ingest failed for cik=%s", cik)
    finally:
        db.close()


@router.post("/edgar-ingest", response_model=EdgarIngestAccepted, status_code=202)
def edgar_ingest_requested(
    request: Request,
    data: EdgarIngestRequest,
    background_tasks: BackgroundTasks,
    _=Depends(require_role(UserRole.ADMIN)),
):
    """Declared ahead of `/{entity_id}/edges` and `/{entity_id}/filing-
    events` below: `/edgar-ingest` has no path parameter, so it can never be
    captured by either `/{entity_id}/...` route regardless of registration
    order, but it is placed first anyway so that remains true by
    inspection, not just by accident of FastAPI's route-matching rules."""
    try:
        normalised = edgar_ingest.normalise_cik(data.cik)
    except ValueError:
        raise HTTPException(status_code=422, detail="cik must be 1 to 10 digits")

    try:
        edgar_ingest.require_user_agent()
    except edgar_ingest.EdgarNotConfigured as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    audit.record_detail(request, cik=normalised)

    # planning#134: this on-demand background task is one of the call sites
    # the job queue retires.
    background_tasks.add_task(_run_edgar_ingest, normalised)
    return EdgarIngestAccepted(status="accepted", cik=normalised)


@router.get("/{entity_id}/edges", response_model=list[EdgeResponse])
def get_entity_edges(
    entity_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    entity = db.get(OrgEntity, entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Entity not found")
    edges = entity_graph.project_edges(db, entity_id=entity_id)
    return [
        EdgeResponse(
            subject=e["subject"],
            object=e["object"],
            relation=e["relation"],
            confirmed=e["confirmed"],
            sources=[EdgeSource(**s) for s in e["sources"]],
        )
        for e in edges
    ]


@router.get("/{entity_id}/filing-events", response_model=list[FilingEventResponse])
def list_filing_events(
    entity_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Open to any authenticated user, matching #212's GET convention (this
    module's own docstring) — reviewing what this system knows about a
    counterparty's filings needs no ADMIN grant."""
    entity = db.get(OrgEntity, entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Entity not found")

    rows = (
        db.query(EntityFilingEvent)
        .filter(EntityFilingEvent.entity_id == entity_id)
        .order_by(EntityFilingEvent.filing_date.desc())
        .all()
    )
    observer_ids = {r.observer_id for r in rows}
    observers_by_id = {o.id: o for o in db.query(Observer).filter(Observer.id.in_(observer_ids)).all()}
    return [
        FilingEventResponse(
            id=r.id,
            form=r.form,
            accession_number=r.accession_number,
            filing_date=r.filing_date.isoformat(),
            items=r.items,
            evidence_id=r.evidence_id,
            observer_name=(observers_by_id[r.observer_id].name if r.observer_id in observers_by_id else None),
        )
        for r in rows
    ]


@router.get("/{entity_id}/subsidiary-listings", response_model=list[SubsidiaryListingGroup])
def list_subsidiary_listings(
    entity_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Open to any authenticated user (same GET convention as #212/#213
    slice 1). Rows are grouped by `accession_number` — newest filing
    first — each group carrying that EX-21's `rows[{name, jurisdiction,
    subsidiary_entity_id}]` in stored (`row_index`) order. This is planning
    #213 slice 2's snapshot surface: the year-over-year diff a caller wants
    is a comparison ACROSS groups here, never a stored computation (see
    migration 0063's docstring)."""
    entity = db.get(OrgEntity, entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Entity not found")

    rows = (
        db.query(EntitySubsidiaryListing)
        .filter(EntitySubsidiaryListing.filer_entity_id == entity_id)
        .order_by(EntitySubsidiaryListing.filing_date.desc(), EntitySubsidiaryListing.row_index.asc())
        .all()
    )

    groups: dict[str, SubsidiaryListingGroup] = {}
    order: list[str] = []
    for r in rows:
        if r.accession_number not in groups:
            groups[r.accession_number] = SubsidiaryListingGroup(
                accession_number=r.accession_number,
                filing_date=r.filing_date.isoformat(),
                report_date=r.report_date.isoformat() if r.report_date else None,
                exhibit_type=r.exhibit_type,
                evidence_id=r.evidence_id,
                rows=[],
            )
            order.append(r.accession_number)
        groups[r.accession_number].rows.append(
            SubsidiaryListingRow(name=r.name, jurisdiction=r.jurisdiction, subsidiary_entity_id=r.subsidiary_entity_id)
        )
    return [groups[k] for k in order]


@router.get("/{entity_id}/filing-sections", response_model=list[FilingSectionResponse])
def list_filing_sections(
    entity_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Open to any authenticated user. Returns metadata plus the extracted
    `text` for each stored section (currently only `business_
    combinations`) — planning#215 reads this, a person reads this, nothing
    here is a relation."""
    entity = db.get(OrgEntity, entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Entity not found")

    rows = (
        db.query(EntityFilingSection)
        .filter(EntityFilingSection.entity_id == entity_id)
        .order_by(EntityFilingSection.filing_date.desc())
        .all()
    )
    return [
        FilingSectionResponse(
            id=r.id,
            accession_number=r.accession_number,
            form=r.form,
            filing_date=r.filing_date.isoformat(),
            report_date=r.report_date.isoformat() if r.report_date else None,
            section=r.section,
            extraction=r.extraction,
            heading=r.heading,
            heading_match_count=r.heading_match_count,
            start_line=r.start_line,
            end_line=r.end_line,
            text=r.text,
            evidence_id=r.evidence_id,
        )
        for r in rows
    ]
