"""Organizations: a root company and the scope discovered for it
(planning#277 S1a). Mounted at `/api/organizations` (`app/main.py`).

An organization is an `org_entities` row with a `relationship`. Its
CANDIDATES (domains today) each carry SIGNALS; strength is calculated on
load (`org_discovery.strength`). Reads need `entities.read`; adding an
organization is `organizations.create` (admin only); adding a domain and
claiming / rejecting one reuse `entities.propose_candidate` and
`entities.decide_candidate`.

Every read applies `read_scope.entity_clause` to the root and
`read_scope.domain_clause` to the candidate, and a single-id route answers
404 (not 403) when the clause filters the row out. Both clauses grant
everything today (planning#261's entity slice fills them); they are called
here so that slice changes one module, not this one.

There is deliberately no endpoint that takes a company NAME and returns
domains: a candidate is added with its evidence or comes from a signal.
"""

import uuid
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session, aliased

from app.api.deps import require_permission
from app.core.database import get_db
from app.core.permissions import Permission, has_permission
from app.models.engagement import Engagement, EngagementPosture
from app.models.org_entity import OrgEntity
from app.models.scope_candidate import ScopeCandidate, ScopeCandidateEvent, ScopeSignal
from app.models.user import User
from app.services import audit, edgar_ingest, entity_relationship, organizations, read_scope, sec_edgar
from app.services.org_discovery import candidates, filer_search
from app.services.org_discovery import strength as strength_sql
from app.services.org_discovery.tiers import SIGNALS

router = APIRouter()

_DEFAULT_LIMIT = 200
_MAX_LIMIT = 1000


# ── schemas ─────────────────────────────────────────────────────────────────


class EngagementRef(BaseModel):
    id: uuid.UUID
    name: str
    posture: str


class OrganizationSummary(BaseModel):
    id: uuid.UUID
    name: str
    relationship: str
    seed_domain: str | None
    engagement: EngagementRef | None
    claimed: int
    proposed: int
    leads: int
    rejected: int


class AddOrganizationRequest(BaseModel):
    seed_domain: str
    org_name: str
    cik: str | None = None
    relationship: Literal["ours", "ma_target"]
    reference: str
    engagement_name: str | None = None


class AddOrganizationResponse(BaseModel):
    organization_id: uuid.UUID
    relationship: str
    engagement: EngagementRef | None
    candidate_id: uuid.UUID
    target_id: uuid.UUID
    assignment_role: str | None
    ingest_run_id: uuid.UUID | None
    ingest: Literal["queued", "already_running", "not_requested"]


class MatchedFilingResponse(BaseModel):
    form: str
    file_date: str
    accession: str


class FilingStatsResponse(BaseModel):
    total_filings: int
    first_filing: str | None
    last_filing: str | None
    latest_10k: str | None
    partial: bool


class FilerHitResponse(BaseModel):
    cik: str
    display_name: str | None
    edgar_url: str
    matched_filings: list[MatchedFilingResponse]
    why: list[str]
    stats: FilingStatsResponse | None
    entity_id: uuid.UUID | None


class AffiliateRef(BaseModel):
    id: uuid.UUID | None
    name: str | None


class SignalSummary(BaseModel):
    signal_type: str
    tier: str
    family: str
    count: int


class PreviouslyRejected(BaseModel):
    reason: str | None
    at: str


class CandidateRow(BaseModel):
    id: uuid.UUID
    root_entity_id: uuid.UUID
    value: str
    kind: str
    status: str
    strength: str
    proposable: bool
    affiliated: AffiliateRef
    affiliated_is_default: bool
    signals: list[SignalSummary]
    first_seen_at: str | None
    previously_rejected: PreviouslyRejected | None
    target_id: uuid.UUID | None


class AnchorDetail(BaseModel):
    kind: str
    candidate_id: uuid.UUID | None = None
    candidate_value: str | None = None
    entity_id: uuid.UUID | None = None
    entity_name: str | None = None
    user_id: uuid.UUID | None = None


class SignalDetail(BaseModel):
    id: uuid.UUID
    signal_type: str
    tier: str
    family: str
    anchor: AnchorDetail
    via_entity: AffiliateRef
    quote: str | None
    evidence_id: uuid.UUID | None
    first_seen_at: str
    last_seen_at: str


class EventDetail(BaseModel):
    event: str
    at: str
    user_id: uuid.UUID | None
    reason: str | None
    signal_id: uuid.UUID | None


class CandidateDetail(CandidateRow):
    signal_details: list[SignalDetail]
    events: list[EventDetail]
    rejection_reason: str | None
    decided_at: str | None
    accepted_into: str | None
    engagement_id: uuid.UUID | None


class AddCandidateRequest(BaseModel):
    domain: str
    via_entity_id: uuid.UUID | None = None
    source_url: str
    excerpt: str
    quote: str


class ClaimRequest(BaseModel):
    affiliated_entity_id: uuid.UUID | None = None


class RejectRequest(BaseModel):
    reason: str


# ── errors ──────────────────────────────────────────────────────────────────


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, (candidates.CandidateNotFound, entity_relationship.RelationshipNotFound)):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, (candidates.CandidateForbidden, entity_relationship.RelationshipForbidden)):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, (candidates.CandidateConflict, entity_relationship.RelationshipConflict)):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, (candidates.CandidateInvalid, entity_relationship.RelationshipInvalid)):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, edgar_ingest.EdgarNotConfigured):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, sec_edgar.SecForbidden):
        return HTTPException(status_code=502, detail="SEC refused the request; check SEC_USER_AGENT")
    # Any other SEC failure: the class name only, never the message (it
    # carries the URL, and with it the typed domain).
    return HTTPException(status_code=502, detail=f"SEC EDGAR could not be reached ({type(exc).__name__}); try again")


# ── shared reads ────────────────────────────────────────────────────────────


def _require_visible_root(db: Session, user: User, org_id: uuid.UUID) -> uuid.UUID:
    """404 unless `org_id` is a root the caller may read."""
    root = aliased(OrgEntity)
    found = db.execute(
        select(root.id).where(
            root.id == org_id, root.relationship.isnot(None), read_scope.entity_clause(user, root)
        )
    ).scalar_one_or_none()
    if found is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    return found


def _candidate_query(db: Session, user: User, *, candidate_ids):
    """The SELECT every candidate read shares: candidate + calculated
    strength + stored-or-default affiliate, behind both read_scope hooks."""
    sc = ScopeCandidate
    root, aff = aliased(OrgEntity), aliased(OrgEntity)
    st = strength_sql.strength_subquery(candidate_ids=candidate_ids)
    aff_id = func.coalesce(sc.affiliated_entity_id, strength_sql.default_affiliate_expr(sc.id))
    query = (
        select(
            sc,
            st.strength.label("strength"),
            st.proposable.label("proposable"),
            st.rank.label("rank"),
            aff_id.label("aff_id"),
            aff.legal_name.label("aff_name"),
        )
        .select_from(sc)
        .join(root, root.id == sc.root_entity_id)
        .outerjoin(st.subquery, st.candidate_id == sc.id)
        .outerjoin(aff, aff.id == aff_id)
        .where(read_scope.entity_clause(user, root), read_scope.domain_clause(user, sc))
    )
    return query, st, aff_id


def _names(db: Session, ids: set[uuid.UUID]) -> dict[uuid.UUID, str]:
    if not ids:
        return {}
    return {i: n for i, n in db.execute(select(OrgEntity.id, OrgEntity.legal_name).where(OrgEntity.id.in_(ids))).all()}


def _rows(db: Session, result_rows) -> list[CandidateRow]:
    """Candidate rows -> responses, with the signal summaries, first-seen
    and previously-rejected fields fetched for the whole page in two
    queries."""
    ids = [r.ScopeCandidate.id for r in result_rows]
    if not ids:
        return []
    sig = ScopeSignal
    summaries: dict[uuid.UUID, list[SignalSummary]] = {}
    first_seen: dict[uuid.UUID, object] = {}
    for cid, stype, count, seen in db.execute(
        select(sig.candidate_id, sig.signal_type, func.count(), func.min(sig.first_seen_at))
        .where(sig.candidate_id.in_(ids))
        .group_by(sig.candidate_id, sig.signal_type)
    ).all():
        spec = SIGNALS[stype]
        summaries.setdefault(cid, []).append(
            SignalSummary(signal_type=stype, tier=spec.tier, family=spec.family, count=count)
        )
        if cid not in first_seen or seen < first_seen[cid]:
            first_seen[cid] = seen
    previous: dict[uuid.UUID, PreviouslyRejected] = {}
    ev = ScopeCandidateEvent
    for cid, reason, at in db.execute(
        select(ev.candidate_id, ev.reason, ev.at)
        .where(ev.candidate_id.in_(ids), ev.event == "unlocked")
        .order_by(ev.at.asc())
    ).all():
        previous[cid] = PreviouslyRejected(reason=reason, at=at.isoformat())  # latest wins
    out: list[CandidateRow] = []
    for r in result_rows:
        c = r.ScopeCandidate
        out.append(CandidateRow(
            id=c.id, root_entity_id=c.root_entity_id, value=c.value, kind=c.kind, status=c.status,
            strength=r.strength, proposable=bool(r.proposable),
            affiliated=AffiliateRef(id=r.aff_id, name=r.aff_name),
            affiliated_is_default=c.affiliated_entity_id is None,
            signals=sorted(summaries.get(c.id, []), key=lambda s: (s.tier, s.signal_type)),
            first_seen_at=first_seen[c.id].isoformat() if c.id in first_seen else None,
            previously_rejected=previous.get(c.id),
            target_id=c.target_id,
        ))
    return out


def _one_row(db: Session, user: User, candidate_id: uuid.UUID) -> tuple[CandidateRow, ScopeCandidate]:
    query, _st, _aff = _candidate_query(db, user, candidate_ids=[candidate_id])
    row = db.execute(query.where(ScopeCandidate.id == candidate_id).execution_options(populate_existing=True)).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Candidate not found")
    return _rows(db, [row])[0], row.ScopeCandidate


def _require_visible_candidate(db: Session, user: User, candidate_id: uuid.UUID) -> None:
    root = aliased(OrgEntity)
    sc = ScopeCandidate
    found = db.execute(
        select(sc.id).join(root, root.id == sc.root_entity_id).where(
            sc.id == candidate_id, read_scope.entity_clause(user, root), read_scope.domain_clause(user, sc)
        )
    ).scalar_one_or_none()
    if found is None:
        raise HTTPException(status_code=404, detail="Candidate not found")


# ── filer search ────────────────────────────────────────────────────────────


@router.get("/filer-search", response_model=list[FilerHitResponse])
def filer_search_route(
    domain: str,
    db: Session = Depends(get_db),
    _=Depends(require_permission(Permission.ORGANIZATIONS_CREATE)),
):
    """SEC filers whose 10-K contains `domain`: a HINT for the person adding
    an organization. Every call sends requests to SEC; stores nothing."""
    try:
        normalised = candidates.normalise_domain(domain)
        edgar_ingest.require_user_agent()
        hits = filer_search.search_by_domain(db, normalised)
    except candidates.CandidateError as exc:
        raise _http_error(exc)
    except (edgar_ingest.EdgarNotConfigured, sec_edgar.SecFetchError, sec_edgar.SecNotFound) as exc:
        raise _http_error(exc)
    return [
        FilerHitResponse(
            cik=h.cik, display_name=h.display_name, edgar_url=h.edgar_url,
            matched_filings=[MatchedFilingResponse(form=f.form, file_date=f.file_date, accession=f.accession)
                             for f in h.matched_filings],
            why=filer_search.describe_match(h, normalised),
            stats=FilingStatsResponse(**vars(h.stats)) if h.stats else None,
            entity_id=h.entity_id,
        )
        for h in hits
    ]


# ── add / list organizations ────────────────────────────────────────────────


def _no_followup_for_ma_target(db, *, entity_id, cik10, user_id):
    return None, "the AI acquisition read is not queued automatically for an M&A target organization"


@router.post("/", response_model=AddOrganizationResponse, status_code=201)
def add_organization(
    request: Request,
    data: AddOrganizationRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ORGANIZATIONS_CREATE)),
):
    """One atomic act: the entity, its relationship (a new `pre_close`
    engagement for an M&A target), the seed domain claimed into the
    destination, and, when a CIK is given, a queued filing ingest."""
    try:
        result = organizations.add_organization(
            db,
            seed_domain=data.seed_domain,
            org_name=data.org_name,
            cik=data.cik,
            relationship=data.relationship,
            reference=data.reference,
            engagement_name=data.engagement_name,
            user=current_user,
            may_mark_ours=has_permission(current_user, Permission.ENTITIES_MARK_OURS),
        )
    except (candidates.CandidateError, entity_relationship.RelationshipError) as exc:
        raise _http_error(exc)
    entity, engagement, run = result.entity, result.engagement, result.ingest_run
    audit.record_detail(
        request,
        organization=str(entity.id),
        relationship=data.relationship,
        # NOT a key containing "auth": `audit.scrub` would redact it.
        reference=data.reference.strip(),
        engagement=str(engagement.id) if engagement else None,
        engagement_created=result.engagement_created,
        seed=result.candidate.value,
        assignment=result.assignment.role if result.assignment else None,
        filer_cik_set=entity.cik is not None and data.cik is not None,
    )
    if result.target_created:
        # A seed target created here gets the same first discovery run a
        # claimed one does; `_launch_initial_discovery` enforces posture.
        from app.api.targets import _launch_initial_discovery

        _launch_initial_discovery(db, result.target, current_user.id, background_tasks)
    if run is not None:
        from app.api.entities import _run_ingest_then_read
        from app.services import onboarding

        followup = onboarding.followup_read if data.relationship == "ours" else _no_followup_for_ma_target
        background_tasks.add_task(_run_ingest_then_read, run.id, entity.id, entity.cik, current_user.id, followup)
    return AddOrganizationResponse(
        organization_id=entity.id,
        relationship=data.relationship,
        engagement=EngagementRef(id=engagement.id, name=engagement.name, posture=engagement.posture) if engagement else None,
        candidate_id=result.candidate.id,
        target_id=result.target.id,
        assignment_role=result.assignment.role if result.assignment else None,
        ingest_run_id=run.id if run else None,
        ingest="queued" if run else ("already_running" if data.cik else "not_requested"),
    )


@router.get("/", response_model=list[OrganizationSummary])
def list_organizations(
    limit: int = Query(_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ENTITIES_READ)),
):
    root = aliased(OrgEntity)
    roots = db.execute(
        select(root.id, root.legal_name, root.relationship)
        .where(root.relationship.isnot(None), read_scope.entity_clause(current_user, root))
        .order_by(root.legal_name, root.id)
        .limit(limit).offset(offset)
    ).all()
    if not roots:
        return []
    root_ids = [r.id for r in roots]

    sc = ScopeCandidate
    st = strength_sql.strength_subquery(candidate_ids=select(sc.id).where(sc.root_entity_id.in_(root_ids)))
    is_open = sc.status == "open"
    counts = {
        r.root_entity_id: r
        for r in db.execute(
            select(
                sc.root_entity_id,
                func.count().filter(sc.status == "claimed").label("claimed"),
                func.count().filter(and_(is_open, st.proposable)).label("proposed"),
                func.count().filter(and_(is_open, ~st.proposable, st.signal_count >= 1)).label("leads"),
                func.count().filter(sc.status == "rejected").label("rejected"),
            )
            .select_from(sc)
            .outerjoin(st.subquery, st.candidate_id == sc.id)
            .where(sc.root_entity_id.in_(root_ids), read_scope.domain_clause(current_user, sc))
            .group_by(sc.root_entity_id)
        ).all()
    }
    seeds: dict[uuid.UUID, str] = {}
    for root_id, value in db.execute(
        select(sc.root_entity_id, func.min(sc.value))
        .join(ScopeSignal, ScopeSignal.candidate_id == sc.id)
        .where(sc.root_entity_id.in_(root_ids), ScopeSignal.signal_type == "admin_seed")
        .group_by(sc.root_entity_id)
    ).all():
        seeds[root_id] = value
    engagements: dict[uuid.UUID, Engagement] = {}
    for e in db.execute(
        select(Engagement).where(Engagement.subject_entity_id.in_(root_ids)).order_by(Engagement.created_at)
    ).scalars():
        current = engagements.get(e.subject_entity_id)
        # Prefer a live engagement (the destination) over an abandoned one.
        if current is None or (
            current.posture == EngagementPosture.ABANDONED.value and e.posture != EngagementPosture.ABANDONED.value
        ):
            engagements[e.subject_entity_id] = e
    out = []
    for r in roots:
        c = counts.get(r.id)
        e = engagements.get(r.id) if r.relationship == "ma_target" else None
        out.append(OrganizationSummary(
            id=r.id, name=r.legal_name, relationship=r.relationship, seed_domain=seeds.get(r.id),
            engagement=EngagementRef(id=e.id, name=e.name, posture=e.posture) if e else None,
            claimed=c.claimed if c else 0, proposed=c.proposed if c else 0,
            leads=c.leads if c else 0, rejected=c.rejected if c else 0,
        ))
    return out


# ── candidates ──────────────────────────────────────────────────────────────


@router.get("/{org_id}/candidates", response_model=list[CandidateRow])
def list_candidates(
    org_id: uuid.UUID,
    status: Literal["open", "claimed", "rejected", "all"] = "open",
    include_leads: bool = False,
    strength: Literal["strong", "supporting", "lead", "context"] | None = None,
    affiliated_entity_id: uuid.UUID | None = None,
    limit: int = Query(_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ENTITIES_READ)),
):
    _require_visible_root(db, current_user, org_id)
    sc = ScopeCandidate
    query, st, aff_id = _candidate_query(
        db, current_user, candidate_ids=select(sc.id).where(sc.root_entity_id == org_id)
    )
    query = query.where(sc.root_entity_id == org_id)
    if status != "all":
        query = query.where(sc.status == status)
    if not include_leads:
        # An open candidate is shown only once it clears the propose bar.
        query = query.where(or_(sc.status != "open", st.proposable))
    if strength is not None:
        query = query.where(st.strength == strength)
    if affiliated_entity_id is not None:
        query = query.where(aff_id == affiliated_entity_id)
    query = query.order_by(st.rank.desc(), sc.value, sc.id).limit(limit).offset(offset)
    return _rows(db, db.execute(query).all())


@router.get("/candidates/{candidate_id}", response_model=CandidateDetail)
def get_candidate(
    candidate_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ENTITIES_READ)),
):
    row, candidate = _one_row(db, current_user, candidate_id)
    signals = db.execute(
        select(ScopeSignal).where(ScopeSignal.candidate_id == candidate_id).order_by(ScopeSignal.first_seen_at, ScopeSignal.id)
    ).scalars().all()
    entity_ids = {s.via_entity_id for s in signals} | {s.anchor_entity_id for s in signals if s.anchor_entity_id}
    names = _names(db, entity_ids)
    anchor_values = {
        i: v for i, v in db.execute(
            select(ScopeCandidate.id, ScopeCandidate.value).where(
                ScopeCandidate.id.in_({s.anchor_candidate_id for s in signals if s.anchor_candidate_id})
            )
        ).all()
    } if any(s.anchor_candidate_id for s in signals) else {}
    details = [
        SignalDetail(
            id=s.id, signal_type=s.signal_type, tier=SIGNALS[s.signal_type].tier, family=SIGNALS[s.signal_type].family,
            anchor=AnchorDetail(
                kind=s.anchor_kind,
                candidate_id=s.anchor_candidate_id, candidate_value=anchor_values.get(s.anchor_candidate_id),
                entity_id=s.anchor_entity_id, entity_name=names.get(s.anchor_entity_id),
                user_id=s.anchor_user_id,
            ),
            via_entity=AffiliateRef(id=s.via_entity_id, name=names.get(s.via_entity_id)),
            quote=s.quote, evidence_id=s.evidence_id,
            first_seen_at=s.first_seen_at.isoformat(), last_seen_at=s.last_seen_at.isoformat(),
        )
        for s in signals
    ]
    events = db.execute(
        select(ScopeCandidateEvent).where(ScopeCandidateEvent.candidate_id == candidate_id)
        .order_by(ScopeCandidateEvent.at, ScopeCandidateEvent.id)
    ).scalars().all()
    return CandidateDetail(
        **row.model_dump(),
        signal_details=details,
        events=[EventDetail(event=e.event, at=e.at.isoformat(), user_id=e.user_id, reason=e.reason, signal_id=e.signal_id)
                for e in events],
        rejection_reason=candidate.rejection_reason,
        decided_at=candidate.decided_at.isoformat() if candidate.decided_at else None,
        accepted_into=candidate.accepted_into,
        engagement_id=candidate.engagement_id,
    )


@router.post("/{org_id}/candidates", response_model=CandidateRow, status_code=201)
def add_candidate(
    request: Request,
    org_id: uuid.UUID,
    data: AddCandidateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ENTITIES_PROPOSE_CANDIDATE)),
):
    """A person adds a domain WITH its evidence (a Strong `person_evidence`
    signal); nothing here looks a domain up from a name."""
    _require_visible_root(db, current_user, org_id)
    try:
        candidate = candidates.add_by_person(
            db,
            root_entity_id=org_id,
            via_entity_id=data.via_entity_id or org_id,
            domain=data.domain,
            source_url=data.source_url,
            excerpt=data.excerpt,
            quote=data.quote,
            user=current_user,
        )
    except candidates.CandidateError as exc:
        raise _http_error(exc)
    audit.record_detail(
        request, candidate=str(candidate.id), organization=str(org_id), value=candidate.value,
        signal="person_evidence",
    )
    return _one_row(db, current_user, candidate.id)[0]


@router.post("/candidates/{candidate_id}/claim", response_model=CandidateRow)
def claim_candidate(
    request: Request,
    candidate_id: uuid.UUID,
    data: ClaimRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ENTITIES_DECIDE_CANDIDATE)),
):
    """Creates the target already inside the destination the ROOT organization
    resolves to (our estate, or its engagement, so it inherits the
    engagement's posture), then queues the same initial discovery run
    `POST /targets` does. That run is gated per observer by
    `probe_authorisation.authorise_discovery`, so under a restricting
    posture only passive sources execute."""
    _require_visible_candidate(db, current_user, candidate_id)
    try:
        result = candidates.claim(
            db, candidate_id=candidate_id, user=current_user, affiliated_entity_id=data.affiliated_entity_id
        )
    except candidates.CandidateError as exc:
        raise _http_error(exc)
    c = result.candidate
    audit.record_detail(
        request,
        candidate=str(c.id),
        value=c.value,
        destination=c.accepted_into,
        engagement=str(c.engagement_id) if c.engagement_id else None,
        target=str(result.target.id),
        created=result.created,
    )
    if result.created:
        from app.api.targets import _launch_initial_discovery

        _launch_initial_discovery(db, result.target, current_user.id, background_tasks)
    return _one_row(db, current_user, candidate_id)[0]


@router.post("/candidates/{candidate_id}/reject", response_model=CandidateRow)
def reject_candidate(
    request: Request,
    candidate_id: uuid.UUID,
    data: RejectRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ENTITIES_DECIDE_CANDIDATE)),
):
    _require_visible_candidate(db, current_user, candidate_id)
    try:
        candidate = candidates.reject(db, candidate_id=candidate_id, user=current_user, reason=data.reason)
    except candidates.CandidateError as exc:
        raise _http_error(exc)
    audit.record_detail(
        request, candidate=str(candidate.id), value=candidate.value, decision={"from": "open", "to": "rejected"},
        reason=candidate.rejection_reason,
    )
    return _one_row(db, current_user, candidate_id)[0]
