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
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import exists, func, or_, select
from sqlalchemy.orm import Session, aliased

from app.api.deps import require_permission
from app.api.findings import _NOT_EXCLUDED_FROM_MAIN, _OPEN_STATES
from app.core.database import get_db
from app.core.permissions import Permission, has_permission
from app.models.connector_instance import ConnectorInstance
from app.models.asset_canonical import AssetCanonical
from app.models.engagement import Engagement, EngagementPosture
from app.models.finding_canonical import FindingCanonical
from app.models.org_entity import OrgEntity
from app.models.scope_candidate import (
    ScopeCandidate,
    ScopeCandidateEvent,
    ScopeCandidateReassignment,
    ScopeSignal,
)
from app.models.target import Target
from app.models.target_asset_link import TargetAssetLink
from app.models.user import User
from app.services import audit, edgar_ingest, entity_relationship, organizations, read_scope, sec_edgar
from app.services import org_tree as org_tree_sql
from app.services.org_discovery import candidates, filer_search, rollup, runner
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
    deal_reference: str | None = None


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


class LocateResponse(BaseModel):
    org_id: uuid.UUID
    node: uuid.UUID | None  # None when the entity IS the root


class TreeNodeResponse(BaseModel):
    entity_id: uuid.UUID
    name: str
    parent_id: uuid.UUID | None
    relation: Literal["subsidiary_of", "acquired"] | None
    event_date: str | None
    status: Literal["confirmed", "proposed"]
    depth: int


class OrganizationDetailSummary(BaseModel):
    claimed: int
    to_review: int
    leads: int
    rejected: int
    assets_under_claimed_scope: int
    has_filer: bool
    affiliates: int
    proposed_affiliates: int


class SignalTypeResponse(BaseModel):
    signal_type: str
    tier: str
    family: str
    label: str
    description: str
    built: bool


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


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0


class AcquisitionRow(BaseModel):
    entity_id: uuid.UUID | None  # None on the organic row
    name: str  # organic row: the root's legal name
    organic: bool
    closed: str | None  # ISO date of the acquired relation's event_date
    closed_precision: str | None  # the relation's event_date_precision
    postures: list[str]  # sorted distinct postures of the claimed targets' engagements; "estate" = no engagement
    domains_claimed: int
    domains_to_review: int
    asns_claimed: int
    cidrs_claimed: int
    ip_to_review: int  # asn + cidr candidates still in review
    assets: int
    open_findings: SeverityCounts
    worst_severity: Literal["critical", "high", "medium", "low", "unknown"] | None
    kev: int  # CISA KEV only (`findings.kev`), as bod_sla does
    risk_score_sum: int
    risk_share: float | None  # None for every row when the estate sum is 0


class AcquisitionRollup(BaseModel):
    rows: list[AcquisitionRow]
    estate_risk_score_sum: int


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
    decided_by_connector_instance_id: uuid.UUID | None = None
    # Set exactly for an ASN or CIDR (migration 0087).
    rir: str | None = None
    rir_handle: str | None = None
    # Null unless the row is claimed AND has a target (planning#277 S2).
    asset_count: int | None = None
    open_findings: SeverityCounts | None = None
    worst_severity: Literal["critical", "high", "medium", "low", "unknown"] | None = None


class ClaimResponse(CandidateRow):
    # CIDR candidates claimed by an ASN claim's cascade (0 for a domain or CIDR).
    claimed_prefixes: int = 0


class CandidatePage(BaseModel):
    items: list[CandidateRow]
    total: int


class ReassignmentRow(BaseModel):
    id: uuid.UUID
    candidate_id: uuid.UUID
    candidate_value: str  # the claimed prefix
    rir: str | None  # of the candidate
    rir_handle: str | None  # the holder the prefix was claimed under
    prefix: str  # the part now shown under another holder
    new_holder_kind: str
    new_holder_handle: str | None
    evidence_id: uuid.UUID
    first_detected_at: str  # ISO 8601, like CandidateRow.first_seen_at
    last_seen_at: str


class ReassignmentPage(BaseModel):
    items: list[ReassignmentRow]
    total: int


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
    matched_values: list[str] | None = None
    first_seen_at: str
    last_seen_at: str


class EventDetail(BaseModel):
    event: str
    at: str
    user_id: uuid.UUID | None
    reason: str | None
    signal_id: uuid.UUID | None
    connector_instance_id: uuid.UUID | None = None


class CandidateDetail(CandidateRow):
    signal_details: list[SignalDetail]
    events: list[EventDetail]
    rejection_reason: str | None
    decided_at: str | None
    accepted_into: str | None
    engagement_id: uuid.UUID | None
    decided_by_id: uuid.UUID | None = None
    # The instance's CURRENT name (never stored); None when the caller cannot
    # read that instance, or it no longer exists. The id above is still returned.
    decided_by_connector_name: str | None = None


class AddCandidateRequest(BaseModel):
    domain: str
    via_entity_id: uuid.UUID | None = None
    source_url: str
    excerpt: str
    quote: str


class RecheckAccepted(BaseModel):
    claimed_domains: int


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


def _visible_root(db: Session, user: User, org_id: uuid.UUID) -> bool:
    """Is `org_id` a root the caller may read?"""
    root = aliased(OrgEntity)
    found = db.execute(
        select(root.id).where(
            root.id == org_id, root.relationship.isnot(None), read_scope.entity_clause(user, root)
        )
    ).scalar_one_or_none()
    return found is not None


def _require_visible_root(db: Session, user: User, org_id: uuid.UUID) -> uuid.UUID:
    """404 unless `org_id` is a root the caller may read."""
    if not _visible_root(db, user, org_id):
        raise HTTPException(status_code=404, detail="Organization not found")
    return org_id


def _aff_id_expr():
    """The stored-or-default affiliate of a candidate: ONE expression, used by
    the candidate list, the subtree filter and the summary."""
    return func.coalesce(ScopeCandidate.affiliated_entity_id, strength_sql.default_affiliate_expr(ScopeCandidate.id))


def _subtree_or_404(db: Session, user: User, org_id: uuid.UUID, node_id: uuid.UUID) -> set[uuid.UUID]:
    try:
        return org_tree_sql.subtree_ids(db, user, org_id, node_id)
    except org_tree_sql.NodeNotInTree:
        raise HTTPException(status_code=404, detail="Affiliate not found in this organization's tree")


_SEVERITY_ORDER = ("critical", "high", "medium", "low", "unknown")


def _target_rollups(db: Session, user: User, target_ids: set[uuid.UUID]) -> dict[uuid.UUID, tuple[int, SeverityCounts]]:
    """Asset count and OPEN-finding severity counts per target, for a whole
    page in two queries. "Open" is the Findings API's own definition
    (`_OPEN_STATES`, not excluded by the shared-infra verifier); assets and
    findings the caller may not read are not counted."""
    if not target_ids:
        return {}
    link = TargetAssetLink
    asset_counts = dict(db.execute(
        select(link.target_id, func.count(func.distinct(link.asset_canonical_id)))
        .join(AssetCanonical, AssetCanonical.id == link.asset_canonical_id)
        .where(link.target_id.in_(target_ids), read_scope.asset_clause(user, AssetCanonical))
        .group_by(link.target_id)
    ).all())
    sev: dict[uuid.UUID, dict[str, int]] = {}
    for target_id, severity, n in db.execute(
        select(link.target_id, FindingCanonical.severity, func.count(func.distinct(FindingCanonical.id)))
        .join(AssetCanonical, AssetCanonical.id == link.asset_canonical_id)
        .join(FindingCanonical, FindingCanonical.asset_canonical_id == AssetCanonical.id)
        .where(
            link.target_id.in_(target_ids),
            FindingCanonical.state.in_(_OPEN_STATES),
            _NOT_EXCLUDED_FROM_MAIN,
            read_scope.finding_clause(user, FindingCanonical, AssetCanonical),
        )
        .group_by(link.target_id, FindingCanonical.severity)
    ).all():
        bucket = severity if severity in _SEVERITY_ORDER else "unknown"
        sev.setdefault(target_id, {}).setdefault(bucket, 0)
        sev[target_id][bucket] += n
    return {t: (asset_counts.get(t, 0), SeverityCounts(**sev.get(t, {}))) for t in target_ids}


def _worst(counts: SeverityCounts) -> str | None:
    for name in _SEVERITY_ORDER:
        if getattr(counts, name) > 0:
            return name
    return None


def _candidate_read_scope(user: User, sc, root):
    """The two read_scope hooks every candidate read applies: ONE place, so a
    tightening of either reaches the candidate list and the reassignment list."""
    return (read_scope.entity_clause(user, root), read_scope.domain_clause(user, sc))


def _candidate_query(db: Session, user: User, *, candidate_ids):
    """The SELECT every candidate read shares: candidate + calculated
    strength + stored-or-default affiliate, behind both read_scope hooks."""
    sc = ScopeCandidate
    root, aff = aliased(OrgEntity), aliased(OrgEntity)
    st = strength_sql.strength_subquery(candidate_ids=candidate_ids)
    aff_id = _aff_id_expr()
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
        .where(*_candidate_read_scope(user, sc, root))
    )
    return query, st, aff_id


def _names(db: Session, ids: set[uuid.UUID]) -> dict[uuid.UUID, str]:
    if not ids:
        return {}
    return {i: n for i, n in db.execute(select(OrgEntity.id, OrgEntity.legal_name).where(OrgEntity.id.in_(ids))).all()}


def _rows(db: Session, user: User, result_rows) -> list[CandidateRow]:
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
    rollups = _target_rollups(
        db, user,
        {r.ScopeCandidate.target_id for r in result_rows
         if r.ScopeCandidate.status == "claimed" and r.ScopeCandidate.target_id is not None},
    )
    out: list[CandidateRow] = []
    for r in result_rows:
        c = r.ScopeCandidate
        rollup = rollups.get(c.target_id) if c.status == "claimed" and c.target_id is not None else None
        out.append(CandidateRow(
            id=c.id, root_entity_id=c.root_entity_id, value=c.value, kind=c.kind, status=c.status,
            strength=r.strength, proposable=bool(r.proposable),
            affiliated=AffiliateRef(id=r.aff_id, name=r.aff_name),
            affiliated_is_default=c.affiliated_entity_id is None,
            signals=sorted(summaries.get(c.id, []), key=lambda s: (s.tier, s.signal_type)),
            first_seen_at=first_seen[c.id].isoformat() if c.id in first_seen else None,
            previously_rejected=previous.get(c.id),
            target_id=c.target_id,
            decided_by_connector_instance_id=c.decided_by_connector_instance_id,
            rir=c.rir, rir_handle=c.rir_handle,
            asset_count=rollup[0] if rollup else None,
            open_findings=rollup[1] if rollup else None,
            worst_severity=_worst(rollup[1]) if rollup else None,
        ))
    return out


def _one_row(db: Session, user: User, candidate_id: uuid.UUID) -> tuple[CandidateRow, ScopeCandidate]:
    query, _st, _aff = _candidate_query(db, user, candidate_ids=[candidate_id])
    row = db.execute(query.where(ScopeCandidate.id == candidate_id).execution_options(populate_existing=True)).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Candidate not found")
    return _rows(db, user, [row])[0], row.ScopeCandidate


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
    # After the add's commit: check the seed against anything else claimed in
    # the new root, and (part C) generate from it.
    background_tasks.add_task(runner.verify_after_claim, result.candidate.id)
    if run is not None:
        from app.api.entities import _run_ingest_then_read
        from app.services import onboarding

        followup = onboarding.followup_read if data.relationship == "ours" else _no_followup_for_ma_target
        background_tasks.add_task(_run_ingest_then_read, run.id, entity.id, entity.cik, current_user.id, followup)
    return AddOrganizationResponse(
        organization_id=entity.id,
        relationship=data.relationship,
        engagement=EngagementRef(id=engagement.id, name=engagement.name, posture=engagement.posture, deal_reference=engagement.deal_reference) if engagement else None,
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
    counts = {
        r.root_entity_id: r
        for r in db.execute(
            select(
                sc.root_entity_id,
                func.count().filter(sc.status == "claimed").label("claimed"),
                func.count().filter(strength_sql.is_to_review(sc.status, st)).label("proposed"),
                func.count().filter(strength_sql.is_lead(sc.status, st)).label("leads"),
                func.count().filter(sc.status == "rejected").label("rejected"),
            )
            .select_from(sc)
            .outerjoin(st.subquery, st.candidate_id == sc.id)
            .where(sc.root_entity_id.in_(root_ids), sc.kind == "domain", read_scope.domain_clause(current_user, sc))
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
            engagement=EngagementRef(id=e.id, name=e.name, posture=e.posture, deal_reference=e.deal_reference) if e else None,
            claimed=c.claimed if c else 0, proposed=c.proposed if c else 0,
            leads=c.leads if c else 0, rejected=c.rejected if c else 0,
        ))
    return out


# ── catalogue, tree, summary ────────────────────────────────────────────────


@router.get("/signal-types", response_model=list[SignalTypeResponse])
def list_signal_types(_=Depends(require_permission(Permission.ENTITIES_READ))):
    """The static signal catalogue (`tiers.SIGNALS`), for labels and filters."""
    return [
        SignalTypeResponse(
            signal_type=t, tier=spec.tier, family=spec.family, label=spec.label,
            description=spec.description, built=spec.built,
        )
        for t, spec in SIGNALS.items()
    ]


@router.get("/locate/{entity_id}", response_model=LocateResponse)
def locate_entity(
    entity_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ENTITIES_READ)),
):
    """Which organization page shows this entity? Membership is decided by the same
    read-scoped `org_tree` walk `/tree` uses, so the page always contains the node."""
    ent = aliased(OrgEntity)
    entity = db.execute(
        select(ent).where(ent.id == entity_id, read_scope.entity_clause(current_user, ent))
    ).scalar_one_or_none()
    if entity is None:
        raise HTTPException(status_code=404, detail="Entity not found")
    if entity.relationship is not None and _visible_root(db, current_user, entity.id):
        return LocateResponse(org_id=entity.id, node=None)
    # resolve() only proposes candidates (it ignores read scope); the tree decides.
    stops = sorted(entity_relationship.resolve(db, entity_id).stops, key=lambda s: (s.depth, str(s.entity_id)))
    for stop in stops:
        if not _visible_root(db, current_user, stop.entity_id):
            continue
        for n in org_tree_sql.org_tree(db, current_user, stop.entity_id):
            if n.entity_id == entity_id and n.status == "confirmed":
                return LocateResponse(org_id=stop.entity_id, node=entity_id)
    raise HTTPException(status_code=404, detail="Not part of an organization you can see")


@router.get("/{org_id}/tree", response_model=list[TreeNodeResponse])
def get_tree(
    org_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ENTITIES_READ)),
):
    _require_visible_root(db, current_user, org_id)
    return [
        TreeNodeResponse(
            entity_id=n.entity_id, name=n.name, parent_id=n.parent_id, relation=n.relation,
            event_date=n.event_date.isoformat() if n.event_date else None, status=n.status, depth=n.depth,
        )
        for n in org_tree_sql.org_tree(db, current_user, org_id)
    ]


@router.get("/{org_id}/summary", response_model=OrganizationDetailSummary)
def get_summary(
    org_id: uuid.UUID,
    subtree_of: uuid.UUID | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ENTITIES_READ)),
):
    _require_visible_root(db, current_user, org_id)
    nodes = org_tree_sql.org_tree(db, current_user, org_id)
    scope_ids = _subtree_or_404(db, current_user, org_id, subtree_of) if subtree_of is not None else None
    sc = ScopeCandidate
    st = strength_sql.strength_subquery(candidate_ids=select(sc.id).where(sc.root_entity_id == org_id))
    in_scope = [sc.root_entity_id == org_id, sc.kind == "domain", read_scope.domain_clause(current_user, sc)]
    if scope_ids is not None:
        in_scope.append(_aff_id_expr().in_(scope_ids))
    c = db.execute(
        select(
            func.count().filter(sc.status == "claimed").label("claimed"),
            func.count().filter(strength_sql.is_to_review(sc.status, st)).label("to_review"),
            func.count().filter(strength_sql.is_lead(sc.status, st)).label("leads"),
            func.count().filter(sc.status == "rejected").label("rejected"),
        )
        .select_from(sc)
        .outerjoin(st.subquery, st.candidate_id == sc.id)
        .where(*in_scope)
    ).one()
    claimed_targets = select(sc.target_id).where(*in_scope, sc.status == "claimed", sc.target_id.is_not(None))
    assets = db.execute(
        select(func.count(func.distinct(TargetAssetLink.asset_canonical_id)))
        .join(AssetCanonical, AssetCanonical.id == TargetAssetLink.asset_canonical_id)
        .where(TargetAssetLink.target_id.in_(claimed_targets), read_scope.asset_clause(current_user, AssetCanonical))
    ).scalar_one()
    has_filer = db.execute(select(OrgEntity.cik.is_not(None)).where(OrgEntity.id == org_id)).scalar_one()
    return OrganizationDetailSummary(
        claimed=c.claimed, to_review=c.to_review, leads=c.leads, rejected=c.rejected,
        assets_under_claimed_scope=assets, has_filer=bool(has_filer),
        affiliates=sum(1 for n in nodes if n.status == "confirmed" and n.parent_id is not None),
        proposed_affiliates=sum(1 for n in nodes if n.status == "proposed"),
    )


@router.get("/{org_id}/acquisitions", response_model=AcquisitionRollup)
def get_acquisitions(
    org_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ENTITIES_READ)),
):
    """What risk each acquisition brought into the estate: one row per confirmed
    acquisition plus an organic row, counting CLAIMED scope only (rules in
    `org_discovery.rollup`). Four queries, aggregated in Python."""
    _require_visible_root(db, current_user, org_id)
    nodes = org_tree_sql.org_tree(db, current_user, org_id)
    deal_map = rollup.deal_of(nodes)
    sc = ScopeCandidate

    # 1. Claimed and to-review candidates, with their bucket's affiliate.
    st = strength_sql.strength_subquery(candidate_ids=select(sc.id).where(sc.root_entity_id == org_id))
    to_review = strength_sql.is_to_review(sc.status, st)
    cand_rows = db.execute(
        select(sc.id, _aff_id_expr().label("aff_id"), sc.kind, sc.target_id, sc.decided_at, sc.status, to_review.label("to_review"))
        .select_from(sc)
        .outerjoin(st.subquery, st.candidate_id == sc.id)
        .where(sc.root_entity_id == org_id, read_scope.domain_clause(current_user, sc), or_(sc.status == "claimed", to_review))
    ).all()

    # An affiliate that is not a confirmed node (a proposed company, or one
    # outside the tree) is not a deal: its candidates count as organic.
    bucket_of = {c.id: deal_map.get(c.aff_id) for c in cand_rows}
    claimed = [c for c in cand_rows if c.status == "claimed"]
    claims = [rollup.Claim(c.id, c.kind, c.target_id, c.decided_at) for c in claimed if c.target_id is not None]
    target_ids = {c.target_id for c in claims}

    # 2. Links to readable assets, each asset attributed to ONE candidate.
    links = []
    if target_ids:
        links = db.execute(
            select(TargetAssetLink.target_id, TargetAssetLink.asset_canonical_id)
            .join(AssetCanonical, AssetCanonical.id == TargetAssetLink.asset_canonical_id)
            .where(TargetAssetLink.target_id.in_(target_ids), read_scope.asset_clause(current_user, AssetCanonical))
        ).all()
    owner = rollup.attribute(claims, [(t, a) for t, a in links])

    # 3. Open findings per asset and severity, "open" exactly as `_target_rollups` defines it.
    fnd = FindingCanonical
    finding_rows = []
    if owner:
        finding_rows = db.execute(
            select(
                fnd.asset_canonical_id, fnd.severity, func.count(func.distinct(fnd.id)),
                func.count(func.distinct(fnd.id)).filter(fnd.kev.is_(True)),
                func.coalesce(func.sum(func.coalesce(fnd.risk_score, 0)), 0),
            )
            .join(AssetCanonical, AssetCanonical.id == fnd.asset_canonical_id)
            .where(
                fnd.asset_canonical_id.in_(
                    select(TargetAssetLink.asset_canonical_id).where(TargetAssetLink.target_id.in_(target_ids))
                ),
                fnd.state.in_(_OPEN_STATES),
                _NOT_EXCLUDED_FROM_MAIN,
                read_scope.finding_clause(current_user, fnd, AssetCanonical),
            )
            .group_by(fnd.asset_canonical_id, fnd.severity)
        ).all()

    # 4. Target -> posture.
    posture_of: dict[uuid.UUID, str] = {}
    if target_ids:
        posture_of = {
            t: (p if p is not None else "estate")
            for t, p in db.execute(
                select(Target.id, Engagement.posture)
                .outerjoin(Engagement, Engagement.id == Target.engagement_id)
                .where(Target.id.in_(target_ids))
            ).all()
        }

    # ── aggregate ───────────────────────────────────────────────────────────
    buckets: list[uuid.UUID | None] = [n.entity_id for n in nodes if n.status == "confirmed" and n.relation == "acquired"]
    buckets.append(None)
    agg = {
        b: {"dom": 0, "dom_rev": 0, "asn": 0, "cidr": 0, "ip_rev": 0, "assets": 0, "kev": 0, "risk": 0,
            "sev": {}, "postures": set()}
        for b in buckets
    }
    for c in cand_rows:
        a = agg[bucket_of[c.id]]
        if c.status == "claimed":
            key = {"domain": "dom", "asn": "asn", "cidr": "cidr"}.get(c.kind)
            if key:
                a[key] += 1
            if c.target_id is not None and c.target_id in posture_of:
                a["postures"].add(posture_of[c.target_id])
        elif c.to_review:
            a["dom_rev" if c.kind == "domain" else "ip_rev"] += 1
    for asset_id, cand_id in owner.items():
        agg[bucket_of[cand_id]]["assets"] += 1
    for asset_id, severity, n, kev_n, risk in finding_rows:
        cand_id = owner.get(asset_id)
        if cand_id is None:
            continue  # an asset the caller may not read (asset_clause), or one with no claim
        a = agg[bucket_of[cand_id]]
        bucket = severity if severity in _SEVERITY_ORDER else "unknown"
        a["sev"][bucket] = a["sev"].get(bucket, 0) + n
        a["kev"] += kev_n
        a["risk"] += int(risk)
    estate = sum(a["risk"] for a in agg.values())

    by_id = {n.entity_id: n for n in nodes}
    out: list[AcquisitionRow] = []
    for b in buckets:
        a = agg[b]
        counts = SeverityCounts(**a["sev"])
        node = by_id[b] if b is not None else nodes[0]
        out.append(AcquisitionRow(
            entity_id=b, name=node.name, organic=b is None,
            closed=node.event_date.isoformat() if b is not None and node.event_date else None,
            closed_precision=node.event_date_precision if b is not None else None,
            postures=sorted(a["postures"]),
            domains_claimed=a["dom"], domains_to_review=a["dom_rev"], asns_claimed=a["asn"], cidrs_claimed=a["cidr"],
            ip_to_review=a["ip_rev"], assets=a["assets"], open_findings=counts, worst_severity=_worst(counts),
            kev=a["kev"], risk_score_sum=a["risk"], risk_share=(a["risk"] / estate) if estate > 0 else None,
        ))
    organic = out.pop()
    out.sort(key=lambda r: r.name)
    dated = sorted((r for r in out if r.closed is not None), key=lambda r: r.closed, reverse=True)  # stable
    undated = [r for r in out if r.closed is None]
    return AcquisitionRollup(rows=[*dated, *undated, organic], estate_risk_score_sum=estate)


# ── candidates ──────────────────────────────────────────────────────────────


@router.get("/{org_id}/candidates", response_model=CandidatePage)
def list_candidates(
    org_id: uuid.UUID,
    status: Literal["open", "claimed", "rejected", "all"] = "open",
    kind: Literal["domain", "asn", "cidr"] = "domain",
    include_leads: bool = False,
    strength: Literal["strong", "supporting", "lead", "context"] | None = None,
    affiliated_entity_id: uuid.UUID | None = None,
    subtree_of: uuid.UUID | None = None,
    q: str | None = Query(None, max_length=253),
    signal_type: str | None = None,
    leads_only: bool = False,
    reassigned: bool | None = None,
    limit: int = Query(_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ENTITIES_READ)),
):
    _require_visible_root(db, current_user, org_id)
    if signal_type is not None and signal_type not in SIGNALS:
        raise HTTPException(status_code=422, detail="Unknown signal_type")
    scope_ids = _subtree_or_404(db, current_user, org_id, subtree_of) if subtree_of is not None else None
    sc = ScopeCandidate
    query, st, aff_id = _candidate_query(
        db, current_user, candidate_ids=select(sc.id).where(sc.root_entity_id == org_id)
    )
    query = query.where(sc.root_entity_id == org_id, sc.kind == kind)
    if leads_only:
        # Exactly the summary's `leads` bucket: status / include_leads do not apply.
        query = query.where(strength_sql.is_lead(sc.status, st))
    else:
        if status != "all":
            query = query.where(sc.status == status)
        if not include_leads:
            # An open candidate is shown only once it clears the propose bar.
            query = query.where(or_(sc.status != "open", st.proposable))
    if scope_ids is not None:
        query = query.where(aff_id.in_(scope_ids))
    if q:
        # Bound parameter; LIKE wildcards in the input are matched literally.
        literal = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        query = query.where(sc.value.ilike(f"%{literal}%", escape="\\"))
    if signal_type is not None:
        query = query.where(
            exists().where(ScopeSignal.candidate_id == sc.id, ScopeSignal.signal_type == signal_type)
        )
    if strength is not None:
        query = query.where(st.strength == strength)
    if affiliated_entity_id is not None:
        query = query.where(aff_id == affiliated_entity_id)
    if reassigned is not None:
        has_rows = exists().where(ScopeCandidateReassignment.candidate_id == sc.id)
        query = query.where(has_rows if reassigned else ~has_rows)
    total = db.execute(select(func.count()).select_from(query.order_by(None).subquery())).scalar_one()
    query = query.order_by(st.rank.desc(), sc.value, sc.id).limit(limit).offset(offset)
    return CandidatePage(items=_rows(db, current_user, db.execute(query).all()), total=total)


@router.get("/{org_id}/reassignments", response_model=ReassignmentPage)
def list_reassignments(
    org_id: uuid.UUID,
    candidate_id: uuid.UUID | None = None,
    new_holder_kind: Literal["org", "customer", "unknown", "unregistered"] | None = None,
    seen_since: datetime | None = None,
    limit: int = Query(_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ENTITIES_READ)),
):
    """Reassigned-away records of this organization's claimed CIDR candidates
    (planning#278 S3c3b2). A candidate_id of another root yields no rows."""
    _require_visible_root(db, current_user, org_id)
    sc, ra = ScopeCandidate, ScopeCandidateReassignment
    root = aliased(OrgEntity)
    query = (
        select(ra, sc.value, sc.rir, sc.rir_handle)
        .select_from(ra)
        .join(sc, sc.id == ra.candidate_id)
        .join(root, root.id == sc.root_entity_id)
        .where(*_candidate_read_scope(current_user, sc, root), sc.root_entity_id == org_id)
    )
    if candidate_id is not None:
        query = query.where(ra.candidate_id == candidate_id)
    if new_holder_kind is not None:
        query = query.where(ra.new_holder_kind == new_holder_kind)
    if seen_since is not None:
        query = query.where(ra.last_seen_at >= seen_since)
    total = db.execute(select(func.count()).select_from(query.order_by(None).subquery())).scalar_one()
    query = query.order_by(ra.last_seen_at.desc(), ra.prefix, ra.id).limit(limit).offset(offset)
    items = [
        ReassignmentRow(
            id=r.id, candidate_id=r.candidate_id, candidate_value=value, rir=rir, rir_handle=handle,
            prefix=r.prefix, new_holder_kind=r.new_holder_kind, new_holder_handle=r.new_holder_handle,
            evidence_id=r.evidence_id, first_detected_at=r.first_detected_at.isoformat(),
            last_seen_at=r.last_seen_at.isoformat(),
        )
        for r, value, rir, handle in db.execute(query).all()
    ]
    return ReassignmentPage(items=items, total=total)


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
            quote=s.quote, evidence_id=s.evidence_id, matched_values=s.matched_values,
            first_seen_at=s.first_seen_at.isoformat(), last_seen_at=s.last_seen_at.isoformat(),
        )
        for s in signals
    ]
    events = db.execute(
        select(ScopeCandidateEvent).where(ScopeCandidateEvent.candidate_id == candidate_id)
        .order_by(ScopeCandidateEvent.at, ScopeCandidateEvent.id)
    ).scalars().all()
    connector_name = None
    if candidate.decided_by_connector_instance_id is not None:
        connector_name = db.execute(
            select(ConnectorInstance.name).where(
                ConnectorInstance.id == candidate.decided_by_connector_instance_id,
                read_scope.connector_instance_clause(current_user, ConnectorInstance),
            )
        ).scalar_one_or_none()
    return CandidateDetail(
        **row.model_dump(),
        signal_details=details,
        events=[EventDetail(event=e.event, at=e.at.isoformat(), user_id=e.user_id, reason=e.reason, signal_id=e.signal_id,
                            connector_instance_id=e.connector_instance_id)
                for e in events],
        rejection_reason=candidate.rejection_reason,
        decided_at=candidate.decided_at.isoformat() if candidate.decided_at else None,
        accepted_into=candidate.accepted_into,
        engagement_id=candidate.engagement_id,
        decided_by_id=candidate.decided_by_id,
        decided_by_connector_name=connector_name,
    )


@router.post("/{org_id}/candidates", response_model=CandidateRow, status_code=201)
def add_candidate(
    request: Request,
    org_id: uuid.UUID,
    data: AddCandidateRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ENTITIES_PROPOSE_CANDIDATE)),
):
    """A person adds a domain WITH its evidence (a Strong `person_evidence`
    signal); nothing here looks a domain up from a name."""
    _require_visible_root(db, current_user, org_id)
    created: list[uuid.UUID] = []
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
            new_candidate_ids=created,
        )
    except candidates.CandidateError as exc:
        raise _http_error(exc)
    audit.record_detail(
        request, candidate=str(candidate.id), organization=str(org_id), value=candidate.value,
        signal="person_evidence",
    )
    if created:  # add_by_person has committed
        background_tasks.add_task(runner.verify_new_candidates, created)
    return _one_row(db, current_user, candidate.id)[0]


@router.post("/{org_id}/recheck", response_model=RecheckAccepted, status_code=202)
def recheck_organization(
    request: Request,
    org_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ENTITIES_DECIDE_CANDIDATE)),
):
    """Re-asks ARIN and RIPE for every claimed domain of the root, ignoring
    cache rows older than the run start, then runs the dedicated-IP sweep.
    Passive registry lookups; never un-claims anything."""
    _require_visible_root(db, current_user, org_id)
    n = db.scalar(
        select(func.count()).select_from(ScopeCandidate).where(
            ScopeCandidate.root_entity_id == org_id,
            ScopeCandidate.kind == "domain",
            ScopeCandidate.status == "claimed",
        )
    ) or 0
    if not runner.try_begin_recheck(org_id):
        raise HTTPException(409, "A re-check of this organization is already running")
    audit.record_detail(request, organization=str(org_id), claimed_domains=n)
    background_tasks.add_task(runner.recheck_root, org_id)
    return RecheckAccepted(claimed_domains=n)


@router.post("/candidates/{candidate_id}/claim", response_model=ClaimResponse)
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
        target=str(result.target.id) if result.target is not None else None,
        created=result.created,
        kind=c.kind,
        claimed_prefixes=[str(p.candidate.id) for p in result.prefixes],
    )
    from app.api.targets import _launch_initial_discovery

    if result.created:
        _launch_initial_discovery(db, result.target, current_user.id, background_tasks)
    for prefix in result.prefixes:
        if prefix.created:
            _launch_initial_discovery(db, prefix.target, current_user.id, background_tasks)
    if c.kind == "domain":
        background_tasks.add_task(runner.verify_after_claim, c.id)
    row = _one_row(db, current_user, candidate_id)[0]
    return ClaimResponse(**row.model_dump(), claimed_prefixes=len(result.prefixes))


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
