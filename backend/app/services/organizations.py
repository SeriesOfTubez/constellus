"""Add an organization (planning#277 S1a): one atomic act.

An organization is a root: an `org_entities` row with a `relationship`
(`ours` or `ma_target`), whose tree the discovery signals attach to. Adding
one records, in ONE transaction:

1. the entity (or, for a CIK that already has a bare entity, that entity),
2. its relationship (`ours`, or `ma_target` with a NEW `pre_close`
   engagement named by the caller),
3. the seed domain as a `scope_candidates` row carrying an `admin_seed`
   signal, claimed straight away into the organization's destination (our
   estate, or the new engagement) as a `Target`,
4. for an M&A target, a `viewer` assignment on the new engagement for a caller
   who does not already read every restricted engagement (an admin does),
5. when a CIK was given, a queued EDGAR ingest (the ROUTE schedules the
   background task after this commits).

Any error and nothing is written: this function owns the transaction and
rolls back before re-raising.

`org_name` flows to exactly one place, `OrgEntity(legal_name=...)`; it is
never an input to a signal (pinned by `test_org_discovery_invariants.py`).

## Engagement authorisation is NOT set here

planning#277's spec asked for `authorised_by_id` / `authorised_at` /
`authorisation_reference` on the new engagement. Migration 0059's
`ck_engagements_authorisation_matches_posture` allows those only on a
`day_0` / `integrated` engagement (a `pre_close` row carrying them "would
read as authorised, and it is not"), and a new engagement here is
`pre_close`. The reference is therefore recorded in the audit row by the
route, not on the engagement.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.permissions import Permission, has_permission
from app.models.engagement import Engagement
from app.models.entity_ingest_run import EntityIngestRun
from app.models.org_entity import RELATIONSHIP_MA_TARGET, RELATIONSHIP_OURS, OrgEntity
from app.models.role_assignment import RoleAssignment
from app.models.scope_candidate import ScopeCandidate
from app.models.target import Target
from app.services import entity_relationship
from app.services.org_discovery import candidates

MAX_ORG_NAME = 200
SEED_ELSEWHERE_MESSAGE = "the seed domain is already a target elsewhere"
_CIK_INPUT_RE = re.compile(r"^\d{1,10}$")


@dataclass
class AddResult:
    entity: OrgEntity
    engagement: Engagement | None
    candidate: ScopeCandidate
    target: Target
    assignment: RoleAssignment | None
    ingest_run: EntityIngestRun | None
    engagement_created: bool = False
    target_created: bool = False


def add_organization(
    db: Session,
    *,
    seed_domain: str,
    org_name: str,
    cik: str | None,
    relationship: str,
    reference: str,
    engagement_name: str | None,
    user,
    may_mark_ours: bool,
) -> AddResult:
    # ── 1. validate (before touching the database) ─────────────────────────
    org_name = (org_name or "").strip()
    if not 1 <= len(org_name) <= MAX_ORG_NAME:
        raise candidates.CandidateInvalid(f"organization name must be 1 to {MAX_ORG_NAME} characters")
    reference = (reference or "").strip()
    if not reference:
        raise candidates.CandidateInvalid("a reference is required")
    if relationship not in (RELATIONSHIP_OURS, RELATIONSHIP_MA_TARGET):
        raise candidates.CandidateInvalid("relationship must be 'ours' or 'ma_target'")
    engagement_name = engagement_name.strip() if engagement_name is not None else None
    if relationship == RELATIONSHIP_MA_TARGET:
        if not engagement_name:
            raise candidates.CandidateInvalid("an engagement name is required for an M&A target")
    elif engagement_name is not None:
        raise candidates.CandidateInvalid("an engagement name is only for an M&A target")
    seed = candidates.normalise_domain(seed_domain)
    if cik is not None:
        cik = cik.strip()
        if not _CIK_INPUT_RE.match(cik):
            raise candidates.CandidateInvalid("cik must be 1 to 10 digits")
        cik = cik.zfill(10)

    # ── 2. marking a company ours is an authorisation ──────────────────────
    if relationship == RELATIONSHIP_OURS and not may_mark_ours:
        raise candidates.CandidateForbidden("only an admin can mark a company as ours")

    try:
        result = _write(
            db, seed=seed, org_name=org_name, cik=cik, relationship=relationship, reference=reference,
            engagement_name=engagement_name, user=user, may_mark_ours=may_mark_ours,
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        constraint = getattr(getattr(exc.orig, "diag", None), "constraint_name", None) or "integrity error"
        raise candidates.CandidateConflict(f"could not add the organization ({constraint}); nothing was changed") from exc
    except Exception:
        db.rollback()
        raise
    db.refresh(result.entity)
    db.refresh(result.candidate)
    db.refresh(result.target)
    if result.engagement is not None:
        db.refresh(result.engagement)
    return result


def _write(
    db: Session, *, seed: str, org_name: str, cik: str | None, relationship: str, reference: str,
    engagement_name: str | None, user, may_mark_ours: bool,
) -> AddResult:
    """Everything that writes; flushes only. The caller commits or rolls back."""
    # ── 3. the entity ──────────────────────────────────────────────────────
    entity = None
    if cik is not None:
        entity = db.execute(
            select(OrgEntity).where(OrgEntity.cik == cik).with_for_update()
        ).scalar_one_or_none()
    if entity is not None:
        is_subject = db.execute(
            select(Engagement.id).where(Engagement.subject_entity_id == entity.id).limit(1)
        ).first() is not None
        if entity.relationship is not None or is_subject:
            raise candidates.CandidateConflict("that filer is already an organization")
        # The existing entity keeps its legal_name: the caller's text is not
        # allowed to rename a record other data may already cite.
    else:
        entity = OrgEntity(id=uuid.uuid4(), legal_name=org_name, cik=cik, created_by_id=user.id)
        db.add(entity)
        db.flush()

    # ── 4. the relationship (the same cores the PUT route uses) ────────────
    engagement: Engagement | None = None
    engagement_created = False
    if relationship == RELATIONSHIP_OURS:
        entity_relationship._apply_ours(db, entity, reference, user)
    else:
        _prev, engagement, engagement_created = entity_relationship._apply_ma_target(
            db, entity, user, None, engagement_name, may_mark_ours,
            deal_reference=reference,
        )

    # ── 5. the seed domain: signal, then claim ─────────────────────────────
    outcome = candidates.record_signal(
        db,
        root_entity_id=entity.id,
        value=seed,
        signal_type="admin_seed",
        anchor_kind="person",
        anchor_user_id=user.id,
        via_entity_id=entity.id,
    )
    candidate = outcome.candidate
    if candidate is None or candidate.status != "open":
        status = candidate.status if candidate is not None else "missing"
        raise candidates.CandidateConflict(f"the seed domain is already a candidate of this organization ({status})")
    claimed = candidates._claim_seed(
        db, candidate=candidate, root=entity, engagement=engagement, user=user,
        elsewhere_message=SEED_ELSEWHERE_MESSAGE,
    )

    # ── 6. a non-admin who creates a deal can see it ───────────────────────
    assignment: RoleAssignment | None = None
    if engagement is not None and not has_permission(user, Permission.ENGAGEMENTS_READ_RESTRICTED):
        assignment = RoleAssignment(user_id=user.id, role="viewer", engagement_id=engagement.id)
        db.add(assignment)
        db.flush()

    # ── 7. queue the filer's ingest ────────────────────────────────────────
    run: EntityIngestRun | None = None
    if cik is not None:
        run = EntityIngestRun(cik=cik, status="queued", requested_by_id=user.id)
        try:
            with db.begin_nested():
                db.add(run)
        except IntegrityError:
            # An ingest of this CIK is already in flight
            # (uq_entity_ingest_runs_active_kind_cik). Not an error: the
            # organization is added either way.
            run = None

    return AddResult(
        entity=entity, engagement=engagement, candidate=candidate, target=claimed.target,
        assignment=assignment, ingest_run=run, engagement_created=engagement_created,
        target_created=claimed.created,
    )
