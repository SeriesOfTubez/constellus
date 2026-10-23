"""Scope candidates: record signals, add by person, claim, reject
(planning#277 S1a). Replaces the former candidate-domains service.

## No name -> domain path, by construction

Nothing in this package reads `org_entities.legal_name`, and no function
here takes a company name. A candidate exists only because a SIGNAL names its
value, and a signal is either borne by something already decided (a claimed
candidate, a confirmed filer's own filing) or by a person. The chain is
enforced twice: here (`record_signal`) and in the database
(`trg_scope_signals_anchor`, migration 0083).
`tests/test_org_discovery_invariants.py` pins the "no name" half with an AST
walk over every module in this package.

## Transaction ownership (CONTRIBUTING.md)

Helpers `flush()` and never commit. The owners are the top-level functions
documented as such: `add_by_person`, `claim`, `reject`. (`add_by_person`'s
evidence write goes through `entity_graph.store_evidence`, which commits its
own evidence row, as it always has.) `_claim_seed` is the helper
`organizations.add_organization` uses; that function owns the commit.

## Claim creates the target INSIDE its destination, in one transaction

`claim` does not use `target_service.ensure_pending`, which commits a new
target with no engagement (an unrestricted owned-estate target) before a
caller could attach it. The `Target` row is inserted with
`engagement_id`/`entity_id` already set, and the decision is written in the
SAME commit.

The destination comes from the ROOT organization (planning#240, #277): `ours`
-> our estate (no engagement); `ma_target` -> the root's one live engagement.
There is no picker. A root with no relationship, or whose engagements are all
abandoned, blocks the claim.

An existing target with the same value: same destination and a compatible
entity -> attached (idempotent); anything else -> `CandidateConflict`,
nothing changed. Moving a target is a `PATCH /targets/{id}` decision with its
own widening rules.

## Unlock

A rejected candidate comes back to `open` only when a NEW Strong signal of a
type that was NOT present at rejection arrives. Re-seeing the same evidence,
or any Supporting/Context signal, is stored and changes nothing.

## Errors

`CandidateNotFound` (404), `CandidateConflict` (409), `CandidateInvalid`
(400), `CandidateForbidden` (403). Audit rows are the CALLER's job.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import literal_column, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.engagement import Engagement, EngagementPosture
from app.models.org_entity import RELATIONSHIP_MA_TARGET, RELATIONSHIP_OURS, OrgEntity
from app.models.scope_candidate import (
    ANCHOR_KINDS,
    CANDIDATE_KINDS,
    ScopeCandidate,
    ScopeCandidateEvent,
    ScopeSignal,
)
from app.models.target import Target, TargetType, VerificationMethod
from app.services import entity_graph, entity_relationship, target_service
from app.services.org_discovery import strength as strength_sql
from app.services.org_discovery.tiers import SIGNALS, STRONG

TARGET_SOURCE_TYPE = "candidate_domain"

# Same shape as migration 0083's `ck_scope_candidates_domain_shape`.
_DOMAIN_RE = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,63}|xn--[a-z0-9-]{1,59})$")

# A cited URL is stored, never requested -- validated by shape only. Not
# `urllib.parse`: `test_egress_gate_guard` treats any `urllib` import as a
# network transport, and this package must stay one that makes no requests.
_SOURCE_URL_RE = re.compile(r"^https?://[^\s/?#@]+(?:[/?#][^\s]*)?$", re.IGNORECASE)
_MAX_SOURCE_URL = 2048
_MAX_EXCERPT = 50_000
_MAX_QUOTE = 2_000
MAX_REJECTION_REASON = 500

NOT_PROPOSABLE_MESSAGE = "not enough evidence to claim: add evidence or wait for a second independent signal"
NOT_IN_TREE_MESSAGE = "not in this organization's tree"


class CandidateError(Exception):
    pass


class CandidateNotFound(CandidateError):
    pass


class CandidateConflict(CandidateError):
    pass


class CandidateInvalid(CandidateError):
    pass


class CandidateForbidden(CandidateError):
    pass


def normalise_domain(value: str) -> str:
    """Canonical form stored in `scope_candidates.value` and, on claim,
    `targets.value`: `target_service.canonicalize_value` (lowercase,
    punycode, no scheme/path), then a leading `www.` removed. Raises
    `CandidateInvalid` for anything that is not a hostname."""
    try:
        canonical = target_service.canonicalize_value(value or "")
    except Exception as exc:  # canonicalize_value raises on undecodable IDNs
        raise CandidateInvalid(f"not a domain: {exc}") from exc
    if canonical.startswith("www."):
        canonical = canonical[4:]
    if not canonical or not _DOMAIN_RE.match(canonical):
        raise CandidateInvalid("not a domain (expected a hostname such as example.com)")
    try:
        if target_service.detect_type(canonical) != TargetType.DOMAIN:
            raise CandidateInvalid("not a domain")
    except ValueError as exc:
        raise CandidateInvalid(str(exc)) from exc
    return canonical


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── the tree ────────────────────────────────────────────────────────────────


def roots_of(db: Session, entity_id: uuid.UUID) -> list[OrgEntity]:
    """The roots `entity_id` belongs to: the `resolve()` stops' entities
    (ours or ma_target). An entity with no stop has no root, so nothing can
    be anchored to it."""
    stops = entity_relationship.resolve(db, entity_id).stops
    found: list[OrgEntity] = []
    for stop in stops:
        entity = db.get(OrgEntity, stop.entity_id)
        if entity is not None and entity not in found:
            found.append(entity)
    return found


def _in_tree(db: Session, root_entity_id: uuid.UUID, entity_id: uuid.UUID) -> bool:
    return root_entity_id in {s.entity_id for s in entity_relationship.resolve(db, entity_id).stops}


# ── signals ─────────────────────────────────────────────────────────────────


@dataclass
class SignalOutcome:
    outcome: str  # "recorded" | "skipped_context_only"
    candidate: ScopeCandidate | None = None
    signal: ScopeSignal | None = None
    created_candidate: bool = False
    created_signal: bool = False
    unlocked: bool = False


def record_signal(
    db: Session,
    *,
    root_entity_id: uuid.UUID,
    value: str,
    kind: str = "domain",
    signal_type: str,
    anchor_kind: str,
    anchor_candidate_id: uuid.UUID | None = None,
    anchor_entity_id: uuid.UUID | None = None,
    anchor_user_id: uuid.UUID | None = None,
    via_entity_id: uuid.UUID,
    evidence_id: uuid.UUID | None = None,
    quote: str | None = None,
    observer_id: uuid.UUID | None = None,
) -> SignalOutcome:
    """Record one signal for (root, kind, value), creating the candidate if
    this is its first Strong/Supporting signal. Flushes; never commits."""
    spec = SIGNALS.get(signal_type)
    if spec is None:
        raise CandidateInvalid(f"unknown signal type {signal_type!r}")
    if kind not in CANDIDATE_KINDS:
        raise CandidateInvalid(f"unknown candidate kind {kind!r}")
    value = normalise_domain(value)
    if anchor_kind not in ANCHOR_KINDS:
        raise CandidateInvalid(f"unknown anchor kind {anchor_kind!r}")

    if (evidence_id is None) != (quote is None):
        raise CandidateInvalid("evidence and quote are given together or not at all")
    if evidence_id is None and signal_type != "admin_seed":
        raise CandidateInvalid("this signal type needs evidence and a quote")
    if quote is not None:
        if not quote.strip():
            raise CandidateInvalid("quote is required")
        if len(quote) > _MAX_QUOTE:
            raise CandidateInvalid(f"quote is longer than {_MAX_QUOTE} characters")
        if value not in quote.lower():
            raise CandidateInvalid("quote must contain the domain as written (ASCII or punycode form)")

    if not _in_tree(db, root_entity_id, via_entity_id):
        raise CandidateInvalid(f"via entity is {NOT_IN_TREE_MESSAGE}")

    if anchor_kind == "filer_filing":
        if anchor_entity_id is None:
            raise CandidateInvalid("a filer_filing anchor needs the filer entity")
        filer = db.get(OrgEntity, anchor_entity_id)
        if filer is None or not filer.cik:
            raise CandidateInvalid("the anchoring filer has no CIK")
        if not _in_tree(db, root_entity_id, anchor_entity_id):
            raise CandidateInvalid(f"anchoring filer is {NOT_IN_TREE_MESSAGE}")
    elif anchor_kind == "claimed_candidate":
        if anchor_candidate_id is None:
            raise CandidateInvalid("a claimed_candidate anchor needs the anchoring candidate")
        anchor = db.get(ScopeCandidate, anchor_candidate_id)
        if anchor is None or anchor.status != "claimed" or anchor.root_entity_id != root_entity_id:
            raise CandidateInvalid("the anchoring candidate must be claimed, under the same organization")

    candidate = db.execute(
        select(ScopeCandidate)
        .where(
            ScopeCandidate.root_entity_id == root_entity_id,
            ScopeCandidate.kind == kind,
            ScopeCandidate.value == value,
        )
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    created_candidate = False
    if candidate is None:
        if spec.tier not in (STRONG, "supporting"):
            # A Context signal never creates a candidate.
            return SignalOutcome(outcome="skipped_context_only")
        inserted = db.execute(
            pg_insert(ScopeCandidate.__table__)
            .values(id=uuid.uuid4(), root_entity_id=root_entity_id, kind=kind, value=value, status="open")
            .on_conflict_do_nothing(constraint="uq_scope_candidates_root_kind_value")
            .returning(ScopeCandidate.__table__.c.id)
        ).scalar()
        created_candidate = inserted is not None
        candidate = db.execute(
            select(ScopeCandidate)
            .where(
                ScopeCandidate.root_entity_id == root_entity_id,
                ScopeCandidate.kind == kind,
                ScopeCandidate.value == value,
            )
            .execution_options(populate_existing=True)
        ).scalar_one()

    table = ScopeSignal.__table__
    row = db.execute(
        pg_insert(table)
        .values(
            id=uuid.uuid4(),
            candidate_id=candidate.id,
            signal_type=signal_type,
            anchor_kind=anchor_kind,
            anchor_candidate_id=anchor_candidate_id,
            anchor_entity_id=anchor_entity_id,
            anchor_user_id=anchor_user_id,
            via_entity_id=via_entity_id,
            evidence_id=evidence_id,
            quote=quote,
            observer_id=observer_id,
        )
        .on_conflict_do_update(constraint="uq_scope_signals_route", set_={"last_seen_at": _now()})
        .returning(table.c.id, literal_column("(xmax = 0)").label("inserted"))
    ).one()
    created_signal = bool(row.inserted)
    signal = db.execute(
        select(ScopeSignal).where(ScopeSignal.id == row.id).execution_options(populate_existing=True)
    ).scalar_one()

    unlocked = False
    if created_signal and spec.tier == STRONG:
        # Whatever status we read above: a reject may have committed since,
        # without our new type among its `rejected_strong_types`. The helper
        # locks the row and re-checks.
        unlocked = _maybe_unlock(db, candidate_id=candidate.id, signal=signal)
        if unlocked:
            db.refresh(candidate)
    db.flush()
    return SignalOutcome(
        outcome="recorded", candidate=candidate, signal=signal,
        created_candidate=created_candidate, created_signal=created_signal, unlocked=unlocked,
    )


def _maybe_unlock(db: Session, *, candidate_id: uuid.UUID, signal: ScopeSignal) -> bool:
    candidate = db.execute(
        select(ScopeCandidate).where(ScopeCandidate.id == candidate_id).with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one()
    if candidate.status != "rejected" or signal.signal_type in (candidate.rejected_strong_types or []):
        return False
    old_reason = candidate.rejection_reason
    candidate.status = "open"
    candidate.rejection_reason = None
    candidate.rejected_strong_types = None
    candidate.decided_at = None
    candidate.decided_by_id = None
    db.add(ScopeCandidateEvent(
        id=uuid.uuid4(), candidate_id=candidate.id, event="unlocked", reason=old_reason, signal_id=signal.id,
    ))
    db.flush()
    return True


# ── a person adds a domain ──────────────────────────────────────────────────


def add_by_person(
    db: Session,
    *,
    root_entity_id: uuid.UUID,
    via_entity_id: uuid.UUID,
    domain: str,
    source_url: str,
    excerpt: str,
    quote: str,
    user,
) -> ScopeCandidate:
    """A person adds a domain with evidence. `excerpt` is stored as
    `person_supplied` evidence attributed to `source_url`; `quote` must be a
    substring of `excerpt` and must contain the domain as written (ASCII or
    punycode). The signal is Strong (`person_evidence`). Owner: commits."""
    if db.get(OrgEntity, root_entity_id) is None:
        raise CandidateNotFound("organization not found")
    domain = normalise_domain(domain)

    source_url = (source_url or "").strip()
    if not _SOURCE_URL_RE.match(source_url) or len(source_url) > _MAX_SOURCE_URL:
        raise CandidateInvalid("source_url must be an http(s) URL")
    if not excerpt or not excerpt.strip():
        raise CandidateInvalid("excerpt is required")
    if len(excerpt) > _MAX_EXCERPT:
        raise CandidateInvalid(f"excerpt is longer than {_MAX_EXCERPT} characters")
    quote = (quote or "").strip()
    if not quote:
        raise CandidateInvalid("quote is required")
    if len(quote) > _MAX_QUOTE:
        raise CandidateInvalid(f"quote is longer than {_MAX_QUOTE} characters")
    if quote not in excerpt:
        raise CandidateInvalid("quote must appear verbatim in the excerpt")
    if domain not in quote.lower():
        raise CandidateInvalid("quote must contain the domain as written (ASCII or punycode form)")
    if not _in_tree(db, root_entity_id, via_entity_id):
        raise CandidateInvalid(f"company is {NOT_IN_TREE_MESSAGE}")

    evidence = entity_graph.store_evidence(
        db,
        content=excerpt.encode("utf-8"),
        content_type="text/plain; charset=utf-8",
        source_url=source_url,
        fetched_at=_now(),
        origin="person_supplied",
    )
    try:
        outcome = record_signal(
            db, root_entity_id=root_entity_id, value=domain, signal_type="person_evidence",
            anchor_kind="person", anchor_user_id=user.id, via_entity_id=via_entity_id,
            evidence_id=evidence.id, quote=quote,
        )
        candidate = outcome.candidate
        db.commit()
    except CandidateError:
        db.rollback()
        raise
    except IntegrityError as exc:
        db.rollback()
        raise CandidateConflict("could not record the domain; it may have been added at the same time") from exc
    db.refresh(candidate)
    return candidate


# ── claim ───────────────────────────────────────────────────────────────────


@dataclass
class ClaimResult:
    candidate: ScopeCandidate
    target: Target
    created: bool


def _strength_row(db: Session, candidate_id: uuid.UUID):
    s = strength_sql.strength_subquery(candidate_ids=[candidate_id])
    return db.execute(
        select(s.subquery.c.proposable, s.subquery.c.strength, s.subquery.c.strong_types)
        .where(s.candidate_id == candidate_id)
    ).one_or_none()


def _live_engagements(db: Session, root_entity_id: uuid.UUID) -> list[Engagement]:
    return list(
        db.execute(
            select(Engagement)
            .where(
                Engagement.subject_entity_id == root_entity_id,
                Engagement.posture != EngagementPosture.ABANDONED.value,
            )
            .order_by(Engagement.created_at, Engagement.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalars()
    )


def _destination(db: Session, root: OrgEntity) -> Engagement | None:
    """The engagement to claim into, or None for our own estate. `root` is
    locked and fresh. Raises unless there is exactly one destination."""
    if root.relationship == RELATIONSHIP_OURS:
        return None
    if root.relationship == RELATIONSHIP_MA_TARGET:
        live = _live_engagements(db, root.id)
        if not live:
            raise CandidateConflict("this deal's engagement was abandoned; nothing can be claimed into it")
        if len(live) > 1:
            raise CandidateConflict("this organization has more than one live engagement; the destination is ambiguous")
        return live[0]
    raise CandidateConflict("set this organization's relationship first (ours or M&A target)")


def _attach_or_create_target(
    db: Session, *, value: str, destination_id: uuid.UUID | None, entity_id: uuid.UUID, user, now: datetime,
    elsewhere_message: str, other_entity_message: str,
) -> tuple[Target, bool]:
    existing = db.execute(select(Target).where(Target.value == value)).scalar_one_or_none()
    if existing is not None:
        if existing.engagement_id != destination_id:
            raise CandidateConflict(elsewhere_message)
        if existing.entity_id is not None and existing.entity_id != entity_id:
            raise CandidateConflict(other_entity_message)
        existing.entity_id = entity_id
        return existing, False
    target = Target(
        id=uuid.uuid4(),
        type=TargetType.DOMAIN.value,
        value=value,
        verified=True,
        verification_method=VerificationMethod.MANUAL.value,
        verified_by_id=user.id,
        verified_at=now,
        source_type=TARGET_SOURCE_TYPE,
        engagement_id=destination_id,
        entity_id=entity_id,
    )
    db.add(target)
    return target, True


def _write_claim(
    db: Session, candidate: ScopeCandidate, *, affiliated_id: uuid.UUID, destination_id: uuid.UUID | None,
    target: Target, user, now: datetime,
) -> None:
    candidate.status = "claimed"
    candidate.affiliated_entity_id = affiliated_id
    candidate.decided_at = now
    candidate.decided_by_id = user.id
    candidate.accepted_into = "engagement" if destination_id is not None else "estate"
    candidate.engagement_id = destination_id
    candidate.target_id = target.id
    db.add(ScopeCandidateEvent(id=uuid.uuid4(), candidate_id=candidate.id, event="claimed", user_id=user.id))


def claim(
    db: Session, *, candidate_id: uuid.UUID, user, affiliated_entity_id: uuid.UUID | None = None
) -> ClaimResult:
    """A person claims a proposable candidate. Owner: commits once."""
    candidate = db.execute(
        select(ScopeCandidate).where(ScopeCandidate.id == candidate_id).with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if candidate is None:
        raise CandidateNotFound("candidate not found")
    if candidate.status != "open":
        db.rollback()
        raise CandidateConflict(f"candidate is already {candidate.status}")

    row = _strength_row(db, candidate.id)
    if row is None or not row.proposable:
        db.rollback()
        raise CandidateConflict(NOT_PROPOSABLE_MESSAGE)

    affiliated_id = affiliated_entity_id
    if affiliated_id is None:
        affiliated_id = db.execute(
            select(strength_sql.default_affiliate_expr(candidate.id))
        ).scalar_one()
    if affiliated_id is None:
        db.rollback()
        raise CandidateInvalid(f"affiliated company is {NOT_IN_TREE_MESSAGE}")

    # Serialise against a concurrent relationship change on any company this
    # answer rests on (`entity_relationship`'s writers lock the same rows):
    # walk once, lock everything the walk read PLUS the root in one ordered
    # statement (one lock order for every claim), reloading past the identity
    # map, then walk again under the lock.
    first = entity_relationship.resolve(db, affiliated_id)
    lock_ids = sorted(set(first.visited) | {candidate.root_entity_id})
    locked = {
        e.id: e for e in db.execute(
            select(OrgEntity).where(OrgEntity.id.in_(lock_ids)).order_by(OrgEntity.id)
            .with_for_update().execution_options(populate_existing=True)
        ).scalars()
    }
    root = locked.get(candidate.root_entity_id)
    if root is None:
        db.rollback()
        raise CandidateNotFound("organization not found")
    # The destination first: it is the more truthful refusal when the root's
    # relationship has been cleared (the tree check below would then fail on
    # every company, the root included).
    try:
        engagement = _destination(db, root)
    except CandidateError:
        db.rollback()
        raise
    destination_id = engagement.id if engagement is not None else None

    second = entity_relationship.resolve(db, affiliated_id)
    if second.visited != first.visited or [(s.entity_id, s.relationship) for s in second.stops] != [
        (s.entity_id, s.relationship) for s in first.stops
    ]:
        db.rollback()
        raise CandidateConflict("this company's relationships changed while claiming; try again")
    if root.id not in {s.entity_id for s in second.stops}:
        db.rollback()
        raise CandidateInvalid(f"affiliated company is {NOT_IN_TREE_MESSAGE}")

    now = _now()
    try:
        target, created = _attach_or_create_target(
            db, value=candidate.value, destination_id=destination_id, entity_id=affiliated_id, user=user, now=now,
            elsewhere_message="that domain is already a target outside this destination; change it on the target itself",
            other_entity_message="that target is already attributed to a different entity",
        )
    except CandidateConflict:
        db.rollback()
        raise

    try:
        if created:
            # INSERT before the candidate's UPDATE references it (no ORM
            # relationship orders the two). A flush, not a commit: nothing
            # is visible to any other session until the single commit below.
            db.flush()
        _write_claim(db, candidate, affiliated_id=affiliated_id, destination_id=destination_id,
                     target=target, user=user, now=now)
        db.commit()
    except IntegrityError as exc:
        # Most likely `uq_targets_value` (the same target added
        # concurrently). Either way nothing was written: the target insert
        # and the decision share this one commit.
        db.rollback()
        constraint = getattr(getattr(exc.orig, "diag", None), "constraint_name", None) or "integrity error"
        raise CandidateConflict(f"claim was rolled back ({constraint}); nothing was changed") from exc
    db.refresh(candidate)
    db.refresh(target)
    if created:
        # Tag rules -- the same step `ensure_pending` runs for a new target.
        target_service._apply_target_rules(db, target)
    return ClaimResult(candidate=candidate, target=target, created=created)


def _claim_seed(
    db: Session, *, candidate: ScopeCandidate, root: OrgEntity, engagement: Engagement | None, user,
    elsewhere_message: str,
) -> ClaimResult:
    """`organizations.add_organization`'s claim of the seed domain: the same
    target and decision logic as `claim` without the proposable gate (the
    seed's own `admin_seed` signal is Strong; that is checked, not assumed).
    The destination is the one the caller just created. Flushes only; the
    caller owns the commit and the rollback."""
    row = _strength_row(db, candidate.id)
    if row is None or not row.proposable or "admin_seed" not in (row.strong_types or []):
        raise RuntimeError("the seed candidate has no admin_seed signal")
    destination_id = engagement.id if engagement is not None else None
    now = _now()
    target, created = _attach_or_create_target(
        db, value=candidate.value, destination_id=destination_id, entity_id=root.id, user=user, now=now,
        elsewhere_message=elsewhere_message, other_entity_message=elsewhere_message,
    )
    if created:
        db.flush()
    _write_claim(db, candidate, affiliated_id=root.id, destination_id=destination_id,
                 target=target, user=user, now=now)
    db.flush()
    return ClaimResult(candidate=candidate, target=target, created=created)


# ── reject ──────────────────────────────────────────────────────────────────


def _reject_locked(db: Session, candidate: ScopeCandidate, *, user, reason: str) -> None:
    """Reject an `open` candidate already locked by the caller. Flushes."""
    strong = sorted(
        db.execute(
            select(ScopeSignal.signal_type).where(
                ScopeSignal.candidate_id == candidate.id,
                ScopeSignal.signal_type.in_(strength_sql.STRONG_TYPES),
            ).distinct()
        ).scalars()
    )
    candidate.status = "rejected"
    candidate.decided_at = _now()
    candidate.decided_by_id = user.id
    candidate.rejection_reason = reason
    candidate.rejected_strong_types = strong
    db.add(ScopeCandidateEvent(
        id=uuid.uuid4(), candidate_id=candidate.id, event="rejected", user_id=user.id, reason=reason,
    ))
    db.flush()


def reject(db: Session, *, candidate_id: uuid.UUID, user, reason: str) -> ScopeCandidate:
    """A person rejects an open candidate, with a reason. Owner: commits."""
    reason = (reason or "").strip()
    if not reason:
        raise CandidateInvalid("a reason is required")
    if len(reason) > MAX_REJECTION_REASON:
        raise CandidateInvalid(f"reason is longer than {MAX_REJECTION_REASON} characters")
    candidate = db.execute(
        select(ScopeCandidate).where(ScopeCandidate.id == candidate_id).with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if candidate is None:
        raise CandidateNotFound("candidate not found")
    if candidate.status != "open":
        db.rollback()
        raise CandidateConflict(f"candidate is already {candidate.status}")
    _reject_locked(db, candidate, user=user, reason=reason)
    db.commit()
    db.refresh(candidate)
    return candidate
