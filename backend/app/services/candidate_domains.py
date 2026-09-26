"""Candidate domains — evidence-only, human-accepted into an engagement
(planning#216, L6, MVP slice).

The step from "this company is part of the acquisition" to "this domain may
be monitored", and the only way a lineage result ever becomes scan scope.

## No name → domain path, by construction

Nothing in this module reads `org_entities.legal_name`, and no function
here takes a company name. A candidate comes from exactly two places:

  - `propose_from_filing` — a domain the filer's own 10-K names as its
    website (`edgar_html.find_website_mentions`, called from
    `edgar_ingest`), citing the stored 10-K.
  - `add_manual` — a person pastes an excerpt, cites its URL, and quotes
    the sentence naming the domain. The excerpt is stored as evidence with
    `origin='person_supplied'`; this module fetches nothing (a server-side
    fetch of a counterparty's page would be `target_host` traffic pre-close).

`test_candidate_domains.py::test_no_name_to_domain_path` pins the first
claim with an AST check, so a later edit that reads the name fails a test
rather than a review.

## Accept creates the target INSIDE the engagement, in one transaction

`accept` does NOT go through `target_service.ensure_pending`, which commits
a new target with no engagement — an unrestricted, owned-estate target —
before a caller could attach it to anything. For a candidate found under a
`pre_close` engagement, that window is precisely the "arrives as an
unrestricted target by accident" the issue forbids. Here the `Target` row
is inserted with `engagement_id`/`entity_id` already set, and the
candidate's decision is written in the SAME commit.

Which engagements may receive a candidate (Jason, 2026-09-26, C3): one
whose `subject_entity_id` IS the candidate's entity, or is ONE CONFIRMED
`acquired`/`subsidiary_of` hop from it (either direction), and which is not
`abandoned`. A proposed relation is not enough: "AI raises attention,
never scope" — only a confirmed edge (a person, or a granted SEC source)
can carry a candidate into scope.

An existing target with the same value (C4): same engagement → idempotent
(sets `entity_id` if empty); anything else → `CandidateConflict`, nothing
changed. Moving an owned-estate or another engagement's target is a
`PATCH /targets/{id}` decision with its own widening rules, not a side
effect of accepting a candidate.

## Errors

`CandidateNotFound` (404), `CandidateConflict` (409), `CandidateInvalid`
(422) — the API maps each to its status. Audit rows are the CALLER's job
(the API has the `Request`), same split as `entity_graph.decide`.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timezone

from sqlalchemy import and_, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.candidate_domain import CandidateDomain
from app.models.engagement import Engagement, EngagementPosture
from app.models.entity_relation import EntityRelation
from app.models.observer import Observer
from app.models.org_entity import OrgEntity
from app.models.target import Target, TargetType, VerificationMethod
from app.services import entity_graph, target_service

SOURCE_FILING = "edgar_10k_website"
SOURCE_PERSON = "person"
TARGET_SOURCE_TYPE = "candidate_domain"

# Relations that carry a candidate from a related entity into an
# engagement (C3). `dba`/`formerly_named` are the SAME entity under another
# name — those are modelled as separate `OrgEntity` rows too, but C3 as
# decided names only these two.
_HOP_RELATIONS = ("acquired", "subsidiary_of")

# Same shape as migration 0064's `ck_candidate_domains_domain_shape`.
_DOMAIN_RE = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,63}|xn--[a-z0-9-]{1,59})$")

# A cited URL is stored, never requested — validated by shape only. Not
# `urllib.parse`: `test_egress_gate_guard` treats any `urllib` import as a
# network transport, and this module must stay one that makes no requests.
_SOURCE_URL_RE = re.compile(r"^https?://[^\s/?#@]+(?:[/?#][^\s]*)?$", re.IGNORECASE)
_MAX_SOURCE_URL = 2048
_MAX_EXCERPT = 50_000
_MAX_QUOTE = 2_000


class CandidateError(Exception):
    pass


class CandidateNotFound(CandidateError):
    pass


class CandidateConflict(CandidateError):
    pass


class CandidateInvalid(CandidateError):
    pass


def normalise_domain(value: str) -> str:
    """Canonical form stored in `candidate_domains.domain` and, on accept,
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


def propose_from_filing(
    db: Session,
    *,
    entity_id: uuid.UUID,
    domain: str,
    observer: Observer,
    evidence_id: uuid.UUID,
    quote: str,
    filing_date: date,
) -> bool:
    """One 10-K named `domain` as the filer's website. Inserts a proposed
    candidate on first sight (citing THIS 10-K) and returns True; on any
    later sight only widens `first_cited_on`/`last_cited_on` and returns
    False. Never touches `status`, so re-ingest can never undo a person's
    rejection (the row's existence, in any status, suppresses a re-insert).
    A person-sourced row for the same domain keeps its own evidence and
    dates. A domain that fails `normalise_domain` is skipped (False)."""
    try:
        domain = normalise_domain(domain)
    except CandidateInvalid:
        return False
    if domain not in quote.lower() or len(quote) > _MAX_QUOTE:
        return False

    table = CandidateDomain.__table__
    stmt = pg_insert(table).values(
        id=uuid.uuid4(),
        entity_id=entity_id,
        domain=domain,
        source=SOURCE_FILING,
        observer_id=observer.id,
        evidence_id=evidence_id,
        quote=quote,
        first_cited_on=filing_date,
        last_cited_on=filing_date,
    )
    existed = db.execute(
        select(CandidateDomain.id).where(CandidateDomain.entity_id == entity_id, CandidateDomain.domain == domain)
    ).scalar_one_or_none()
    stmt = stmt.on_conflict_do_update(
        constraint="uq_candidate_domains_entity_domain",
        set_={
            "first_cited_on": func.least(table.c.first_cited_on, stmt.excluded.first_cited_on),
            "last_cited_on": func.greatest(table.c.last_cited_on, stmt.excluded.last_cited_on),
        },
        where=table.c.source == SOURCE_FILING,
    )
    db.execute(stmt)
    db.commit()
    return existed is None


def add_manual(
    db: Session,
    *,
    entity_id: uuid.UUID,
    domain: str,
    source_url: str,
    excerpt: str,
    quote: str,
    user,
) -> CandidateDomain:
    """A person adds a candidate with evidence (C2). `excerpt` is stored as
    `person_supplied` evidence attributed to `source_url`; `quote` must be a
    substring of `excerpt` and must contain the domain as written (ASCII or
    punycode — an IDN quoted in Unicode is refused, since the DB CHECK
    compares against the punycode form)."""
    if db.get(OrgEntity, entity_id) is None:
        raise CandidateNotFound("entity not found")
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

    existing = db.execute(
        select(CandidateDomain).where(CandidateDomain.entity_id == entity_id, CandidateDomain.domain == domain)
    ).scalar_one_or_none()
    if existing is not None:
        raise CandidateConflict(f"this entity already has a candidate for that domain (status {existing.status})")

    evidence = entity_graph.store_evidence(
        db,
        content=excerpt.encode("utf-8"),
        content_type="text/plain; charset=utf-8",
        source_url=source_url,
        fetched_at=datetime.now(timezone.utc),
        origin="person_supplied",
    )
    candidate = CandidateDomain(
        id=uuid.uuid4(),
        entity_id=entity_id,
        domain=domain,
        source=SOURCE_PERSON,
        observer_id=None,
        evidence_id=evidence.id,
        quote=quote,
        created_by_id=user.id,
    )
    db.add(candidate)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise CandidateConflict("this entity already has a candidate for that domain") from exc
    db.refresh(candidate)
    return candidate


def engagement_may_receive(db: Session, *, entity_id: uuid.UUID, engagement: Engagement) -> bool:
    """C3: the engagement's subject is `entity_id`, or is one CONFIRMED
    `acquired`/`subsidiary_of` hop from it in either direction."""
    subject = engagement.subject_entity_id
    if subject is None:
        return False
    if subject == entity_id:
        return True
    hop = db.execute(
        select(EntityRelation.id).where(
            EntityRelation.status == "confirmed",
            EntityRelation.relation.in_(_HOP_RELATIONS),
            or_(
                and_(EntityRelation.subject_id == subject, EntityRelation.object_id == entity_id),
                and_(EntityRelation.subject_id == entity_id, EntityRelation.object_id == subject),
            ),
        ).limit(1)
    ).scalar_one_or_none()
    return hop is not None


@dataclass
class AcceptResult:
    candidate: CandidateDomain
    target: Target
    created: bool


def accept(db: Session, *, candidate_id: uuid.UUID, engagement_id: uuid.UUID, user) -> AcceptResult:
    candidate = db.execute(
        select(CandidateDomain).where(CandidateDomain.id == candidate_id).with_for_update()
    ).scalar_one_or_none()
    if candidate is None:
        raise CandidateNotFound("candidate not found")
    if candidate.status != "proposed":
        raise CandidateConflict(f"candidate is already {candidate.status}")

    engagement = db.get(Engagement, engagement_id)
    if engagement is None:
        raise CandidateInvalid("engagement not found")
    if engagement.posture == EngagementPosture.ABANDONED.value:
        raise CandidateConflict("cannot accept into an abandoned engagement — it is terminal")
    if not engagement_may_receive(db, entity_id=candidate.entity_id, engagement=engagement):
        raise CandidateConflict(
            "that engagement's subject is neither this entity nor one confirmed "
            "acquired/subsidiary_of relation away from it"
        )

    now = datetime.now(timezone.utc)
    existing = db.execute(select(Target).where(Target.value == candidate.domain)).scalar_one_or_none()
    if existing is not None:
        if existing.engagement_id != engagement.id:
            raise CandidateConflict(
                "that domain is already a target outside this engagement; change it on the target itself"
            )
        if existing.entity_id is not None and existing.entity_id != candidate.entity_id:
            raise CandidateConflict("that target is already attributed to a different entity")
        existing.entity_id = candidate.entity_id
        target, created = existing, False
    else:
        target = Target(
            id=uuid.uuid4(),
            type=TargetType.DOMAIN.value,
            value=candidate.domain,
            verified=True,
            verification_method=VerificationMethod.MANUAL.value,
            verified_by_id=user.id,
            verified_at=now,
            source_type=TARGET_SOURCE_TYPE,
            engagement_id=engagement.id,
            entity_id=candidate.entity_id,
        )
        db.add(target)
        created = True

    try:
        if created:
            # INSERT before the candidate's UPDATE references it (no ORM
            # relationship orders the two). A flush, not a commit: nothing
            # is visible to any other session until the single commit below.
            db.flush()
        candidate.status = "accepted"
        candidate.decided_at = now
        candidate.decided_by_id = user.id
        candidate.engagement_id = engagement.id
        candidate.target_id = target.id
        db.commit()
    except IntegrityError as exc:
        # Most likely `uq_targets_value` (the same target added
        # concurrently). Either way nothing was written: the target insert
        # and the decision share this one commit.
        db.rollback()
        constraint = getattr(getattr(exc.orig, "diag", None), "constraint_name", None) or "integrity error"
        raise CandidateConflict(f"accept was rolled back ({constraint}); nothing was changed") from exc
    db.refresh(candidate)
    db.refresh(target)
    if created:
        # Tag rules — the same step `ensure_pending` runs for a new target.
        target_service._apply_target_rules(db, target)
    return AcceptResult(candidate=candidate, target=target, created=created)


def reject(db: Session, *, candidate_id: uuid.UUID, user) -> CandidateDomain:
    candidate = db.execute(
        select(CandidateDomain).where(CandidateDomain.id == candidate_id).with_for_update()
    ).scalar_one_or_none()
    if candidate is None:
        raise CandidateNotFound("candidate not found")
    if candidate.status != "proposed":
        raise CandidateConflict(f"candidate is already {candidate.status}")
    candidate.status = "rejected"
    candidate.decided_at = datetime.now(timezone.utc)
    candidate.decided_by_id = user.id
    db.commit()
    db.refresh(candidate)
    return candidate
