"""First-run seeding from a company name (planning#232).

A new install knows nothing. An ADMIN searches SEC EDGAR by company name,
picks the registrant that is theirs, and this module marks it `ours`, then
the EDGAR ingest (and, when the AI connector is configured, the acquisition
read) runs on it. Decisions:

- **Hints, never automatic.** The name search is a new ADMIN-only onboarding
  route; `registrant_link`'s gated route is untouched. Nothing matches by
  name on its own: a person picks the CIK.
- **"Ours" goes through `entity_relationship.set_ours`** with the fixed
  reference `ONBOARDING_REFERENCE`; set_ours records the user and time. An
  existing entity for the CIK is reused, and one already `ours` is NOT
  re-authorised (its original authorisation stands). An engagement subject
  is refused by set_ours (`RelationshipConflict`).
- **The AI read is queued only when configured**, with the same checks as the
  registrant-link flow; otherwise the reason is recorded on the ingest run.
- **CIK only.** No Wayback / private-company path.

Nothing here enters scope: no Target is created and no candidate domain is
accepted. Whatever the ingest proposes stays proposed until an ADMIN accepts
it through the existing candidate-domain route.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.entity_ingest_run import EntityIngestRun
from app.models.org_entity import OrgEntity
from app.services import edgar_ingest, entity_relationship, registrant_link, sec_edgar
from app.services.registrant_link import RegistrantFacts

ONBOARDING_REFERENCE = "first-run onboarding"
MAX_QUERY_LENGTH = 200


class OnboardingError(Exception):
    pass


class OnboardingInvalid(OnboardingError):
    pass


class OnboardingNotFound(OnboardingError):
    pass


class OnboardingConflict(OnboardingError):
    pass


def search(db: Session, *, query: str, contains: bool = False) -> list[RegistrantFacts]:
    """Registrants matching a company name, with the facts a person decides
    on. Every call sends requests to SEC. Hints only."""
    query = (query or "").strip()
    if not query or len(query) > MAX_QUERY_LENGTH:
        raise OnboardingInvalid(f"q must be 1 to {MAX_QUERY_LENGTH} characters")
    return registrant_link.search_registrants(db, query=query, contains=contains)


@dataclass
class SeedOutcome:
    entity: OrgEntity
    previous_relationship: str | None
    ours_set_now: bool  # False when it was already ours
    run: EntityIngestRun | None  # None when an ingest of this CIK was already queued/running


def seed(db: Session, *, cik: str, user) -> SeedOutcome:
    """Create-or-reuse the entity for `cik`, mark it ours, queue its ingest.

    Each step is its own unit of work and commits (`set_ours` commits its
    own session), so a failure part-way leaves the earlier steps in place:
    an entity without `ours`, or an `ours` entity without a queued run. Both
    are safe to retry (the entity is reused, `ours` is not re-applied) and
    neither puts anything in scope."""
    try:
        cik10 = edgar_ingest.normalise_cik(cik)
    except ValueError:
        raise OnboardingInvalid("cik must be 1 to 10 digits")
    edgar_ingest.require_user_agent()  # EdgarNotConfigured propagates

    entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik10)).scalar_one_or_none()
    if entity is None:
        try:
            facts = registrant_link.facts_for(db, cik10)
        except sec_edgar.SecNotFound:
            raise OnboardingNotFound("no SEC registrant with that CIK")
        if not facts.name:
            raise OnboardingInvalid("SEC returned no company name for that CIK")
        db.execute(
            pg_insert(OrgEntity.__table__)
            .values(id=uuid.uuid4(), legal_name=facts.name, cik=cik10)
            .on_conflict_do_nothing(constraint="uq_org_entities_cik")
        )
        db.commit()
        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik10)).scalar_one()

    if entity.relationship == entity_relationship.RELATIONSHIP_OURS:
        previous, ours_set_now = entity_relationship.RELATIONSHIP_OURS, False
    else:
        entity, previous = entity_relationship.set_ours(
            db, entity_id=entity.id, reference=ONBOARDING_REFERENCE, user=user
        )
        ours_set_now = True

    run = EntityIngestRun(cik=cik10, status="queued", requested_by_id=user.id)
    db.add(run)
    try:
        db.commit()
    except IntegrityError:
        # An ingest of this CIK is already in flight (uq_entity_ingest_runs_
        # active_kind_cik). Not an error: the company is ours either way.
        db.rollback()
        run = None
    else:
        db.refresh(run)
    db.refresh(entity)
    return SeedOutcome(entity=entity, previous_relationship=previous, ours_set_now=ours_set_now, run=run)


def followup_read(
    db: Session, *, entity_id: uuid.UUID, cik10: str, user_id: uuid.UUID | None
) -> tuple[EntityIngestRun | None, str | None]:
    """After the seed's ingest succeeded: queue the AI acquisition read, or
    say why not. Returns (run, None) or (None, reason)."""

    def still_valid(entity: OrgEntity | None) -> str | None:
        if entity is None or entity.cik != cik10:
            return "the company was removed or changed before the read could start"
        if entity.relationship != entity_relationship.RELATIONSHIP_OURS:
            return "the company is no longer marked as ours"
        return None

    return registrant_link.queue_acquisition_read(
        db, entity_id=entity_id, cik10=cik10, user_id=user_id, still_valid=still_valid
    )
