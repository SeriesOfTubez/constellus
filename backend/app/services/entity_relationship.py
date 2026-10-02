"""A mapped company's relationship to us, and where its domains inherit to
(planning#240, Jason 2026-10-01 — the decisions comment on #240 is live).

## The three states (`org_entities.relationship`, migration 0068)

- unset (NULL) — map and browse only. Accepting a candidate domain is
  blocked; AI reads run under the strict data policy.
- `ours` — an AUTHORISATION (admin-only, reference required, audited by the
  API): accepted domains join our own estate (a target with no engagement).
- `ma_target` — the subject of at least one engagement. Accepted domains
  join that engagement and inherit its posture.

Cross-table invariants this module keeps on every write it owns, and that
`app.api.engagements` keeps through `on_subject_changed`:

- `ma_target` ⇔ the subject of ≥ 1 engagement (any posture, `abandoned`
  included — an abandoned deal stays readable, item 6's spirit).
- `ours` ⇒ the subject of no engagement.

An `integrated` engagement is never flipped to `ours` (item 6): nothing in
this module or in the engagement transitions changes a relationship on a
posture change.

## Inheritance — `resolve` (item 3), one rule for accept AND the AI policy

A candidate domain is found under some entity. `resolve` walks the
CONFIRMED family tree from that entity UP, parent by parent, and stops each
path at the nearest entity that has a relationship. Parent edges, in this
codebase's direction convention:

- `child subsidiary_of parent` (EX-21), and
- `parent acquired child` (the acquisition reader / a person).

Never child → parent: walking DOWN would let an engagement whose subject is
one division receive its parent's domains (the carve-out leak #216's
original either-direction C3 hop had). `proposed` and `rejected` edges are
never walked: "AI raises attention, never scope".

Outcomes (`Resolution.status`):

- `ours` / `engagement` — exactly one destination; accept may proceed
  without asking.
- `ambiguous` — more than one live destination (two engagements, or ours on
  one path and an engagement on another). Accept must be told which; there
  is no default.
- `abandoned` — some path stopped at an M&A target whose engagements are
  all abandoned, and no live destination exists. Blocked, not skipped: the
  walk does not continue past it.
- `unset` — no path reached a relationship. Blocked.

Live = any posture except `abandoned`.

`ai_scope` reads the same walk: ours → no engagement, deployment policy;
engagement(s) only → the restricting-first one, as `pick_engagement` always
did (never loosens); anything else (unset, conflicting, nothing) → strict.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.models.engagement import Engagement, EngagementPosture
from app.models.entity_relation import EntityRelation
from app.models.org_entity import RELATIONSHIP_MA_TARGET, RELATIONSHIP_OURS, OrgEntity
from app.services import posture

# A cap on the walk, not a design limit: a real corporate tree is a handful
# of levels deep. Reaching it means a cycle the visited set did not catch
# or bad data — either way the answer is "unresolved", the safe direction.
MAX_DEPTH = 12


class RelationshipError(Exception):
    pass


class RelationshipNotFound(RelationshipError):
    pass


class RelationshipConflict(RelationshipError):
    pass


class RelationshipInvalid(RelationshipError):
    pass


class RelationshipForbidden(RelationshipError):
    """The caller's role may not clear an `ours` authorisation. Checked
    under the row lock, so a concurrent change cannot slip past it."""


@dataclass
class Stop:
    """One path's answer: the nearest entity on it that has a relationship."""
    entity_id: uuid.UUID
    relationship: str
    depth: int


@dataclass
class Resolution:
    status: str  # ours | engagement | ambiguous | abandoned | unset
    estate: bool = False
    engagements: list[Engagement] = field(default_factory=list)  # live only
    stops: list[Stop] = field(default_factory=list)
    # Every engagement at a stop, abandoned included (for `ai_scope`).
    all_engagements: list[Engagement] = field(default_factory=list)
    # Every entity the walk read (for callers that lock what they relied on).
    visited: list[uuid.UUID] = field(default_factory=list)

    @property
    def destination_count(self) -> int:
        return (1 if self.estate else 0) + len(self.engagements)


def parents(db: Session, entity_id: uuid.UUID) -> list[uuid.UUID]:
    """Confirmed parents of `entity_id` (see the module docstring for the
    two edge directions)."""
    rows = db.execute(
        select(EntityRelation.subject_id, EntityRelation.object_id, EntityRelation.relation).where(
            EntityRelation.status == "confirmed",
            or_(
                and_(EntityRelation.relation == "subsidiary_of", EntityRelation.subject_id == entity_id),
                and_(EntityRelation.relation == "acquired", EntityRelation.object_id == entity_id),
            ),
        )
    ).all()
    found: list[uuid.UUID] = []
    for subject_id, object_id, relation in rows:
        parent = object_id if relation == "subsidiary_of" else subject_id
        if parent != entity_id and parent not in found:
            found.append(parent)
    return found


def _engagements_of(db: Session, entity_id: uuid.UUID) -> list[Engagement]:
    return (
        db.query(Engagement)
        .filter(Engagement.subject_entity_id == entity_id)
        .order_by(Engagement.created_at.asc())
        .all()
    )


def resolve(db: Session, entity_id: uuid.UUID) -> Resolution:
    stops: list[Stop] = []
    visited: set[uuid.UUID] = set()
    frontier: list[uuid.UUID] = [entity_id]
    depth = 0
    while frontier and depth <= MAX_DEPTH:
        next_frontier: list[uuid.UUID] = []
        for node in frontier:
            if node in visited:
                continue
            visited.add(node)
            entity = db.get(OrgEntity, node)
            if entity is None:
                continue
            if entity.relationship is not None:
                stops.append(Stop(entity_id=node, relationship=entity.relationship, depth=depth))
                continue  # nearest on this path: never walk past it
            next_frontier.extend(p for p in parents(db, node) if p not in visited)
        frontier = next_frontier
        depth += 1

    estate = any(s.relationship == RELATIONSHIP_OURS for s in stops)
    all_engagements: list[Engagement] = []
    live: list[Engagement] = []
    abandoned_only_stop = False
    for stop in stops:
        if stop.relationship != RELATIONSHIP_MA_TARGET:
            continue
        rows = _engagements_of(db, stop.entity_id)
        all_engagements.extend(rows)
        stop_live = [e for e in rows if e.posture != EngagementPosture.ABANDONED.value]
        if stop_live:
            live.extend(stop_live)
        else:
            abandoned_only_stop = True

    res = Resolution(
        status="unset", estate=estate, engagements=live, stops=stops,
        all_engagements=all_engagements, visited=sorted(visited),
    )
    count = res.destination_count
    if count > 1:
        res.status = "ambiguous"
    elif count == 1:
        res.status = "ours" if estate else "engagement"
    elif abandoned_only_stop:
        res.status = "abandoned"
    return res


def ai_scope(db: Session, entity_id: uuid.UUID) -> tuple[Engagement | None, bool]:
    """(engagement to scope the call to, force_strict). Item 5."""
    res = resolve(db, entity_id)
    if res.estate and not res.all_engagements:
        return None, False
    if res.all_engagements and not res.estate:
        chosen = max(res.all_engagements, key=lambda e: (posture.posture_restricts(e.posture), e.created_at))
        return chosen, False
    return None, True


# ── writes ───────────────────────────────────────────────────────────────────

def _lock_entity(db: Session, entity_id: uuid.UUID) -> OrgEntity:
    entity = db.execute(
        select(OrgEntity).where(OrgEntity.id == entity_id).with_for_update()
    ).scalar_one_or_none()
    if entity is None:
        raise RelationshipNotFound("entity not found")
    return entity


def _clear_ours(entity: OrgEntity) -> None:
    entity.ours_authorised_by_id = None
    entity.ours_authorised_at = None
    entity.ours_reference = None


def set_ours(db: Session, *, entity_id: uuid.UUID, reference: str, user) -> tuple[OrgEntity, str | None]:
    """Admin-only at the API. Returns (entity, previous relationship)."""
    reference = (reference or "").strip()
    if not reference:
        raise RelationshipInvalid("a reference is required to mark a company as ours")
    entity = _lock_entity(db, entity_id)
    if _engagements_of(db, entity.id):
        raise RelationshipConflict(
            "this company is the subject of an engagement, so it is an M&A target; "
            "an engagement subject cannot also be ours"
        )
    previous = entity.relationship
    entity.relationship = RELATIONSHIP_OURS
    entity.ours_authorised_by_id = user.id
    entity.ours_authorised_at = datetime.now(timezone.utc)
    entity.ours_reference = reference
    db.commit()
    db.refresh(entity)
    return entity, previous


def set_ma_target(
    db: Session,
    *,
    entity_id: uuid.UUID,
    user,
    engagement_id: uuid.UUID | None = None,
    new_engagement_name: str | None = None,
    may_clear_ours: bool,
) -> tuple[OrgEntity, str | None, Engagement, bool]:
    """Pick an existing engagement (no subject yet, or already this one; not
    abandoned) or create a new `pre_close` one with this entity as subject.
    Exactly one of the two. Returns (entity, previous relationship,
    engagement, engagement_created). Moving `ours` → M&A is admin-only at
    the API (it clears an authorisation)."""
    if (engagement_id is None) == (new_engagement_name is None):
        raise RelationshipInvalid("give exactly one of engagement_id or new_engagement_name")
    entity = _lock_entity(db, entity_id)
    previous = entity.relationship
    if previous == RELATIONSHIP_OURS and not may_clear_ours:
        raise RelationshipForbidden("only an admin can change a company marked ours")

    if engagement_id is not None:
        engagement = db.execute(
            select(Engagement).where(Engagement.id == engagement_id).with_for_update()
        ).scalar_one_or_none()
        if engagement is None:
            raise RelationshipInvalid("engagement not found")
        if engagement.posture == EngagementPosture.ABANDONED.value:
            raise RelationshipConflict("that engagement was abandoned; create a new one")
        if engagement.subject_entity_id not in (None, entity.id):
            raise RelationshipConflict(
                "that engagement already has a different subject; change it on the engagement itself"
            )
        engagement.subject_entity_id = entity.id
        created = False
    else:
        name = (new_engagement_name or "").strip()
        if not name:
            raise RelationshipInvalid("the new engagement needs a name")
        if db.query(Engagement).filter(Engagement.name == name).first() is not None:
            raise RelationshipConflict("an engagement with this name already exists")
        engagement = Engagement(
            id=uuid.uuid4(), name=name, posture=EngagementPosture.PRE_CLOSE.value,
            subject_entity_id=entity.id, created_by_id=user.id,
        )
        db.add(engagement)
        created = True

    entity.relationship = RELATIONSHIP_MA_TARGET
    _clear_ours(entity)
    db.commit()
    db.refresh(entity)
    db.refresh(engagement)
    return entity, previous, engagement, created


def clear(db: Session, *, entity_id: uuid.UUID, may_clear_ours: bool) -> tuple[OrgEntity, str | None]:
    """Back to unset. Refused while the entity is an engagement's subject:
    detach or delete the engagement first (that path resets it)."""
    entity = _lock_entity(db, entity_id)
    if entity.relationship == RELATIONSHIP_OURS and not may_clear_ours:
        raise RelationshipForbidden("only an admin can change a company marked ours")
    if _engagements_of(db, entity.id):
        raise RelationshipConflict(
            "this company is the subject of an engagement; detach or delete the engagement first"
        )
    previous = entity.relationship
    entity.relationship = None
    _clear_ours(entity)
    db.commit()
    db.refresh(entity)
    return entity, previous


def check_may_become_subject(db: Session, entity_id: uuid.UUID) -> OrgEntity:
    """For `app.api.engagements` before it makes `entity_id` a subject:
    refuses an `ours` entity (a company cannot be ours and a target)."""
    entity = _lock_entity(db, entity_id)
    if entity.relationship == RELATIONSHIP_OURS:
        raise RelationshipConflict("that company is marked ours; an engagement subject must be an M&A target")
    return entity


def on_subject_changed(db: Session, *, added: uuid.UUID | None, removed: uuid.UUID | None) -> None:
    """Keep `ma_target` ⇔ subject-of-an-engagement after an engagement's
    subject changes or the engagement is deleted. Flushes; the caller owns
    the commit (CONTRIBUTING.md, transaction ownership). Call AFTER the
    engagement row change is flushed so the count below sees it."""
    db.flush()
    if added is not None:
        entity = db.get(OrgEntity, added)
        if entity is not None and entity.relationship is None:
            entity.relationship = RELATIONSHIP_MA_TARGET
    if removed is not None and removed != added:
        entity = db.get(OrgEntity, removed)
        if (
            entity is not None
            and entity.relationship == RELATIONSHIP_MA_TARGET
            and not _engagements_of(db, removed)
        ):
            entity.relationship = None
    db.flush()
