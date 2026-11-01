"""Which organization discovery candidates a notification may mention
(planning#319, Jason 2026-10-31, #319 6551740956).

Rule recipients are free-typed email addresses with no link to a user, so
nothing under a pre-close or abandoned engagement may reach them: not an
organization's name, not a candidate, not a count. This module is the ONE
predicate for that. The digest applies it when it builds a body, again when it
sends one (a stale digest is sent later from its stored body), and again when
a stored body is read back through the API, so a deal that goes back to a
restricting posture closes up in old digests by itself.

A candidate is eligible when its root organization is
- `ours`, or
- `ma_target` with at least one engagement that is not abandoned,

AND no engagement in `RESTRICTING_POSTURES` names, as its subject, the root or
the candidate's affiliate (stored, else the default from its best signal), and
the candidate's own `engagement_id` is not one in a restricting posture. The
strictest reading wins: one restricting engagement anywhere on those three
excludes the candidate, whatever else is live.

KNOWN LIMIT: the check looks at the root and the candidate's affiliate, not at
every entity between them. `read_scope.entity_clause` does not restrict
entities yet (planning#261's entity slice); when it does, this predicate should
take the same tree rule.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import and_, exists, func, inspect, or_, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from app.models.engagement import Engagement, EngagementPosture
from app.models.org_entity import RELATIONSHIP_MA_TARGET, RELATIONSHIP_OURS, OrgEntity
from app.models.scope_candidate import ScopeCandidate
from app.services.org_discovery import strength as strength_sql
from app.services.posture import RESTRICTING_POSTURES


def _restricting_subject(entity_id_col: Any) -> ColumnElement[bool]:
    return exists().where(
        Engagement.subject_entity_id == entity_id_col,
        Engagement.posture.in_(RESTRICTING_POSTURES),
    )


def root_eligible_clause(root: Any) -> ColumnElement[bool]:
    """A boolean over an `OrgEntity` alias: may a notification name this root?"""
    live_deal = exists().where(
        Engagement.subject_entity_id == root.id,
        Engagement.posture != EngagementPosture.ABANDONED.value,
    )
    return and_(
        or_(
            root.relationship == RELATIONSHIP_OURS,
            and_(root.relationship == RELATIONSHIP_MA_TARGET, live_deal),
        ),
        ~_restricting_subject(root.id),
    )


def candidate_eligible_clause(candidate: Any, root: Any) -> ColumnElement[bool]:
    """A boolean over a `ScopeCandidate` alias joined to its root `OrgEntity`
    alias (`root.id == candidate.root_entity_id`)."""
    # Correlate the default-affiliate subquery to the candidate explicitly: it is
    # used inside an EXISTS (below), where auto-correlation does not reach.
    default_affiliate = strength_sql.default_affiliate_expr(candidate.id).correlate(inspect(candidate).selectable)
    affiliate = func.coalesce(candidate.affiliated_entity_id, default_affiliate)
    restricting_own = exists().where(
        Engagement.id == candidate.engagement_id,
        Engagement.posture.in_(RESTRICTING_POSTURES),
    )
    return and_(
        root_eligible_clause(root),
        or_(affiliate.is_(None), ~_restricting_subject(affiliate)),
        ~restricting_own,
    )


def eligible_candidate_ids(db: Session, candidate_ids: list[uuid.UUID]) -> set[uuid.UUID]:
    """The subset of `candidate_ids` a notification may mention now."""
    if not candidate_ids:
        return set()
    return set(
        db.execute(
            select(ScopeCandidate.id)
            .join(OrgEntity, OrgEntity.id == ScopeCandidate.root_entity_id)
            .where(ScopeCandidate.id.in_(candidate_ids), candidate_eligible_clause(ScopeCandidate, OrgEntity))
        ).scalars()
    )
