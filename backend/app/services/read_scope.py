"""Row-level read scope: the one place that decides which rows a user may read.

## The rule (planning#261, Jason 2026-10-22; comments 6350747062, 6356901236, 6356975937)

- Data under an engagement whose posture is in `posture.RESTRICTING_POSTURES`
  (pre_close, abandoned) is readable only through an assignment on that
  engagement, or a GLOBAL assignment whose role holds
  `engagements.read_restricted` (admin). Any other global role does not open
  it. The constant is reused, not copied: one predicate drives scanning and
  reading, so a deal that reverts to pre_close closes up again by itself.
- day_0 / integrated data and the owned estate (under no engagement) are
  readable by anyone who passed the route's read permission.
- An asset under several targets or engagements is readable only if EVERY
  restricting engagement it falls under is readable (the strictest wins).
- "Falls under" is `target_scope.asset_falls_under` (links + domain suffix +
  CIDR containment), the same SQL the LLM-scope resolver uses.
- A finding is readable iff its asset is.

## What is filled and what is not

Filled: `asset_clause`, `finding_clause`, `target_clause`,
`connector_instance_clause`, `engagement_visible`. Still granting everything until the entity slice after
planning#277: `entity_clause`, `relation_clause`, `domain_clause`. The read
routes not yet on this module are listed in `tests/test_read_scope_sweep.py`.

Callers render a row a user may not read as absent: list routes drop it,
detail routes answer 404 (not 403), so the row is not confirmed to exist.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import exists, or_, select, true
from sqlalchemy.orm import Session, aliased
from sqlalchemy.sql.elements import ColumnElement

from app.core.permissions import Permission, grants_of
from app.models.engagement import Engagement
from app.models.target import Target
from app.models.user import User
from app.services.posture import RESTRICTING_POSTURES
from app.services.target_scope import asset_falls_under


def _closed_engagements(user: User, permission: Permission):
    """None when `user` reads every engagement; otherwise a subquery of the
    restricting engagements closed to them for `permission`."""
    grants = grants_of(user)
    if grants.reads_all_restricted:
        return None
    q = select(Engagement.id).where(Engagement.posture.in_(RESTRICTING_POSTURES))
    opened = grants.readable_engagements(permission)
    if opened:
        q = q.where(Engagement.id.notin_(opened))
    return q


def closed_subject_entities(user: User, permission: Permission):
    """None when `user` reads every engagement; otherwise a select of the
    `subject_entity_id`s (non-null) of the restricting engagements closed to
    them for `permission`. The one definition of "an organization that is deal
    data the user may not see" (planning#284): connector_instance_clause, the
    bindable-organization list and the binding suggestion all use it."""
    closed = _closed_engagements(user, permission)
    if closed is None:
        return None
    return select(Engagement.subject_entity_id).where(
        Engagement.id.in_(closed), Engagement.subject_entity_id.is_not(None)
    )


def _asset_rule(user: User, asset: Any, permission: Permission) -> ColumnElement[bool]:
    closed = _closed_engagements(user, permission)
    if closed is None:
        return true()
    t = aliased(Target)
    # correlate_except(t): the caller may nest this inside its own EXISTS (the
    # query language's `exists finding` block does), where auto-correlation
    # looks only one level up and would pull `asset` into this FROM instead,
    # i.e. "ANY asset under a closed engagement" hides everything.
    return ~exists().where(t.engagement_id.in_(closed), asset_falls_under(asset, t)).correlate_except(t)


def asset_clause(user: User, asset: Any) -> ColumnElement[bool]:
    """WHERE clause limiting `asset` (an AssetCanonical entity or alias) to what `user` may read."""
    return _asset_rule(user, asset, Permission.ASSETS_READ)


def finding_clause(user: User, finding: Any, asset: Any) -> ColumnElement[bool]:
    """WHERE clause limiting `finding` (a FindingCanonical entity or alias), whose asset is
    `asset`, to what `user` may read. `asset` MUST be the finding's own asset
    (joined on `asset_canonical_id`): the rule is decided on it alone."""
    return _asset_rule(user, asset, Permission.FINDINGS_READ)


def target_clause(user: User, target: Any) -> ColumnElement[bool]:
    """WHERE clause limiting `target` (a Target entity or alias): a target
    under a restricting engagement closed to `user` is itself deal data."""
    closed = _closed_engagements(user, Permission.TARGETS_READ)
    if closed is None:
        return true()
    return or_(target.engagement_id.is_(None), target.engagement_id.notin_(closed))


def connector_instance_clause(user: User, instance: Any) -> ColumnElement[bool]:
    """WHERE clause limiting `instance` (a ConnectorInstance entity or alias): an
    instance bound to the organization that is the subject of a restricting
    engagement closed to `user` is itself deal data (planning#284). Unbound
    and ours-bound instances follow the route's own permission."""
    closed_subjects = closed_subject_entities(user, Permission.CONNECTORS_READ)
    if closed_subjects is None:
        return true()
    return or_(instance.bound_entity_id.is_(None), instance.bound_entity_id.notin_(closed_subjects))


def entity_clause(user: User, entity: Any) -> ColumnElement[bool]:
    """WHERE clause limiting `entity` (an OrgEntity entity or alias) to what `user` may read.
    The query language applies it to the `entity` root and to the entity joined onto a
    `relation` or `domain` row. **Today this grants everything**; planning#261 fills it."""
    return true()


def relation_clause(user: User, relation: Any) -> ColumnElement[bool]:
    """WHERE clause limiting `relation` (an EntityRelation entity) to what `user` may read.
    **Today this grants everything**; planning#261 fills it."""
    return true()


def domain_clause(user: User, domain: Any) -> ColumnElement[bool]:
    """WHERE clause limiting `domain` (a CandidateDomain entity) to what `user` may read.
    **Today this grants everything**; planning#261 fills it."""
    return true()


def engagement_visible(db: Session, user: User, engagement_id: Any) -> bool:
    """May `user` see `engagement_id`, and so its reports? Report list, view
    and download call it and answer 404 (not 403) when it is False. A report's
    full engagement SPAN is the entity slice's (planning#261 6356901236); this
    is the report's own engagement only."""
    grants = grants_of(user)
    if grants.reads_all_restricted:
        return True
    posture = db.execute(select(Engagement.posture).where(Engagement.id == engagement_id)).scalar_one_or_none()
    if posture is None or posture not in RESTRICTING_POSTURES:
        return True
    eid = engagement_id if isinstance(engagement_id, uuid.UUID) else uuid.UUID(str(engagement_id))
    return eid in grants.readable_engagements(Permission.REPORTS_READ)
