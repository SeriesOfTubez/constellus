"""Unpersisted users for permission checks.

`has_permission` reads role ASSIGNMENTS only (never `users.role`), so a bare
`User(role=X)` that is never flushed holds no permissions. `user_with` builds
one with the assignments a persisted user would get: a global one mirroring
`role` plus one per engagement. Persisted users get their global assignment
from the `before_flush` hook (models/role_assignment.py) and do not need this.
"""

from __future__ import annotations

import uuid

from app.models.role_assignment import RoleAssignment
from app.models.user import User


def user_with(role, *, engagements: dict[uuid.UUID, str] | None = None, global_role: bool = True, **fields) -> User:
    value = getattr(role, "value", role)
    user = User(role=role, **fields)
    if global_role:
        user.assignments.append(RoleAssignment(role=value, engagement_id=None))
    for eid, r in (engagements or {}).items():
        user.assignments.append(RoleAssignment(role=getattr(r, "value", r), engagement_id=eid))
    return user
