"""Read surface for the audit trail (planning#194).

Writes happen at one choke point in `services/audit.py`; this module only
reads. There is deliberately **no delete route and no write route**: the
table is append-only, which is the answer to planning#162's observation
that `DELETE /api/logs/` lets an admin erase the trace of their own
actions. That endpoint truncates `system_logs`; this is a different table
with no API path that removes a row, and clearing the system log is itself
an audited action visible here.
"""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import require_role
from app.core.database import get_db
from app.models.audit import AuditLog
from app.models.user import User, UserRole

router = APIRouter()


def _serialize(row: AuditLog, actor: User | None) -> dict:
    return {
        "id": str(row.id),
        "occurred_at": row.occurred_at.isoformat() if row.occurred_at else None,
        "user_id": str(row.user_id) if row.user_id else None,
        "user_email": actor.email if actor else None,
        "user_full_name": actor.full_name if actor else None,
        "action": row.action,
        "resource_type": row.resource_type,
        "resource_id": row.resource_id,
        "detail": row.detail or {},
        "ip_address": row.ip_address,
    }


@router.get("/")
def list_audit_log(
    user_id: uuid.UUID | None = None,
    action: str | None = None,
    resource_type: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(default=200, le=1000),
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN)),
):
    """Who did what, filterable by actor, action, resource and period.

    ADMIN only — narrower than the (ADMIN, INTEGRATION_ADMIN) pair used for
    ordinary administration, because this is the record of what those roles
    did and reading it is a supervisory act, not an operational one.
    """
    q = db.query(AuditLog)
    if user_id:
        q = q.filter(AuditLog.user_id == user_id)
    if action:
        q = q.filter(AuditLog.action == action)
    if resource_type:
        q = q.filter(AuditLog.resource_type == resource_type)
    if since:
        q = q.filter(AuditLog.occurred_at >= since)
    if until:
        q = q.filter(AuditLog.occurred_at <= until)
    rows = q.order_by(AuditLog.occurred_at.desc()).limit(limit).all()

    actor_ids = {r.user_id for r in rows if r.user_id}
    actors: dict[uuid.UUID, User] = {}
    if actor_ids:
        actors = {
            u.id: u for u in db.query(User).filter(User.id.in_(actor_ids)).all()
        }
    return [_serialize(r, actors.get(r.user_id)) for r in rows]


@router.get("/facets")
def audit_facets(
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN)),
):
    """The distinct values present, so the UI can build its filters from what
    is actually in the table rather than from a hardcoded list that drifts
    every time an endpoint is added."""
    actions = [r[0] for r in db.query(AuditLog.action).distinct().order_by(AuditLog.action).all()]
    resource_types = [
        r[0] for r in
        db.query(AuditLog.resource_type).distinct().order_by(AuditLog.resource_type).all()
        if r[0]
    ]
    actor_rows = (
        db.query(User.id, User.email, User.full_name)
        .join(AuditLog, AuditLog.user_id == User.id)
        .distinct()
        .all()
    )
    return {
        "actions": actions,
        "resource_types": resource_types,
        "actors": [
            {"id": str(i), "email": e, "full_name": n} for i, e, n in actor_rows
        ],
    }
