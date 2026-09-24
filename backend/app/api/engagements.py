"""The engagement object's API surface (planning#211).

Mounted at `/api/engagements` (`app/main.py`). Reads are open to any
authenticated user (an engagement's posture governs what this system may
do to a counterparty's infrastructure — every operator who can see a
target should be able to see why it is or isn't being probed). Writes are
tiered: creating a `pre_close` engagement is the SAFE direction (it can
only ever narrow, never widen, what gets probed) and admits the same
(ADMIN, INTEGRATION_ADMIN) pair `patch_target` already does; every state
TRANSITION is ADMIN-only (planning#211 decision 5), because a transition
can widen traffic and `day_0`/`integrated` carry a recorded authorisation
that only an admin should be attesting to.
"""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.models.engagement import Engagement, EngagementPosture
from app.models.target import Target
from app.models.user import User, UserRole
from app.services import audit

router = APIRouter()

_POSTURES = tuple(p.value for p in EngagementPosture)

# The transition table (planning#211 §7), ONE module-level dict so it can
# be tested exhaustively (all 16 (from, to) cells) rather than trusted to
# match a prose table by inspection. Values:
#   "noop"      — from == to; 200 unchanged, no audit write.
#   "needs_ref" — widens FROM a restricting posture; requires a non-blank
#                 `authorisation_reference`, sets authorised_by/at/reference.
#   "ok_clear"  — moves TO a restricting posture (or otherwise demotes);
#                 clears authorised_by/at/reference — the CHECK constraint
#                 (migration 0059) requires them null outside day_0/integrated.
#   "ok_keep"   — widens further while already widened (day_0 -> integrated);
#                 the existing authorisation record still applies, untouched.
#   "deny"      — 409; not a legal transition.
_TRANSITIONS: dict[tuple[str, str], str] = {
    ("pre_close", "pre_close"): "noop",
    ("pre_close", "day_0"): "needs_ref",
    ("pre_close", "integrated"): "deny",
    ("pre_close", "abandoned"): "ok_clear",

    ("day_0", "pre_close"): "ok_clear",
    ("day_0", "day_0"): "noop",
    ("day_0", "integrated"): "ok_keep",
    ("day_0", "abandoned"): "ok_clear",

    ("integrated", "pre_close"): "ok_clear",
    ("integrated", "day_0"): "deny",
    ("integrated", "integrated"): "noop",
    ("integrated", "abandoned"): "ok_clear",

    ("abandoned", "pre_close"): "deny",
    ("abandoned", "day_0"): "deny",
    ("abandoned", "integrated"): "deny",
    ("abandoned", "abandoned"): "noop",
}
# Exhaustiveness is enforced at import time, not just by a test — a
# 4-posture table with a missing cell is a policy gap, not a style nit.
# An explicit raise, not `assert` — asserts are stripped under `python -O`.
if set(_TRANSITIONS) != {(f, t) for f in _POSTURES for t in _POSTURES}:
    raise RuntimeError("_TRANSITIONS is missing or has extra (from, to) cells")


class MemberTarget(BaseModel):
    id: uuid.UUID
    value: str
    type: str


class EngagementResponse(BaseModel):
    id: uuid.UUID
    name: str
    posture: str
    posture_changed_at: str
    authorised_at: str | None
    authorisation_reference: str | None
    authorised_by: str | None
    created_at: str
    member_targets: list[MemberTarget]


class CreateEngagementRequest(BaseModel):
    name: str


class TransitionRequest(BaseModel):
    to: str
    authorisation_reference: str | None = None


def _member_targets(db: Session, engagement_id: uuid.UUID) -> list[MemberTarget]:
    rows = (
        db.query(Target.id, Target.value, Target.type)
        .filter(Target.engagement_id == engagement_id)
        .order_by(Target.value)
        .all()
    )
    return [MemberTarget(id=r[0], value=r[1], type=r[2]) for r in rows]


def _authorised_by_email(db: Session, user_id: uuid.UUID | None) -> str | None:
    if user_id is None:
        return None
    user = db.get(User, user_id)
    return user.email if user is not None else None


def _to_response(db: Session, e: Engagement) -> EngagementResponse:
    return EngagementResponse(
        id=e.id,
        name=e.name,
        posture=e.posture,
        posture_changed_at=e.posture_changed_at.isoformat(),
        authorised_at=e.authorised_at.isoformat() if e.authorised_at else None,
        authorisation_reference=e.authorisation_reference,
        authorised_by=_authorised_by_email(db, e.authorised_by_id),
        created_at=e.created_at.isoformat(),
        member_targets=_member_targets(db, e.id),
    )


@router.get("/", response_model=list[EngagementResponse])
def list_engagements(
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    engagements = db.query(Engagement).order_by(Engagement.created_at.desc()).all()
    if not engagements:
        return []

    ids = [e.id for e in engagements]
    # Batched, not per-row (the same discipline `probe_authorisation`'s
    # module docstring requires of every reader in this codebase): every
    # member target in one query, every authorising user's email in one.
    target_rows = (
        db.query(Target.id, Target.value, Target.type, Target.engagement_id)
        .filter(Target.engagement_id.in_(ids))
        .order_by(Target.value)
        .all()
    )
    targets_by_engagement: dict[uuid.UUID, list[MemberTarget]] = {}
    for tid, value, ttype, eid in target_rows:
        targets_by_engagement.setdefault(eid, []).append(MemberTarget(id=tid, value=value, type=ttype))

    authoriser_ids = {e.authorised_by_id for e in engagements if e.authorised_by_id is not None}
    email_by_id: dict[uuid.UUID, str] = {}
    if authoriser_ids:
        email_by_id = {
            u.id: u.email
            for u in db.query(User).filter(User.id.in_(authoriser_ids)).all()
        }

    return [
        EngagementResponse(
            id=e.id,
            name=e.name,
            posture=e.posture,
            posture_changed_at=e.posture_changed_at.isoformat(),
            authorised_at=e.authorised_at.isoformat() if e.authorised_at else None,
            authorisation_reference=e.authorisation_reference,
            authorised_by=email_by_id.get(e.authorised_by_id) if e.authorised_by_id else None,
            created_at=e.created_at.isoformat(),
            member_targets=targets_by_engagement.get(e.id, []),
        )
        for e in engagements
    ]


@router.get("/{engagement_id}", response_model=EngagementResponse)
def get_engagement(
    engagement_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    engagement = db.get(Engagement, engagement_id)
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return _to_response(db, engagement)


@router.post("/", response_model=EngagementResponse, status_code=201)
def create_engagement(
    data: CreateEngagementRequest,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    """Creates in `pre_close` — the restricting posture, the safe direction
    to default to (matches today's `patch_target` role pair: attaching a
    target to a NEW, unauthorised-by-default engagement never widens
    anything)."""
    name = data.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="name is required")
    if db.query(Engagement).filter(Engagement.name == name).first() is not None:
        raise HTTPException(status_code=409, detail="an engagement with this name already exists")

    engagement = Engagement(id=uuid.uuid4(), name=name, posture=EngagementPosture.PRE_CLOSE.value)
    db.add(engagement)
    db.commit()
    db.refresh(engagement)
    return _to_response(db, engagement)


@router.post("/{engagement_id}/transition", response_model=EngagementResponse)
def transition_engagement(
    request: Request,
    engagement_id: uuid.UUID,
    data: TransitionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    """Drives the engagement's posture through `_TRANSITIONS`. See that
    table for the legal moves; everything else is a 409."""
    engagement = db.get(Engagement, engagement_id)
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")
    if data.to not in _POSTURES:
        raise HTTPException(status_code=422, detail=f"to must be one of {list(_POSTURES)}")

    action = _TRANSITIONS[(engagement.posture, data.to)]

    if action == "deny":
        raise HTTPException(
            status_code=409,
            detail=f"cannot transition an engagement from {engagement.posture} to {data.to}",
        )
    if action == "noop":
        return _to_response(db, engagement)

    if action == "needs_ref":
        reference = (data.authorisation_reference or "").strip()
        if not reference:
            raise HTTPException(
                status_code=422,
                detail="authorisation_reference is required to transition to a widened posture",
            )
        engagement.authorised_by_id = current_user.id
        engagement.authorised_at = datetime.now(timezone.utc)
        engagement.authorisation_reference = reference
    elif action == "ok_clear":
        engagement.authorised_by_id = None
        engagement.authorised_at = None
        engagement.authorisation_reference = None
    # "ok_keep" — leave the existing authorisation record untouched.

    from_posture = engagement.posture
    engagement.posture = data.to
    engagement.posture_changed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(engagement)

    audit.record_detail(
        request,
        engagement=str(engagement.id),
        posture={"from": from_posture, "to": data.to},
        # NOT "authorisation_reference" as the kwarg name — `audit.scrub`'s
        # SECRET_KEY_HINTS matches any key containing "auth" and would
        # silently redact this legitimate business record (it exists to
        # catch `Authorization` headers / `client_secret`, not this field).
        # Same reasoning in `app/api/targets.py`'s `patch_target`.
        reference=engagement.authorisation_reference,
    )

    return _to_response(db, engagement)


@router.delete("/{engagement_id}", status_code=200)
def delete_engagement(
    engagement_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN)),
):
    """409, not the FK's raw 500, when member targets remain — the FK
    (`targets.engagement_id`, ON DELETE RESTRICT — migration 0059) would
    refuse this anyway; checking first turns that into a clean API error."""
    engagement = db.get(Engagement, engagement_id)
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")

    member_count = db.query(Target).filter(Target.engagement_id == engagement_id).count()
    if member_count:
        raise HTTPException(
            status_code=409,
            detail=f"engagement has {member_count} member target(s) — detach them first",
        )

    db.delete(engagement)
    db.commit()
    return {"deleted": True}
