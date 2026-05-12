import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.models.target import Target, TargetType
from app.models.user import UserRole
from app.services import target_service as svc

router = APIRouter()


class TargetResponse(BaseModel):
    id: uuid.UUID
    type: str
    value: str
    verified: bool
    verification_method: str | None
    connector_id: str | None
    token: str
    whois_org: str | None
    whois_asn: str | None
    verified_at: str | None
    created_at: str
    notes: str | None

    model_config = {"from_attributes": True}


class AddTargetRequest(BaseModel):
    value: str
    notes: str | None = None


class AcknowledgeRequest(BaseModel):
    confirmed: bool


@router.get("/", response_model=list[TargetResponse])
def list_targets(
    verified: bool | None = None,
    type: str | None = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    q = db.query(Target)
    if verified is not None:
        q = q.filter(Target.verified == verified)
    if type:
        q = q.filter(Target.type == type)
    return [_to_response(t) for t in q.order_by(Target.created_at.desc()).all()]


@router.post("/", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
def add_target(
    data: AddTargetRequest,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    value = data.value.lower().strip().rstrip(".")
    if not value:
        raise HTTPException(status_code=422, detail="Value is required")
    target = svc.ensure_pending(db, value)
    if data.notes and not target.notes:
        target.notes = data.notes
        db.commit()
    return _to_response(target)


@router.post("/{target_id}/verify", response_model=TargetResponse)
def verify_target(
    target_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    """Check TXT record for domain targets."""
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    if target.type != TargetType.DOMAIN:
        raise HTTPException(status_code=400, detail="TXT verification only applies to domain targets")
    if target.verified:
        return _to_response(target)
    success = svc.attempt_txt_verification(db, target_id)
    db.refresh(target)
    if not success:
        raise HTTPException(
            status_code=422,
            detail=f"TXT record not found. Add: {svc.TXT_PREFIX}.{target.value} = {target.token}",
        )
    return _to_response(target)


@router.post("/{target_id}/acknowledge", response_model=TargetResponse)
def acknowledge_target(
    target_id: uuid.UUID,
    data: AcknowledgeRequest,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    """Acknowledge ownership of an IP or CIDR target."""
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    if target.type == TargetType.DOMAIN:
        raise HTTPException(status_code=400, detail="Use /verify for domain targets")
    if not data.confirmed:
        raise HTTPException(status_code=422, detail="Must confirm ownership")
    result = svc.acknowledge(db, target_id, current_user.id)
    return _to_response(result)


@router.delete("/{target_id}", status_code=204)
def delete_target(
    target_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    db.delete(target)
    db.commit()


def _to_response(t: Target) -> TargetResponse:
    return TargetResponse(
        id=t.id,
        type=t.type,
        value=t.value,
        verified=t.verified,
        verification_method=t.verification_method,
        connector_id=t.connector_id,
        token=t.token,
        whois_org=t.whois_org,
        whois_asn=t.whois_asn,
        verified_at=t.verified_at.isoformat() if t.verified_at else None,
        created_at=t.created_at.isoformat(),
        notes=t.notes,
    )
