import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.models.domain_verification import DomainVerification
from app.models.user import UserRole
from app.services import domain_verification as dv_svc

router = APIRouter()


class DomainVerificationResponse(BaseModel):
    id: uuid.UUID
    domain: str
    verified: bool
    method: str | None
    connector_id: str | None
    token: str
    verified_at: str | None
    created_at: str

    model_config = {"from_attributes": True}


class AddDomainRequest(BaseModel):
    domain: str


@router.get("/", response_model=list[DomainVerificationResponse])
def list_domains(
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    rows = db.query(DomainVerification).order_by(DomainVerification.created_at.desc()).all()
    return [_to_response(r) for r in rows]


@router.post("/", response_model=DomainVerificationResponse, status_code=status.HTTP_201_CREATED)
def add_domain(
    data: AddDomainRequest,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    domain = data.domain.lower().strip().rstrip(".")
    record = dv_svc.ensure_pending(db, domain)
    return _to_response(record)


@router.post("/{domain_id}/verify", response_model=DomainVerificationResponse)
def verify_domain(
    domain_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    record = db.get(DomainVerification, domain_id)
    if not record:
        raise HTTPException(status_code=404, detail="Domain not found")
    if record.verified:
        return _to_response(record)
    success = dv_svc.attempt_txt_verification(db, record.domain)
    db.refresh(record)
    if not success:
        raise HTTPException(
            status_code=422,
            detail=f"TXT record not found. Add: {dv_svc.TXT_PREFIX}.{record.domain} = {record.token}",
        )
    return _to_response(record)


@router.delete("/{domain_id}", status_code=204)
def delete_domain(
    domain_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    record = db.get(DomainVerification, domain_id)
    if not record:
        raise HTTPException(status_code=404, detail="Domain not found")
    db.delete(record)
    db.commit()


def _to_response(r: DomainVerification) -> DomainVerificationResponse:
    return DomainVerificationResponse(
        id=r.id,
        domain=r.domain,
        verified=r.verified,
        method=r.method,
        connector_id=r.connector_id,
        token=r.token,
        verified_at=r.verified_at.isoformat() if r.verified_at else None,
        created_at=r.created_at.isoformat(),
    )
