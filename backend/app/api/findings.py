import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.connectors import REGISTRY
from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.models.finding import Finding, FindingState
from app.models.user import UserRole
from app.models.scan import ScanRun, ScanStatus
from app.services import scan_executor

router = APIRouter()


class StateUpdate(BaseModel):
    state: FindingState
    suppressed_until: datetime | None = None


@router.get("/")
def list_findings(
    scan_id: uuid.UUID | None = None,
    severity: str | None = None,
    category: str | None = None,
    state: str | None = None,
    asset_value: str | None = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    q = db.query(Finding)
    if scan_id:
        q = q.filter(Finding.scan_run_id == scan_id)
    if severity:
        q = q.filter(Finding.severity == severity)
    if category:
        q = q.filter(Finding.category == category)
    if state:
        q = q.filter(Finding.state == state)
    if asset_value:
        q = q.filter(Finding.asset_value.ilike(f"%{asset_value}%"))
    return q.order_by(Finding.discovered_at.desc()).limit(1000).all()


@router.patch("/{finding_id}/state")
def update_finding_state(
    finding_id: uuid.UUID,
    data: StateUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    finding = (
        db.query(Finding)
        .filter(Finding.id == finding_id)
        .order_by(Finding.discovered_at.desc())
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.state = data.state

    if data.state == FindingState.ACKNOWLEDGED:
        finding.acknowledged_by_id = current_user.id
        finding.acknowledged_at = datetime.now(timezone.utc)

    if data.state == FindingState.SUPPRESSED:
        if not data.suppressed_until:
            raise HTTPException(status_code=422, detail="suppressed_until is required when suppressing")
        finding.suppressed_until = data.suppressed_until
        finding.acknowledged_by_id = current_user.id
        finding.acknowledged_at = datetime.now(timezone.utc)

    db.commit()
    return finding


@router.post("/{finding_id}/verify", status_code=202)
def verify_finding(
    finding_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    finding = (
        db.query(Finding)
        .filter(Finding.id == finding_id)
        .order_by(Finding.discovered_at.desc())
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    run = ScanRun(
        id=uuid.uuid4(),
        name=f"Verify: {finding.title[:80]}",
        status=ScanStatus.PENDING,
        scope={"domains": [finding.asset_value], "ip_ranges": []},
        created_by_id=current_user.id,
    )
    db.add(run)
    db.commit()

    background_tasks.add_task(
        _verify_and_resolve, run.id, finding_id, finding.finding_type, REGISTRY
    )
    return {"scan_id": run.id, "status": "queued"}


# ── helpers ───────────────────────────────────────────────────────────────────

def _verify_and_resolve(
    scan_run_id: uuid.UUID,
    original_finding_id: uuid.UUID,
    finding_type: str,
    registry: dict,
) -> None:
    from app.core.database import SessionLocal
    db = SessionLocal()
    try:
        run = db.get(ScanRun, scan_run_id)
        if not run:
            return
        scan_executor.launch(scan_run_id, run.scope, registry)
        new_finding = (
            db.query(Finding)
            .filter(Finding.scan_run_id == scan_run_id, Finding.finding_type == finding_type)
            .first()
        )
        if not new_finding:
            original = (
                db.query(Finding)
                .filter(Finding.id == original_finding_id)
                .order_by(Finding.discovered_at.desc())
                .first()
            )
            if original:
                original.state = FindingState.RESOLVED
                db.commit()
    finally:
        db.close()
