import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.connectors import REGISTRY
from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.models.scan import ScanKind, ScanRun, ScanStatus
from app.models.scan_template import ScanTemplate
from app.models.user import UserRole
from app.schemas.scan import ScanRequest, ScanResponse
from app.services import scan_executor


class ScanUpdate(BaseModel):
    name: str | None = None

router = APIRouter()


@router.get("/", response_model=list[ScanResponse])
def list_scans(
    kind: str | None = None,
    include_rechecks: bool = False,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """List recent scan runs.

    By default rechecks are filtered out — they are noise in the Activity
    feed (one-off per-asset scans the user triggered). Pass
    ?include_rechecks=true to include them, or ?kind=<csv> to filter by
    specific kinds.
    """
    q = db.query(ScanRun)
    if kind:
        kinds = [k.strip() for k in kind.split(",") if k.strip()]
        q = q.filter(ScanRun.kind.in_(kinds))
    elif not include_rechecks:
        q = q.filter(ScanRun.kind != "recheck")
    runs = q.order_by(ScanRun.created_at.desc()).limit(100).all()
    return [_enrich(db, r) for r in runs]


@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan(
    data: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    if not data.scope.domains and not data.scope.ip_ranges:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Scope must include at least one domain or IP range",
        )

    # Every scan creates an identity row (template) it belongs to. One-shot
    # scans get a template with schedule_cron=null/enabled=false; the template
    # exists so the scan can be rerun or promoted to a schedule later.
    scope = data.scope.model_dump()
    options = data.options.model_dump()
    tmpl = ScanTemplate(
        id=uuid.uuid4(),
        name=data.name or "Untitled scan",
        scope=scope,
        options=options,
        schedule_cron=None,
        enabled=False,
        created_by_id=current_user.id,
    )
    db.add(tmpl)

    run = ScanRun(
        id=uuid.uuid4(),
        name=data.name,
        status=ScanStatus.PENDING,
        kind=ScanKind.MANUAL,
        scope=scope,
        options=options,
        template_id=tmpl.id,
        created_by_id=current_user.id,
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    background_tasks.add_task(scan_executor.launch, run.id, run.scope, REGISTRY)

    return _enrich(db, run)


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    run = db.get(ScanRun, scan_id)
    if not run:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _enrich(db, run)


@router.patch("/{scan_id}", response_model=ScanResponse)
def update_scan(
    scan_id: uuid.UUID,
    data: ScanUpdate,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    run = db.get(ScanRun, scan_id)
    if not run:
        raise HTTPException(status_code=404, detail="Scan not found")
    if data.name is not None:
        run.name = data.name
    db.commit()
    return _enrich(db, run)


@router.delete("/{scan_id}", status_code=204)
def delete_scan(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    run = db.get(ScanRun, scan_id)
    if not run:
        raise HTTPException(status_code=404, detail="Scan not found")
    if run.status == ScanStatus.RUNNING:
        raise HTTPException(status_code=400, detail="Cannot delete a running scan — cancel it first")
    # Canonical assets / findings persist across scan runs and are *not*
    # deleted here — they have durable identity. The run row goes away;
    # last_seen_at on the canonical rows keeps the historical record.
    db.delete(run)
    db.commit()


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
def cancel_scan(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    run = db.get(ScanRun, scan_id)
    if not run:
        raise HTTPException(status_code=404, detail="Scan not found")
    if run.status not in (ScanStatus.PENDING, ScanStatus.RUNNING):
        raise HTTPException(status_code=400, detail="Scan is not in a cancellable state")
    run.status = ScanStatus.CANCELLED
    db.commit()
    db.refresh(run)
    return _enrich(db, run)


# ── helpers ───────────────────────────────────────────────────────────────────

def _enrich(db: Session, run: ScanRun) -> ScanResponse:
    return ScanResponse(
        id=run.id,
        name=run.name,
        status=run.status,
        kind=run.kind,
        scope=run.scope,
        options=run.options or {},
        connectors_used=run.connectors_used,
        created_at=run.created_at,
        started_at=run.started_at,
        completed_at=run.completed_at,
        error=run.error,
        asset_count=run.asset_count,
        finding_count=run.finding_count,
    )
