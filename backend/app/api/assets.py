import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.connectors import REGISTRY
from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.models.asset import Asset
from app.models.user import UserRole
from app.services import scan_executor
from app.models.scan import ScanRun, ScanStatus

router = APIRouter()


class AssetIgnoreUpdate(BaseModel):
    ignored: bool


@router.get("/")
def list_assets(
    scan_id: uuid.UUID | None = None,
    asset_type: str | None = None,
    show_ignored: bool = False,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    q = db.query(Asset)
    if scan_id:
        q = q.filter(Asset.scan_run_id == scan_id)
    if asset_type:
        q = q.filter(Asset.asset_type == asset_type)
    if not show_ignored:
        q = q.filter(Asset.ignored == False)  # noqa: E712
    return q.order_by(Asset.discovered_at.desc()).limit(1000).all()


@router.patch("/{asset_id}/ignore", status_code=200)
def set_asset_ignored(
    asset_id: uuid.UUID,
    data: AssetIgnoreUpdate,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id)
        .order_by(Asset.discovered_at.desc())
        .first()
    )
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    asset.ignored = data.ignored
    db.commit()
    return {"id": str(asset_id), "ignored": asset.ignored}


@router.delete("/{asset_id}", status_code=204)
def delete_asset(
    asset_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id)
        .order_by(Asset.discovered_at.desc())
        .first()
    )
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    db.delete(asset)
    db.commit()


@router.post("/{asset_id}/scan", status_code=202)
def scan_asset(
    asset_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    """Kick off an on-demand scan targeting a single asset."""
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id)
        .order_by(Asset.discovered_at.desc())
        .first()
    )
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    run = ScanRun(
        id=uuid.uuid4(),
        name=f"On-demand: {asset.value}",
        status=ScanStatus.PENDING,
        scope={"domains": [asset.value] if asset.asset_type == "dns_record" else [],
               "ip_ranges": [asset.value] if asset.asset_type == "ip_address" else []},
        created_by_id=current_user.id,
    )
    db.add(run)
    db.commit()

    background_tasks.add_task(scan_executor.launch, run.id, run.scope, REGISTRY)
    return {"scan_id": run.id, "status": "queued"}
