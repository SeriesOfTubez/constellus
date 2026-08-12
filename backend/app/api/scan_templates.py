import uuid
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.connectors import REGISTRY
from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.models.scan import ScanKind, ScanRun, ScanStatus
from app.models.scan_template import ScanTemplate
from app.models.user import UserRole
from app.services import scan_executor, scheduler

router = APIRouter()


class ScanTemplateCreate(BaseModel):
    name: str
    scope: dict
    options: dict = {}
    schedule_cron: str | None = None
    enabled: bool = True
    tags: list[str] = []


class ScanTemplateUpdate(BaseModel):
    name: str | None = None
    scope: dict | None = None
    options: dict | None = None
    schedule_cron: str | None = None
    enabled: bool | None = None
    tags: list[str] | None = None


@router.get("/")
def list_templates(
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    templates = db.query(ScanTemplate).order_by(ScanTemplate.created_at.desc()).all()
    return [_serialize(t) for t in templates]


@router.post("/", status_code=201)
def create_template(
    data: ScanTemplateCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    if data.schedule_cron:
        _validate_cron(data.schedule_cron)

    tmpl = ScanTemplate(
        id=uuid.uuid4(),
        name=data.name,
        scope=data.scope,
        options=data.options or {},
        schedule_cron=data.schedule_cron,
        enabled=data.enabled,
        created_by_id=current_user.id,
        tags=data.tags or [],
    )
    db.add(tmpl)
    db.commit()
    db.refresh(tmpl)

    scheduler.upsert_template_job(tmpl)
    return _serialize(tmpl)


@router.get("/{template_id}")
def get_template(
    template_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    tmpl = db.get(ScanTemplate, template_id)
    if not tmpl:
        raise HTTPException(status_code=404, detail="Template not found")
    return _serialize(tmpl)


@router.patch("/{template_id}")
def update_template(
    template_id: uuid.UUID,
    data: ScanTemplateUpdate,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    tmpl = db.get(ScanTemplate, template_id)
    if not tmpl:
        raise HTTPException(status_code=404, detail="Template not found")
    if data.schedule_cron is not None and data.schedule_cron != "":
        _validate_cron(data.schedule_cron)

    if data.name is not None:
        tmpl.name = data.name
    if data.scope is not None:
        tmpl.scope = data.scope
    if data.options is not None:
        tmpl.options = data.options
    if data.schedule_cron is not None:
        tmpl.schedule_cron = data.schedule_cron or None
    if data.enabled is not None:
        tmpl.enabled = data.enabled
    if data.tags is not None:
        tmpl.tags = data.tags

    db.commit()
    db.refresh(tmpl)

    scheduler.upsert_template_job(tmpl)
    return _serialize(tmpl)


@router.delete("/{template_id}", status_code=204)
def delete_template(
    template_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    tmpl = db.get(ScanTemplate, template_id)
    if not tmpl:
        raise HTTPException(status_code=404, detail="Template not found")
    scheduler.remove_template_job(template_id)
    db.delete(tmpl)
    db.commit()


@router.post("/{template_id}/run", status_code=202)
def run_template_now(
    template_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    """Fire a one-shot run from the template, on top of any schedule."""
    tmpl = db.get(ScanTemplate, template_id)
    if not tmpl:
        raise HTTPException(status_code=404, detail="Template not found")

    run = ScanRun(
        id=uuid.uuid4(),
        name=f"{tmpl.name} (manual)",
        status=ScanStatus.PENDING,
        kind=ScanKind.MONITORING,
        scope=tmpl.scope,
        options=tmpl.options or {},
        template_id=tmpl.id,
        created_by_id=current_user.id,
    )
    db.add(run)
    db.commit()

    background_tasks.add_task(scan_executor.launch, run.id, run.scope, REGISTRY)
    return {"scan_id": str(run.id), "status": "queued"}


@router.get("/_/jobs")
def list_scheduled_jobs(
    _=Depends(require_role(UserRole.ADMIN)),
):
    """Debug endpoint — what's actually loaded in the scheduler right now."""
    return scheduler.list_jobs()


# ── helpers ───────────────────────────────────────────────────────────────────

def _validate_cron(expr: str) -> None:
    from apscheduler.triggers.cron import CronTrigger
    try:
        CronTrigger.from_crontab(expr, timezone="UTC")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid cron expression: {exc}")


def _serialize(t: ScanTemplate) -> dict:
    return {
        "id": str(t.id),
        "name": t.name,
        "scope": t.scope or {},
        "options": t.options or {},
        "schedule_cron": t.schedule_cron,
        "enabled": t.enabled,
        "tags": t.tags or [],
        "created_at": t.created_at.isoformat() if isinstance(t.created_at, datetime) else None,
        "created_by_id": str(t.created_by_id) if t.created_by_id else None,
    }
