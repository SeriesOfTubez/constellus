from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import require_role
from app.core.database import get_db
from app.models.system_log import SystemLog
from app.models.user import UserRole
from app.services import app_settings as settings_svc

RETENTION_OPTIONS = [1, 3, 7, 15, 30, 60, 90]

router = APIRouter()

CONNECTOR_SOURCES = {
    "cloudflare", "mailtrap", "tenable", "wiz", "fortimanager", "nuclei",
    "cert_transparency", "certspotter", "subfinder", "dnsrecon", "bruteforce",
}


@router.get("/")
def list_logs(
    source: str | None = None,
    level: str | None = None,
    search: str | None = None,
    since: datetime | None = None,
    limit: int = Query(default=500, le=2000),
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    q = db.query(SystemLog)
    if source:
        if source == "system":
            q = q.filter(SystemLog.source.notin_(CONNECTOR_SOURCES))
        else:
            q = q.filter(SystemLog.source == source)
    if level:
        q = q.filter(SystemLog.level == level.upper())
    if search:
        q = q.filter(SystemLog.message.ilike(f"%{search}%"))
    if since:
        q = q.filter(SystemLog.created_at > since)
    rows = q.order_by(SystemLog.created_at.desc()).limit(limit).all()
    return [
        {
            "id": str(r.id),
            "created_at": r.created_at.isoformat(),
            "level": r.level,
            "source": r.source,
            "logger_name": r.logger_name,
            "message": r.message,
        }
        for r in rows
    ]


@router.get("/sources")
def list_sources(
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    """Distinct sources present in the log table."""
    rows = db.query(SystemLog.source).distinct().order_by(SystemLog.source).all()
    return [r.source for r in rows]


@router.delete("/", status_code=204)
def clear_logs(
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN)),
):
    db.query(SystemLog).delete()
    db.commit()


@router.get("/settings")
def get_log_settings(
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    return {
        "retention_days": settings_svc.get_int(db, "log_retention_days") or 15,
        "retention_options": RETENTION_OPTIONS,
    }


class RetentionUpdate(BaseModel):
    retention_days: int


@router.put("/settings")
def update_log_settings(
    data: RetentionUpdate,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN)),
):
    if data.retention_days not in RETENTION_OPTIONS:
        raise HTTPException(status_code=422, detail=f"retention_days must be one of {RETENTION_OPTIONS}")
    settings_svc.set_value(db, "log_retention_days", str(data.retention_days))
    return {"retention_days": data.retention_days}
