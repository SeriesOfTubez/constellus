from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.services.user import is_first_run

router = APIRouter()


@router.get("/status")
def status(db: Session = Depends(get_db)):
    return {
        "first_run": is_first_run(db),
        "version": "0.1.0",
    }


@router.get("/monitoring-status")
def monitoring_status(db: Session = Depends(get_db)):
    """Return the last + next default monitoring run timestamps.

    The default monitoring template scans every target on a recurring
    schedule; this endpoint lets the UI show "last run / next run" so
    operators don't have to guess when assets and findings were refreshed.
    """
    from app.models.scan import ScanRun, ScanStatus
    from app.services import scheduler

    last_run = (
        db.query(ScanRun)
        .filter(ScanRun.template_id == scheduler.DEFAULT_MONITORING_TEMPLATE_ID)
        .filter(ScanRun.status == ScanStatus.COMPLETED.value)
        .order_by(ScanRun.completed_at.desc())
        .first()
    )
    next_run_iso: str | None = None
    for job in scheduler.list_jobs():
        if job["id"] == str(scheduler.DEFAULT_MONITORING_TEMPLATE_ID):
            next_run_iso = job["next_run_time"]
            break

    return {
        "last_run_at": last_run.completed_at.isoformat() if last_run else None,
        "last_run_id": str(last_run.id) if last_run else None,
        "next_run_at": next_run_iso,
    }
