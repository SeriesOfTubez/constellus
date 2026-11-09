"""Read surface for scheduler run history (planning#329).

Rows are written by `services/job_runs.py`; this module only reads. There is
no write or delete route: retention is a setting (`/api/settings/jobs`) and a
purge job, not an API action.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import require_permission
from app.core.database import get_db
from app.core.permissions import Permission
from app.models.job_run import JOB_RUN_FINISH_REASONS, JobRun
from app.services import job_runs

router = APIRouter()


def _serialize(row: JobRun) -> dict:
    return {
        "id": str(row.id),
        "job": row.job,
        "started_at": row.started_at.isoformat(),
        "finished_at": row.finished_at.isoformat(),
        "duration_seconds": (row.finished_at - row.started_at).total_seconds(),
        "finish_reason": row.finish_reason,
        "items_selected": row.items_selected,
        "counts": row.counts or {},
        "error": row.error,
    }


@router.get("/runs")
def list_runs(
    job: str | None = None,
    finish_reason: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    _=Depends(require_permission(Permission.JOBS_READ)),
):
    """Finished scheduler runs, newest first. ADMIN only."""
    if finish_reason is not None and finish_reason not in JOB_RUN_FINISH_REASONS:
        raise HTTPException(
            status_code=422,
            detail="Unknown finish reason. Use one of: " + ", ".join(sorted(JOB_RUN_FINISH_REASONS)) + ".",
        )
    q = select(JobRun)
    if job:
        q = q.where(JobRun.job == job)
    if finish_reason:
        q = q.where(JobRun.finish_reason == finish_reason)
    rows = db.scalars(q.order_by(JobRun.started_at.desc()).limit(limit)).all()
    return [_serialize(r) for r in rows]


@router.get("/status")
def jobs_status(
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db),
    _=Depends(require_permission(Permission.JOBS_READ)),
):
    """Per job: the latest recorded run and the hourly slots with no run recorded.

    A missed slot means no run is RECORDED for that hour. It may be that the
    backend was down, the previous run overran, or the record write failed;
    this does not claim which.
    """
    return {
        "window_hours": hours,
        "jobs": [
            {
                "job": s.job,
                "cadence_minute": s.cadence_minute,
                "last_run": _serialize(s.last_run) if s.last_run else None,
                "recorded_since": s.recorded_since.isoformat() if s.recorded_since else None,
                "missed_slots": [m.isoformat() for m in s.missed_slots],
            }
            for s in job_runs.status(db, hours=hours)
        ],
    }
