"""Run history for the recorded scheduler jobs (planning#329).

One row per FINISHED run (a skipped run writes nothing; gaps are computed at
read time by `status`). Recording is best effort: it never fails a run.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Callable, TypeVar

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.job_run import JobRun
from app.services import app_settings

if TYPE_CHECKING:
    from app.services.org_discovery.rolling import RollingResult
    from app.services.page_capture import SweepResult

log = logging.getLogger(__name__)

T = TypeVar("T")

# A job listed here is expected hourly at that UTC minute. The cadence stays in
# code (planning#320); this is the single source for the cron registration and
# for the missed-slot computation.
CADENCE_MINUTE: dict[str, int] = {"rediscovery_tick": 20, "capture_sweep": 40}

RUN_HISTORY_DAYS_KEY = "jobs.run_history_days"
DEFAULT_RUN_HISTORY_DAYS, RUN_HISTORY_DAYS_MIN, RUN_HISTORY_DAYS_MAX = 90, 7, 365

_HOUR = timedelta(hours=1)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def run_history_days(db: Session) -> int:
    value = app_settings.get_int(db, RUN_HISTORY_DAYS_KEY)
    if value is not None and RUN_HISTORY_DAYS_MIN <= value <= RUN_HISTORY_DAYS_MAX:
        return value
    return DEFAULT_RUN_HISTORY_DAYS


@dataclass(frozen=True)
class RunOutcome:
    finish_reason: str
    items_selected: int
    counts: dict[str, int]


def capture_outcome(r: "SweepResult") -> RunOutcome:
    if r.not_configured:
        reason = "not_configured"
    elif r.stopped_on_lookup:
        reason = "lookup_failures"
    elif r.out_of_time:
        reason = "time_limit"
    else:
        reason = "done"
    return RunOutcome(
        reason,
        r.candidates,
        {"candidates": r.candidates, "queued": r.queued, "budget": r.budget,
         "skipped": r.skipped, "errors": r.errors},
    )


def rediscovery_outcome(r: "RollingResult") -> RunOutcome:
    if r.rate_limited:
        reason = "rate_limited"
    elif r.out_of_time:
        reason = "time_limit"
    else:
        reason = "done"
    return RunOutcome(
        reason,
        r.due,
        {"due": r.due, "ok": r.ok, "failed": r.failed, "rate_limited": r.rate_limited,
         "skipped_busy": r.skipped_busy, "skipped": r.skipped, "errors": r.errors},
    )


def record(job: str, started_at: datetime, finished_at: datetime, outcome: RunOutcome,
           error: str | None = None) -> bool:
    """Own unit of work. Never raises."""
    db = None
    try:
        db = SessionLocal()
        db.add(JobRun(
            job=job, started_at=started_at, finished_at=finished_at,
            finish_reason=outcome.finish_reason, items_selected=outcome.items_selected,
            counts=dict(outcome.counts), error=error,
        ))
        db.commit()
        return True
    except Exception:
        try:
            if db is not None:
                db.rollback()
        except Exception:
            pass
        log.warning("job_runs: recording a %s run failed", job, exc_info=True)
        return False
    finally:
        if db is not None:
            try:
                db.close()
            except Exception:
                pass


def _record_safely(job: str, started_at: datetime,
                   outcome: RunOutcome | Callable[[], RunOutcome], error: str | None = None) -> None:
    try:
        resolved = outcome() if callable(outcome) else outcome
        finished_at = _now()
        record(job, started_at, finished_at, resolved, error=error)
    except Exception:
        log.warning("job_runs: recording a %s run failed", job, exc_info=True)


def run_recorded(job: str, fn: Callable[[], T], to_outcome: Callable[[T], RunOutcome]) -> T:
    """Run `fn`, record the run, return its result. A failure of `fn` is
    recorded (exception TYPE name only: messages can carry URLs or keys) and
    re-raised; a failure to record is only logged."""
    started = _now()
    try:
        result = fn()
    except Exception as exc:
        _record_safely(job, started, RunOutcome("error", 0, {}), error=type(exc).__name__)
        raise
    _record_safely(job, started, lambda: to_outcome(result))
    return result


def purge(db: Session, now: datetime | None = None) -> int:
    """Delete runs older than the retention setting. Flushes only; the caller commits."""
    now = now or _now()
    cutoff = now - timedelta(days=run_history_days(db))
    res = db.execute(delete(JobRun).where(JobRun.started_at < cutoff).execution_options(synchronize_session=False))
    db.flush()
    return res.rowcount or 0


@dataclass
class JobStatus:
    job: str
    cadence_minute: int
    last_run: JobRun | None
    recorded_since: datetime | None
    missed_slots: list[datetime]


def _slot_at_or_before(t: datetime, minute: int) -> datetime:
    s = t.astimezone(timezone.utc).replace(minute=minute, second=0, microsecond=0)
    return s if s <= t else s - _HOUR


def status(db: Session, now: datetime | None = None, hours: int = 24) -> list[JobStatus]:
    now = (now or _now()).astimezone(timezone.utc)
    window_start = now - timedelta(hours=hours)
    out: list[JobStatus] = []
    for job, minute in CADENCE_MINUTE.items():
        last = db.scalars(
            select(JobRun).where(JobRun.job == job).order_by(JobRun.started_at.desc()).limit(1)
        ).first()
        since = db.scalar(select(func.min(JobRun.started_at)).where(JobRun.job == job))
        missed: list[datetime] = []
        if since is not None:
            starts = db.scalars(
                select(JobRun.started_at).where(JobRun.job == job, JobRun.started_at >= window_start - _HOUR)
            ).all()
            covered = {_slot_at_or_before(s, minute) for s in starts}
            in_window = _slot_at_or_before(window_start, minute)
            if in_window < window_start:
                in_window += _HOUR  # a slot before the window start is out
            first = max(in_window, _slot_at_or_before(since, minute))
            slot = first
            while slot + _HOUR <= now:
                if slot not in covered:
                    missed.append(slot)
                slot += _HOUR
        out.append(JobStatus(job, minute, last, since, missed))
    return out
