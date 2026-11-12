"""Run history for the recorded scheduler jobs (planning#329).

One row per FINISHED run (a skipped run writes nothing; gaps are computed at
read time by `status`). Recording is best effort: it never fails a run.

A job's `Cadence` is one of three kinds: `hourly_at` and `daily_at` are UTC
clock grids, `interval` has no grid (its slots are measured from the last
recorded run). One coverage rule applies to all: a slot is covered by a run
that starts within `COVERAGE` after it, and is judged once that window ends.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Callable, Literal, TypeVar

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.job_run import JobRun
from app.services import app_settings

if TYPE_CHECKING:
    from app.services.cloud_ranges import RefreshResult
    from app.services.org_discovery.rolling import RollingResult
    from app.services.page_capture import SweepResult

log = logging.getLogger(__name__)

T = TypeVar("T")

CadenceKind = Literal["hourly_at", "daily_at", "interval"]
_HOUR = timedelta(hours=1)
_DAY = timedelta(days=1)
# One rule for every kind: a slot is covered by a run that STARTS within this
# long after it, and is judged once that window ends.
COVERAGE = timedelta(hours=1)


@dataclass(frozen=True)
class Cadence:
    """When a job is expected to start. `hourly_at`/`daily_at` are clock grids
    (cron, UTC). `interval` has no grid: APScheduler anchors it at process
    start, so its slots are measured from the last recorded run."""
    kind: CadenceKind
    minute: int | None = None
    hour: int | None = None
    every: timedelta | None = None

    def __post_init__(self) -> None:
        if self.kind == "hourly_at":
            ok = self.minute is not None and 0 <= self.minute <= 59 and self.hour is None and self.every is None
        elif self.kind == "daily_at":
            ok = (self.minute is not None and 0 <= self.minute <= 59 and self.hour is not None
                  and 0 <= self.hour <= 23 and self.every is None)
        else:
            ok = self.every is not None and self.every > timedelta(0) and self.minute is None and self.hour is None
        if not ok:
            raise ValueError(f"inconsistent cadence: {self!r}")

    @property
    def period(self) -> timedelta:
        if self.kind == "hourly_at":
            return _HOUR
        if self.kind == "daily_at":
            return _DAY
        return self.every  # type: ignore[return-value]

    def to_dict(self) -> dict:
        return {
            "kind": self.kind, "minute": self.minute, "hour": self.hour,
            "every_seconds": int(self.every.total_seconds()) if self.every is not None else None,
        }


def hourly_at(minute: int) -> Cadence:
    return Cadence("hourly_at", minute=minute)


def daily_at(hour: int, minute: int = 0) -> Cadence:
    return Cadence("daily_at", minute=minute, hour=hour)


def every(**kw) -> Cadence:
    return Cadence("interval", every=timedelta(**kw))


# The single source for the scheduler registration AND the missed-slot
# computation (the registration test asserts they agree). Order = the order
# on the Settings card: hourly, then the hourly interval, daily, then the
# longer intervals in registration order. The cadence stays in code
# (planning#320). The five seconds-scale ticks (ct_refresher, page_capture,
# capture_tokens, tenancy_enricher, tenancy_tls) are planning#336 slice 2.
CADENCE: dict[str, Cadence] = {
    "alert_digests": hourly_at(5),
    "rediscovery_tick": hourly_at(20),
    "capture_sweep": hourly_at(40),
    "run_reaper": every(hours=1),
    "nightly_rescore": daily_at(3),
    "epss_refresher": every(hours=12),
    "cpe_index_refresher": every(hours=24),
    "cloud_ranges_refresher": every(hours=24),
    "partition_maintenance": every(hours=24),
    "hygiene_scoring": every(hours=24),
    "job_run_purger": every(hours=24),
    "llm_ledger_pruner": every(hours=24),
    "chat_transcript_purger": every(hours=24),
    "report_purger": every(hours=24),
    "llm_models_refresher": every(hours=24),
}

RUN_HISTORY_DAYS_KEY = "jobs.run_history_days"
DEFAULT_RUN_HISTORY_DAYS, RUN_HISTORY_DAYS_MIN, RUN_HISTORY_DAYS_MAX = 90, 7, 365


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


def int_outcome(key: str) -> Callable[[int], RunOutcome]:
    """For a job whose result is one count (rows deleted, digests created)."""
    def to_outcome(n: int) -> RunOutcome:
        return RunOutcome("done", n, {key: n})
    return to_outcome


def epss_outcome(r: dict) -> RunOutcome:  # {"upserted": int, "pruned": int}
    return RunOutcome("done", r["upserted"], {"upserted": r["upserted"], "pruned": r["pruned"]})


def cpe_index_outcome(r: dict) -> RunOutcome:  # cpe_cve_sync.refresh: {"seeded": int, "delta": int}
    return RunOutcome("done", r["seeded"] + r["delta"], {"seeded": r["seeded"], "delta": r["delta"]})


def cloud_ranges_outcome(r: "RefreshResult") -> RunOutcome:
    """Only reached for ok=True (the scheduler raises on a rejected refresh)."""
    items = r.record_count if r.changed else 0
    return RunOutcome("done", items, {"changed": int(r.changed), "record_count": r.record_count})


def partition_outcome(stats: dict[str, dict]) -> RunOutcome:
    """partition_maintenance.run: {table: {"created": [..], "dropped": [..], "retained": int}} -> totals."""
    created = sum(len(v.get("created", ())) for v in stats.values())
    dropped = sum(len(v.get("dropped", ())) for v in stats.values())
    retained = sum(int(v.get("retained", 0)) for v in stats.values())
    return RunOutcome("done", created + dropped, {"created": created, "dropped": dropped, "retained": retained})


def hygiene_outcome(stats: dict) -> RunOutcome:  # elapsed_ms dropped: duration is on the row
    keys = ("scored", "excluded", "deleted", "history_rows")
    return RunOutcome("done", int(stats["scored"]), {k: int(stats.get(k, 0)) for k in keys})


def rescore_outcome(stats: dict) -> RunOutcome:  # rescored, history_rows, promotions
    keys = ("rescored", "history_rows", "promotions")
    return RunOutcome("done", int(stats["rescored"]), {k: int(stats.get(k, 0)) for k in keys})


def reaper_outcome(r: dict) -> RunOutcome:  # {"startup": bool, "runs": int, "ingest_runs": int}
    return RunOutcome("done", r["runs"] + r["ingest_runs"],
                      {"startup": int(r["startup"]), "runs": r["runs"], "ingest_runs": r["ingest_runs"]})


def llm_models_outcome(n: int | None) -> RunOutcome:
    """None = the connector is not configured (the run skipped before any fetch)."""
    if n is None:
        return RunOutcome("not_configured", 0, {})
    return RunOutcome("done", n, {"models": n})


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
    cadence: Cadence
    last_run: JobRun | None
    recorded_since: datetime | None
    missed_slots: list[datetime]


def _grid_at_or_before(t: datetime, c: Cadence) -> datetime:
    """The latest grid point <= t (hourly_at / daily_at only)."""
    t = t.astimezone(timezone.utc)
    if c.kind == "hourly_at":
        s = t.replace(minute=c.minute, second=0, microsecond=0)
    else:
        s = t.replace(hour=c.hour, minute=c.minute, second=0, microsecond=0)
    return s if s <= t else s - c.period


def _grid_missed(starts: list[datetime], since: datetime, window_start: datetime, now: datetime,
                 c: Cadence) -> list[datetime]:
    period = c.period
    covered: set[datetime] = set()
    for s in starts:
        g = _grid_at_or_before(s, c)
        if s < g + COVERAGE:
            covered.add(g)
    first_in_window = _grid_at_or_before(window_start, c)
    if first_in_window < window_start:
        first_in_window += period
    # The first judged slot is the one whose coverage window holds the first recorded run.
    first_recorded = _grid_at_or_before(since - COVERAGE, c) + period
    slot = max(first_in_window, first_recorded)
    missed: list[datetime] = []
    while slot + COVERAGE <= now:
        if slot not in covered:
            missed.append(slot)
        slot += period
    return missed


def _interval_missed(anchor: datetime | None, starts: list[datetime], window_start: datetime,
                     now: datetime, c: Cadence) -> list[datetime]:
    """Slots are last recorded start + k*every. An early run (after a restart)
    re-anchors and is never a miss; a gap longer than every + COVERAGE is one
    missed slot per `every` elapsed. Sub-hour intervals get no computation:
    for a seconds-scale tick idle is not missed (planning#336 slice 2)."""
    step = c.every
    if step is None or step < COVERAGE:
        return []
    chain = ([anchor] if anchor is not None else []) + list(starts)
    missed: list[datetime] = []
    for i, a in enumerate(chain):
        end = chain[i + 1] if i + 1 < len(chain) else now
        k = 1
        while a + k * step + COVERAGE <= end:
            slot = a + k * step
            if slot >= window_start:
                missed.append(slot)
            k += 1
    return missed


def status(db: Session, now: datetime | None = None, hours: int = 24) -> list[JobStatus]:
    now = (now or _now()).astimezone(timezone.utc)
    window_start = now - timedelta(hours=hours)
    out: list[JobStatus] = []
    for job, cadence in CADENCE.items():
        last = db.scalars(select(JobRun).where(JobRun.job == job).order_by(JobRun.started_at.desc()).limit(1)).first()
        since = db.scalar(select(func.min(JobRun.started_at)).where(JobRun.job == job))
        missed: list[datetime] = []
        if since is not None:
            starts = sorted(db.scalars(
                select(JobRun.started_at).where(JobRun.job == job, JobRun.started_at >= window_start)
            ).all())
            if cadence.kind == "interval":
                anchor = db.scalar(select(func.max(JobRun.started_at)).where(JobRun.job == job, JobRun.started_at < window_start))
                missed = _interval_missed(anchor, starts, window_start, now, cadence)
            else:
                missed = _grid_missed(starts, since, window_start, now, cadence)
        out.append(JobStatus(job, cadence, last, since, missed))
    return out
