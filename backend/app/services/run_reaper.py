"""Reap scan runs that will never finish (planning#163).

Nothing previously moved a stale PENDING/RUNNING `scan_runs` row to FAILED, so
every crash mode wedged a run permanently — and a wedged RUNNING row is
indistinguishable in the UI from a scan still in progress. That is the same
"failure becomes a reassuring state" family as planning#160.

Two rules, because two different things strand a run:

1. **Process death** (`reap_at_startup`). Scans only ever execute in *this*
   process — every caller of `scan_executor.launch` is either a FastAPI
   BackgroundTask or an APScheduler job, and the container runs a single
   uvicorn worker (`Dockerfile`: `uvicorn app.main:app`, no `--workers`). So at
   startup, any row still PENDING or RUNNING belongs to a process that no
   longer exists and is stranded by definition — no timeout heuristic needed.

   This is the one assumption in this module: if Constellus ever runs more than
   one backend process, this sweep would reap a live sibling's run and must be
   gated on a process/host lease instead.

2. **Thread death with the process alive** (`reap_stale`). `_fail` can itself
   fail, or the executor thread can die without reaching any handler. The
   process keeps running, so rule 1 never fires. Only age can catch these, so
   the timeouts are deliberately generous — a false reap of a live scan is
   worse than a wedged row surviving another hour.
"""

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models.scan import ScanRun, ScanStatus

log = logging.getLogger(__name__)

# Generous on purpose — see rule 2 above. A chunked scan with batch delays over
# a large estate is legitimately long; reaping a live run is the worse error.
RUNNING_TIMEOUT = timedelta(hours=24)
# A run goes PENDING -> RUNNING in the first statements of `_run`, so a row
# still PENDING hours later never launched at all.
PENDING_TIMEOUT = timedelta(hours=6)

_UNFINISHED = (ScanStatus.PENDING, ScanStatus.RUNNING)


def _reap(db: Session, runs: list[ScanRun], reason: str, now: datetime) -> int:
    if not runs:
        return 0
    for run in runs:
        previous_status = run.status
        run.status = ScanStatus.FAILED
        run.completed_at = now
        run.error = f"{run.error}\n{reason}" if run.error else reason
        log.warning(
            "Reaping stranded scan run %s (was %s): %s",
            run.id, previous_status, reason,
        )
    db.commit()
    return len(runs)


def reap_at_startup(db: Session, now: datetime | None = None) -> int:
    """Fail every unfinished run — see rule 1. Call once, at startup only."""
    now = now or datetime.now(timezone.utc)
    runs = db.query(ScanRun).filter(ScanRun.status.in_(_UNFINISHED)).all()
    return _reap(
        db, runs,
        "Backend restarted while this run was still unfinished; "
        "the process executing it no longer exists (planning#163).",
        now,
    )


def reap_stale(db: Session, now: datetime | None = None) -> int:
    """Fail unfinished runs older than their timeout — see rule 2."""
    now = now or datetime.now(timezone.utc)

    # RUNNING: age from started_at, which `_run` always sets on the
    # PENDING -> RUNNING transition. Fall back to created_at if it is somehow
    # NULL so a malformed row can still be reaped rather than living forever.
    running = [
        r for r in db.query(ScanRun).filter(ScanRun.status == ScanStatus.RUNNING).all()
        if (r.started_at or r.created_at)
        and now - (r.started_at or r.created_at) > RUNNING_TIMEOUT
    ]
    n = _reap(
        db, running,
        f"Run exceeded {RUNNING_TIMEOUT} in RUNNING without completing; "
        "presumed stranded (planning#163).",
        now,
    )

    pending = [
        r for r in db.query(ScanRun).filter(ScanRun.status == ScanStatus.PENDING).all()
        if r.created_at and now - r.created_at > PENDING_TIMEOUT
    ]
    n += _reap(
        db, pending,
        f"Run sat PENDING for more than {PENDING_TIMEOUT} without starting; "
        "presumed never launched (planning#163).",
        now,
    )
    return n


# ── EDGAR ingest runs (planning#219) ────────────────────────────────────────
#
# Same two rules as scan runs, for the same reasons: an ingest is a FastAPI
# BackgroundTask in this process, so at startup every unfinished row is
# stranded; and `_mark_run` is best-effort, so a live process can still leave
# one `running`. Here it matters more than for scans — an unfinished row holds
# `uq_entity_ingest_runs_active_cik` and blocks every re-ingest of that CIK.
#
# An ingest is minutes (one submissions fetch plus a few documents per 10-K
# under the SEC's rate limit), never hours, so the age limits are far tighter
# than scans' and still generous.
INGEST_RUNNING_TIMEOUT = timedelta(hours=2)
INGEST_QUEUED_TIMEOUT = timedelta(hours=1)


def _reap_ingest_runs(db: Session, runs: list, reason: str, now: datetime) -> int:
    if not runs:
        return 0
    for run in runs:
        log.warning("Reaping stranded EDGAR ingest run %s (was %s): %s", run.id, run.status, reason)
        run.status = "failed"
        run.started_at = run.started_at or now
        run.finished_at = now
        run.error = reason
    db.commit()
    return len(runs)


def reap_ingest_runs_at_startup(db: Session, now: datetime | None = None) -> int:
    """Fail every unfinished ingest run. Call once, at startup only."""
    from app.models.entity_ingest_run import INGEST_RUN_ACTIVE, EntityIngestRun

    now = now or datetime.now(timezone.utc)
    runs = db.query(EntityIngestRun).filter(EntityIngestRun.status.in_(INGEST_RUN_ACTIVE)).all()
    return _reap_ingest_runs(
        db, runs,
        "Backend restarted while this ingest was still unfinished; "
        "the process executing it no longer exists.",
        now,
    )


def reap_stale_ingest_runs(db: Session, now: datetime | None = None) -> int:
    """Fail ingest runs older than their timeout."""
    from app.models.entity_ingest_run import EntityIngestRun

    now = now or datetime.now(timezone.utc)
    running = [
        r for r in db.query(EntityIngestRun).filter(EntityIngestRun.status == "running").all()
        if now - (r.started_at or r.created_at) > INGEST_RUNNING_TIMEOUT
    ]
    n = _reap_ingest_runs(
        db, running, f"Ingest exceeded {INGEST_RUNNING_TIMEOUT} running without completing; presumed stranded.", now
    )
    queued = [
        r for r in db.query(EntityIngestRun).filter(EntityIngestRun.status == "queued").all()
        if now - r.created_at > INGEST_QUEUED_TIMEOUT
    ]
    n += _reap_ingest_runs(
        db, queued, f"Ingest sat queued for more than {INGEST_QUEUED_TIMEOUT} without starting; presumed never launched.", now
    )
    return n
