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
