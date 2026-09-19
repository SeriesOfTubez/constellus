"""DB-driver coverage of the executor transaction-discipline fixes and the
stranded scan-run sweep (planning#163, steps 1-3).

The "Transaction ownership" convention (CLAUDE.md) exists because it was
never decided before, and the ambiguity was its own bug class: a handler
that logs-and-continues without rolling back leaves the session's
transaction aborted, so the *next* unrelated statement raises
`PendingRollbackError` — surfacing the failure far from its actual cause,
usually inside the handler meant to record it. Tests 1-3 below each prove
one leg of that convention in isolation:

  1. `scan_executor._fail` recovers a session whose transaction is already
     aborted (the regression this issue's step 1 fixes).
  2. `_record_post_scan_failure` actually lands the failure on
     `partial_failures` rather than swallowing it silently.
  3. A later step's `db.rollback()` does not discard an earlier step's
     already-committed work — the property that makes wrapping all 14
     post-scan handlers in `db.commit()`/`db.rollback()` safe at all.

Tests 4-5 cover `run_reaper` itself (step 3): the startup sweep (rule 1,
every unfinished run belongs to a dead process) and the age-based sweep
(rule 2, a wedged run in a still-alive process).

Requires a live DB connection.

Run with:  python -m app.tests.test_run_reaper
       or: pytest app/tests/test_run_reaper.py
"""

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from app.core.database import SessionLocal
from app.models.scan import ScanRun, ScanStatus
from app.services import run_reaper, scan_executor
from app.services.scan_executor import _record_post_scan_failure
from app.services.run_reaper import PENDING_TIMEOUT, RUNNING_TIMEOUT


def _mk_run(db, status: str = ScanStatus.PENDING, **kwargs) -> ScanRun:
    run = ScanRun(
        id=uuid.uuid4(),
        status=status,
        scope={},
        options={},
        **kwargs,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def _cleanup(db, *run_ids: uuid.UUID) -> None:
    db.rollback()
    for run_id in run_ids:
        db.query(ScanRun).filter(ScanRun.id == run_id).delete()
    db.commit()


# The suite runs against the real dev database (`constellus`), not a dedicated
# test DB — and both reaper entry points sweep the WHOLE scan_runs table by
# design. So tests 4 and 5 can reap rows they did not create: a scan genuinely
# in flight while the suite runs would be marked FAILED, and any exact-count
# assertion would fail depending on unrelated table state.
#
# This is the planning#170 lesson (tests must not depend on global table state)
# with a sharper edge, because here the test mutates real rows rather than just
# colliding with them. Both tests therefore snapshot every pre-existing
# unfinished run before creating their own and restore it afterwards, and
# assert on their OWN rows rather than on the sweep's total count. The
# per-row assertions on COMPLETED/FAILED/CANCELLED rows are what actually
# guard against over-reaping; the count never added anything the per-row
# checks don't already cover.

def _snapshot_foreign_unfinished(db) -> list[tuple]:
    return [
        (r.id, r.status, r.completed_at, r.error)
        for r in db.query(ScanRun).filter(ScanRun.status.in_(
            (ScanStatus.PENDING, ScanStatus.RUNNING)
        )).all()
    ]


def _restore_foreign_unfinished(db, snapshots: list[tuple]) -> None:
    db.rollback()
    for run_id, status, completed_at, error in snapshots:
        run = db.get(ScanRun, run_id)
        if run is not None:
            run.status = status
            run.completed_at = completed_at
            run.error = error
    db.commit()


# ── 1. _fail recovers a poisoned session (regression test for step 1) ──────

def test_fail_recovers_a_poisoned_session():
    db = SessionLocal()
    run = None
    try:
        run = _mk_run(db, status=ScanStatus.RUNNING)

        # Force the transaction into an aborted state, the same way a
        # mid-pipeline connector failure would.
        try:
            db.execute(text("SELECT 1/0"))
        except Exception:
            pass  # transaction is now aborted; deliberately not rolled back

        # Before the step-1 fix this raised PendingRollbackError instead of
        # ever reaching the run row.
        scan_executor._fail(db, run.id, "boom")

        db.rollback()
        reloaded = db.get(ScanRun, run.id)
        assert reloaded.status == ScanStatus.FAILED
        assert reloaded.error == "boom"
    finally:
        if run is not None:
            _cleanup(db, run.id)
        db.close()


# ── 2. post-scan failure is recorded, not swallowed ─────────────────────────

def test_record_post_scan_failure_appends_to_partial_failures():
    db = SessionLocal()
    run = None
    try:
        run = _mk_run(db, status=ScanStatus.RUNNING)

        db.rollback()  # the convention: callers roll back before recording
        _record_post_scan_failure(db, run, "Risk scoring", RuntimeError("boom"))

        db.refresh(run)
        assert len(run.partial_failures) == 1
        assert run.partial_failures[0].startswith("Risk scoring: "), run.partial_failures
    finally:
        if run is not None:
            _cleanup(db, run.id)
        db.close()


# ── 3. a step's rollback does not discard a previously-committed step ──────

def test_rollback_of_a_later_step_does_not_discard_an_earlier_committed_step():
    db = SessionLocal()
    run = None
    try:
        run = _mk_run(db, status=ScanStatus.RUNNING)

        # "Step A": writes and commits, exactly like the post-scan handlers
        # after this issue's fix.
        run.error = "step-a-wrote-this"
        db.commit()

        # "Step B": raises mid-write, then rolls back — must not touch what
        # step A already committed.
        try:
            run.finding_count = 1
            db.execute(text("SELECT 1/0"))
        except Exception:
            db.rollback()

        db.refresh(run)
        assert run.error == "step-a-wrote-this"
    finally:
        if run is not None:
            _cleanup(db, run.id)
        db.close()


# ── 4. reap_at_startup ──────────────────────────────────────────────────────

def test_reap_at_startup_fails_pending_and_running_but_leaves_finished_runs_alone():
    db = SessionLocal()
    ids: list[uuid.UUID] = []
    foreign = _snapshot_foreign_unfinished(db)
    try:
        pending = _mk_run(db, status=ScanStatus.PENDING)
        running = _mk_run(db, status=ScanStatus.RUNNING)
        completed = _mk_run(db, status=ScanStatus.COMPLETED)
        failed = _mk_run(db, status=ScanStatus.FAILED)
        cancelled = _mk_run(db, status=ScanStatus.CANCELLED)
        ids = [r.id for r in (pending, running, completed, failed, cancelled)]

        now = datetime.now(timezone.utc)
        n = run_reaper.reap_at_startup(db, now=now)
        # >= 2, not == 2: the sweep is table-wide and foreign unfinished rows
        # (restored below) legitimately count toward it. See the note above.
        assert n >= 2, f"expected at least our pending+running rows reaped, got {n}"

        db.refresh(pending)
        db.refresh(running)
        db.refresh(completed)
        db.refresh(failed)
        db.refresh(cancelled)

        assert pending.status == ScanStatus.FAILED
        assert pending.completed_at is not None
        assert running.status == ScanStatus.FAILED
        assert running.completed_at is not None

        assert completed.status == ScanStatus.COMPLETED
        assert failed.status == ScanStatus.FAILED and failed.completed_at is None
        assert cancelled.status == ScanStatus.CANCELLED
    finally:
        _cleanup(db, *ids)
        _restore_foreign_unfinished(db, foreign)
        db.close()


# ── 5. reap_stale ───────────────────────────────────────────────────────────

def test_reap_stale_fails_old_running_and_pending_but_not_a_fresh_running_run():
    db = SessionLocal()
    ids: list[uuid.UUID] = []
    foreign = _snapshot_foreign_unfinished(db)
    try:
        now = datetime.now(timezone.utc)

        old_running = _mk_run(
            db, status=ScanStatus.RUNNING,
            started_at=now - RUNNING_TIMEOUT - timedelta(minutes=1),
        )
        fresh_running = _mk_run(
            db, status=ScanStatus.RUNNING,
            started_at=now - timedelta(minutes=5),
        )
        old_pending = _mk_run(
            db, status=ScanStatus.PENDING,
            created_at=now - PENDING_TIMEOUT - timedelta(minutes=1),
        )
        ids = [r.id for r in (old_running, fresh_running, old_pending)]

        n = run_reaper.reap_stale(db, now=now)
        # >= 2 for the same reason as test 4; `fresh_running` below is the
        # assertion that actually proves the age filter doesn't over-reap.
        assert n >= 2, f"expected at least our two old rows reaped, got {n}"

        db.refresh(old_running)
        db.refresh(fresh_running)
        db.refresh(old_pending)

        assert old_running.status == ScanStatus.FAILED
        assert old_running.completed_at is not None
        assert old_pending.status == ScanStatus.FAILED
        assert old_pending.completed_at is not None

        assert fresh_running.status == ScanStatus.RUNNING
        assert fresh_running.completed_at is None
    finally:
        _cleanup(db, *ids)
        _restore_foreign_unfinished(db, foreign)
        db.close()


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
