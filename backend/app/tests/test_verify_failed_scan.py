"""A failed verification scan must never resolve a finding (planning#162 item 4).

`POST /findings/{id}/verify` launches a recheck scan and then resolves the
finding if it was not re-observed. Before this, it did that without checking
whether the scan had actually run: a verification scan that crashed produced
exactly the same evidence as one that found nothing — no new observation —
and the finding was marked RESOLVED. An operational failure became a
reassuring product state (the planning#160 shape).

## Why the obvious test would not have caught it

`scan_executor.launch` catches its own exceptions and calls `_fail()`
internally, so it **returns `None` on success and `None` on catastrophe**.
There is no exception for `_verify_and_resolve` to see and nothing for a
`try/except` to catch. These tests therefore do not mock the status check —
they force a REAL failure by making the executor's `_run` raise, let
`launch`'s own handler mark the run FAILED, and then assert on the finding.
That is the actual production failure path, end to end.

## Dev-DB hygiene

The suite runs against the dev database. Every row here is created with a
unique per-run asset value and deleted by id in `finally`; nothing is
deleted table-wide. `authorisation_decisions` is untouched — these tests
never reach `probe_authorisation` because `_run` is replaced before it can.

`scan_executor` is raw-assignment monkeypatched here and is registered in
`conftest.py`'s `_GUARDED_MODULES`, so the replacement is restored around
each test even if one of them dies mid-way.

Run with:  pytest app/tests/test_verify_failed_scan.py
"""

import uuid
from datetime import datetime, timedelta, timezone

from app.api.findings import _verify_and_resolve
from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.finding_canonical import FindingCanonical
from app.models.scan import ScanKind, ScanRun, ScanStatus
from app.services import scan_executor


def _mk_fixture(db, marker: str):
    """One asset + one OPEN finding + one PENDING recheck run."""
    now = datetime.now(timezone.utc)
    asset = AssetCanonical(
        id=uuid.uuid4(), asset_type="ip_address", value=marker,
        first_seen_at=now, last_seen_at=now, ignored=False, tags=[],
    )
    db.add(asset)
    finding = FindingCanonical(
        id=uuid.uuid4(), asset_canonical_id=asset.id, finding_type="cve",
        source="test", fingerprint=f"fp-{marker}", severity="high",
        title=f"verify-test {marker}", state="open", category="vulnerability",
        # Deliberately stale: "not re-observed by this scan" is true, which is
        # the condition that used to be sufficient on its own to resolve it.
        first_seen_at=now - timedelta(days=2), last_seen_at=now - timedelta(days=2),
        detail={}, tags=[],
    )
    db.add(finding)
    run = ScanRun(
        id=uuid.uuid4(), name=f"Verify: {marker}", status=ScanStatus.PENDING.value,
        kind=ScanKind.RECHECK, scope={"domains": [], "ip_ranges": [marker]},
        options={"skip_discovery": True, "force_reverify": True},
    )
    db.add(run)
    db.commit()
    return asset, finding, run


def _cleanup(asset_id, run_id) -> None:
    db = SessionLocal()
    try:
        db.query(FindingCanonical).filter(
            FindingCanonical.asset_canonical_id == asset_id
        ).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.id == asset_id).delete(synchronize_session=False)
        db.query(ScanRun).filter(ScanRun.id == run_id).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _marker() -> str:
    # 198.51.100.0/24 is RFC 5737 TEST-NET-2 — never routable, never a real
    # asset, and the last octet keeps concurrent runs from colliding.
    return f"198.51.100.{uuid.uuid4().int % 250 + 1}"


def _exploding_run(*args, **kwargs):
    """Stand-in for a scan that dies inside the executor. `launch` catches
    this itself and calls `_fail`, which is exactly the point: the caller
    sees a perfectly normal return."""
    raise RuntimeError("simulated executor crash")


def _completing_run(db, scan_run_id, scope, registry):
    """Stand-in for a scan that ran to completion and observed nothing."""
    run = db.get(ScanRun, scan_run_id)
    run.status = ScanStatus.COMPLETED.value
    run.completed_at = datetime.now(timezone.utc)
    db.commit()


def _reload(finding_id, run_id):
    db = SessionLocal()
    try:
        f = db.get(FindingCanonical, finding_id)
        r = db.get(ScanRun, run_id)
        return (f.state, dict(f.detail or {}), getattr(r.status, "value", r.status))
    finally:
        db.close()


# ── the defect ───────────────────────────────────────────────────────────────

def test_crashed_verification_scan_leaves_the_finding_open():
    marker = _marker()
    db = SessionLocal()
    asset, finding, run = _mk_fixture(db, marker)
    finding_id, run_id, asset_id = finding.id, run.id, asset.id
    started_at = datetime.now(timezone.utc)
    db.close()
    try:
        scan_executor._run = _exploding_run
        _verify_and_resolve(run_id, finding_id, started_at, {})

        state, detail, run_status = _reload(finding_id, run_id)
        assert run_status == ScanStatus.FAILED.value, (
            f"expected the executor's own handler to mark the run FAILED, got {run_status}"
        )
        assert state == "open", (
            "a crashed verification scan resolved the finding — absence of "
            f"evidence became evidence of absence (state={state})"
        )
        lv = detail.get("last_verification")
        assert lv and lv["outcome"] == "failed", f"no failure recorded on the finding: {detail}"
        assert lv["scan_run_status"] == ScanStatus.FAILED.value
        assert lv["scan_run_id"] == str(run_id)
        assert "simulated executor crash" in (lv.get("error") or ""), (
            f"the operator is told it failed but not why: {lv}"
        )
    finally:
        _cleanup(asset_id, run_id)


def test_cancelled_verification_scan_leaves_the_finding_open():
    """CANCELLED is not FAILED and is not COMPLETED. The gate is
    `== COMPLETED`, not `!= FAILED`, so a cancelled run cannot resolve
    anything either."""
    marker = _marker()
    db = SessionLocal()
    asset, finding, run = _mk_fixture(db, marker)
    finding_id, run_id, asset_id = finding.id, run.id, asset.id
    started_at = datetime.now(timezone.utc)
    db.close()
    try:
        def _cancelling_run(db_, scan_run_id, scope, registry):
            r = db_.get(ScanRun, scan_run_id)
            r.status = ScanStatus.CANCELLED.value
            db_.commit()

        scan_executor._run = _cancelling_run
        _verify_and_resolve(run_id, finding_id, started_at, {})

        state, detail, run_status = _reload(finding_id, run_id)
        assert run_status == ScanStatus.CANCELLED.value
        assert state == "open", f"a cancelled scan resolved the finding (state={state})"
        assert (detail.get("last_verification") or {}).get("outcome") == "failed"
    finally:
        _cleanup(asset_id, run_id)


def test_run_that_never_started_leaves_the_finding_open():
    """The PENDING case: the executor returned without touching the run at
    all. Nothing was scanned, so nothing may be concluded."""
    marker = _marker()
    db = SessionLocal()
    asset, finding, run = _mk_fixture(db, marker)
    finding_id, run_id, asset_id = finding.id, run.id, asset.id
    started_at = datetime.now(timezone.utc)
    db.close()
    try:
        scan_executor._run = lambda *a, **kw: None
        _verify_and_resolve(run_id, finding_id, started_at, {})

        state, detail, run_status = _reload(finding_id, run_id)
        assert run_status == ScanStatus.PENDING.value
        assert state == "open", f"a scan that never ran resolved the finding (state={state})"
        assert (detail.get("last_verification") or {}).get("outcome") == "failed"
    finally:
        _cleanup(asset_id, run_id)


# ── the behaviour that must survive the fix ──────────────────────────────────

def test_completed_scan_that_did_not_re_observe_still_resolves():
    """The feature itself. If this stops working, the gate is too tight."""
    marker = _marker()
    db = SessionLocal()
    asset, finding, run = _mk_fixture(db, marker)
    finding_id, run_id, asset_id = finding.id, run.id, asset.id
    started_at = datetime.now(timezone.utc)
    db.close()
    try:
        scan_executor._run = _completing_run
        _verify_and_resolve(run_id, finding_id, started_at, {})

        state, detail, run_status = _reload(finding_id, run_id)
        assert run_status == ScanStatus.COMPLETED.value
        assert state == "resolved", f"a completed, unobserved finding did not resolve (state={state})"
        assert (detail.get("last_verification") or {}).get("outcome") == "resolved"
    finally:
        _cleanup(asset_id, run_id)


def test_completed_scan_that_re_observed_the_finding_leaves_it_open():
    marker = _marker()
    db = SessionLocal()
    asset, finding, run = _mk_fixture(db, marker)
    finding_id, run_id, asset_id = finding.id, run.id, asset.id
    started_at = datetime.now(timezone.utc)
    db.close()
    try:
        def _observing_run(db_, scan_run_id, scope, registry):
            _completing_run(db_, scan_run_id, scope, registry)
            f = db_.get(FindingCanonical, finding_id)
            f.last_seen_at = datetime.now(timezone.utc)
            db_.commit()

        scan_executor._run = _observing_run
        _verify_and_resolve(run_id, finding_id, started_at, {})

        state, detail, _ = _reload(finding_id, run_id)
        assert state == "open", f"a re-observed finding was resolved (state={state})"
        assert (detail.get("last_verification") or {}).get("outcome") == "still_observed"
    finally:
        _cleanup(asset_id, run_id)
