"""Tests for planning#148 step 2 — Phase 3 (nuclei) routed through the
probe-authorisation gate.

Background: `app.services.probe_authorisation.authorise_probes` was, until
this slice, the choke point for every active-probe path EXCEPT Phase 3
scanning. Phase 3 filtered its own target list with an interim
`is_scan_authorised(db, t, auth_mode)` call — a second, independently
maintained scope mechanism deciding whether to emit active traffic, which
is exactly the duplication `probe_authorisation`'s own module docstring
exists to forbid. This slice deletes that interim filter and routes Phase 3
through the gate exactly like Phase 1.5 already does, now that `nuclei` has
both a seeded `observers` row (migration 0049) and an `observer` class
attribute on `NucleiConnector` — the two things whose absence would have
made a deny-undeclared gate refuse nuclei outright and kill Phase 3
scanning entirely.

Dev-DB caveat (same as test_cidr_sweep.py): there is no dedicated test
database. Every test below snapshots and restores the shared rows it
touches (the `nuclei` connector_config row's `enabled` flag, the
`probe_authorisation_mode` app setting) in a `finally`, and deletes any
`AuthorisationDecision` / `AssetCanonical` / `AssetState` rows it creates.
`_run_pipeline` is driven directly with `skip_discovery=True` and assets
seeded purely from `ip_ranges`, so no DNS lookup or network I/O happens.

Address hygiene: every address below is RFC-5737 documentation space
(203.0.113.0/24) — this repo's pre-commit hook rejects a real routable
address in any tracked file.

Run with:  python -m app.tests.test_phase3_gate
       or: pytest app/tests/test_phase3_gate.py
"""

import uuid

from app.connectors.base import PhaseResult, ScanningConnector
from app.connectors.nuclei import NucleiConnector
from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.authorisation_decision import AuthorisationDecision
from app.services import app_settings as settings_svc
from app.services import connector_config
from app.services import probe_authorisation
from app.services import scan_executor
from app.tests import _decision_log


# ── shared stub / harness plumbing (mirrors test_cidr_sweep.py) ────────────

class _CaptureScanner(ScanningConnector):
    """Records the targets Phase 3 hands it. `observer` is settable so the
    undeclared case can be exercised with the same class."""
    name = "capture"

    def __init__(self, observer_name="nuclei"):
        self.calls = []
        if observer_name is not None:
            self.observer = observer_name

    def get_config_schema(self):
        return {}

    def is_configured(self):
        return True

    def scan(self, targets, config):
        self.calls.append(list(targets))
        return PhaseResult()


def _set_probe_mode(db, value):
    from app.models.app_settings import AppSetting
    if value is None:
        db.query(AppSetting).filter(AppSetting.key == "probe_authorisation_mode").delete()
        db.commit()
    else:
        settings_svc.set_value(db, "probe_authorisation_mode", value)


def _cleanup(values: list[str]) -> None:
    """Mirrors test_probe_authorisation.py's `_cleanup` — removes any
    AssetCanonical/AssetState/AuthorisationDecision rows keyed by these
    RFC-5737 values, whether left over from a prior run or created here."""
    db = SessionLocal()
    try:
        rows = db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).all()
        ids = [r.id for r in rows]
        if ids:
            db.query(AuthorisationDecision).filter(AuthorisationDecision.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
            db.query(AssetState).filter(AssetState.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _cleanup_decisions_for_run(scan_run_id: uuid.UUID) -> None:
    """Thin alias over the shared helper. This file had its own copy of
    this delete until planning#189; `test_cidr_sweep.py` needed the same
    one and did not have it, and two more files needed a different cleanup
    handle entirely. One implementation, in `_decision_log`, so the next
    file that needs it finds it instead of reinventing it — or omitting it.
    """
    _decision_log.cleanup_for_run(scan_run_id)


def _run_pipeline_with_stub(chunk_scope: dict, stub, mode: str) -> uuid.UUID:
    """Drive `_run_pipeline` directly against a throwaway chunk with a
    stub registry of exactly one connector (`nuclei`'s slot), so no real
    scanner-worker call happens. Returns the scan_run_id used, so the
    caller can query/clean up the decision rows it produced."""
    db = SessionLocal()
    scan_run_id = uuid.uuid4()
    nuclei_row = connector_config.get_one(db, "nuclei")
    had_row = nuclei_row is not None
    original_enabled = nuclei_row.enabled if nuclei_row else None
    original_mode = settings_svc.get(db, "probe_authorisation_mode")
    try:
        connector_config.set_enabled(db, "nuclei", True)
        _set_probe_mode(db, mode)
        scan_executor._run_pipeline(
            db, scan_run_id, chunk_scope, {}, "disabled", "standard", True,
            {"nuclei": stub}, [], frozenset(),
        )
    finally:
        if had_row:
            connector_config.set_enabled(db, "nuclei", original_enabled)
        _set_probe_mode(db, original_mode)
        db.close()
    return scan_run_id


# ── 1. the blocker this whole step existed to clear ─────────────────────────

def test_nuclei_declares_a_resolvable_addressing_capable_observer():
    """The direct guard against the blocker planning#148 step 2 closed.

    If this fails, `NucleiConnector` has no resolvable `observer` (either
    the migration-0049 `observers` row is missing, or the class attribute
    is), and Phase 3 emits nothing at all, in either gate mode — the
    always-enforced connector-declaration check denies it outright.
    """
    db = SessionLocal()
    try:
        row, denial_rule = probe_authorisation._resolve_connector_observer(db, NucleiConnector())
        assert denial_rule is None, f"nuclei observer denied: {denial_rule!r}"
        assert row.name == "nuclei"
        assert row.addressing == "name"
        assert row.kind == "scan"
        assert row.emits_traffic_to_target is True
    finally:
        db.close()


# ── 2. every allowed probe writes a reconstructible decision row ───────────

def test_phase3_writes_an_authorisation_decision_row():
    """The "every allowed probe writes a decision row that reconstructs why
    it was permitted" criterion, now true for Phase 3 too."""
    ip = "203.0.113.210"
    _cleanup([ip])
    stub = _CaptureScanner()
    scan_run_id = None
    try:
        scan_run_id = _run_pipeline_with_stub(
            {"domains": [], "ip_ranges": [ip]}, stub, "log_only",
        )
        db = SessionLocal()
        try:
            rows = (
                db.query(AuthorisationDecision)
                .filter(AuthorisationDecision.evidence_snapshot["scan_run_id"].astext == str(scan_run_id))
                .all()
            )
            assert rows, "no authorisation_decisions row written for this scan_run_id"
            nuclei_rows = [r for r in rows if r.evidence_snapshot.get("connector_id") == "nuclei"]
            assert nuclei_rows, (
                f"no decision row attributes to nuclei: {[r.evidence_snapshot for r in rows]!r}"
            )
            # The load-bearing half of the rollout contract, and the reason
            # this assertion is not redundant with test 3. `log_only` must
            # record the REAL computed verdict -- what WOULD happen under
            # `enforce` -- not a rubber stamp, even though it blocks nothing.
            # This IP is never persisted, so every cap chain ends in a denial;
            # a row saying allowed=True here would mean the log is recording
            # the mode's no-op rather than the decision. planning#148's one
            # remaining step is flipping the mode based on reading exactly
            # these rows, which an always-True log would make impossible.
            assert any(r.allowed is False for r in nuclei_rows), (
                "log_only wrote no denial for an unresolved asset -- the decision "
                "log is recording the no-op, not the real verdict: "
                f"{[(r.allowed, r.rule_fired) for r in nuclei_rows]!r}"
            )
            assert all(r.evidence_snapshot.get("gate_mode") == "log_only" for r in nuclei_rows), (
                f"gate_mode not stamped on the decision rows: {[r.evidence_snapshot.get('gate_mode') for r in nuclei_rows]!r}"
            )
        finally:
            db.close()
        assert stub.calls, "log_only recorded a denial but must still have run the scan"
    finally:
        if scan_run_id is not None:
            _cleanup_decisions_for_run(scan_run_id)
        _cleanup([ip])


# ── 3/4. log_only records but never narrows; enforce narrows for real ──────

_DENIED_IP = "203.0.113.211"  # never persisted -> unresolved_asset under enforce


def test_phase3_log_only_does_not_narrow_the_target_list():
    """Rollout contract: log-only records verdicts, it never blocks — even
    for an asset the gate would deny under enforce (unresolved/unprojected)."""
    _cleanup([_DENIED_IP])
    stub = _CaptureScanner()
    scan_run_id = None
    try:
        scan_run_id = _run_pipeline_with_stub(
            {"domains": [], "ip_ranges": [_DENIED_IP]}, stub, "log_only",
        )
        assert stub.calls, "log_only must still call scan() — it never narrows"
        expected = scan_executor._extract_scan_targets(
            [scan_executor.DiscoveredAsset(asset_type="ip_address", value=_DENIED_IP)]
        )
        assert stub.calls[0] == expected, (
            f"log_only target list diverged from _extract_scan_targets: {stub.calls[0]!r} != {expected!r}"
        )
    finally:
        if scan_run_id is not None:
            _cleanup_decisions_for_run(scan_run_id)
        _cleanup([_DENIED_IP])


def test_phase3_enforce_narrows_to_the_gate_verdict():
    """Paired with the log_only test above: together they are the
    behavioural proof that the interim `is_scan_authorised` filter was
    REPLACED by the gate, not merely deleted. Under `enforce` the same
    unresolved asset must never reach `connector.scan`."""
    _cleanup([_DENIED_IP])
    stub = _CaptureScanner()
    scan_run_id = None
    try:
        scan_run_id = _run_pipeline_with_stub(
            {"domains": [], "ip_ranges": [_DENIED_IP]}, stub, "enforce",
        )
        assert stub.calls == [], f"enforce must deny the unresolved asset, got: {stub.calls!r}"
    finally:
        if scan_run_id is not None:
            _cleanup_decisions_for_run(scan_run_id)
        _cleanup([_DENIED_IP])


# ── 5. the connector-declaration check is always-enforced ──────────────────

def test_phase3_undeclared_connector_is_denied_in_log_only_mode():
    """The duck-typed hole closed for Phase 3: a connector with no
    resolvable `observer` is denied outright, and that denial is NOT
    subject to the log-only rollout — unlike the scope/probe_class caps
    exercised in tests 3/4 above, this one fires in every mode."""
    ip = "203.0.113.212"
    _cleanup([ip])
    stub = _CaptureScanner(observer_name=None)
    scan_run_id = None
    try:
        scan_run_id = _run_pipeline_with_stub(
            {"domains": [], "ip_ranges": [ip]}, stub, "log_only",
        )
        assert stub.calls == [], f"undeclared connector must be denied even in log_only: {stub.calls!r}"
    finally:
        if scan_run_id is not None:
            _cleanup_decisions_for_run(scan_run_id)
        _cleanup([ip])


if __name__ == "__main__":
    _tests = [
        test_nuclei_declares_a_resolvable_addressing_capable_observer,
        test_phase3_writes_an_authorisation_decision_row,
        test_phase3_log_only_does_not_narrow_the_target_list,
        test_phase3_enforce_narrows_to_the_gate_verdict,
        test_phase3_undeclared_connector_is_denied_in_log_only_mode,
    ]
    for _t in _tests:
        _t()
        print(f"ok {_t.__name__}")
    print(f"\n{len(_tests)} passed")
