"""Coverage for planning#204 — surfacing `probe_class` past the projector.

`probe_class` (`no_probe` / `name_only` / `direct_addressable`) was computed
by `app.services.projector` onto `asset_state.attributes` and read by
`probe_authorisation._probe_class_cap`, then went nowhere: 0 hits in
`app/api/`, 0 in `frontend/src`. An asset the gate declined to authorise for
port scanning was visually identical to one that was scanned and had
nothing open — opposite conclusions for a security tool.

Three things are pinned here:

  1. The serializer surface (`app.api.assets._serialize_asset`) — direct
     row-seeding style, same as `test_hygiene_serializer.py` (the closest
     template: another top-level, non-bridged field landing next to
     `surface`/`hygiene_score`).
  2. The gate surface (`GateResult.port_scan_unauthorised_ids`,
     `app.services.probe_authorisation`) — same direct-seeding style as
     `test_probe_authorisation.py`. Put HERE rather than appended to that
     file: this issue's tests are about one new field threading through
     three layers, and keeping them together makes the planning#204 diff
     reviewable as one unit rather than scattered across the module that
     already has 1300+ lines of unrelated gate coverage.
  3. The executor surface (`ScanRun.port_scan_unauthorised_count`) — driven
     through the real (stubbed-connector) pipeline, `scan_executor._run`,
     the same harness shape as `test_swept_host_port_retirement.py`'s
     `_run_pipeline_with_stub`, one level up (`_run` rather than
     `_run_pipeline`) because the field under test is stamped in `_run`,
     after the chunk loop, not inside `_run_pipeline` itself.

## The wording constraint every test here assumes but does not itself check

The gate's mode is `log_only` today: it denies ON PAPER and the connector
scans anyway. Nothing built for this issue — code, comment, or UI string —
may assert that a probe did not HAPPEN, only that it was not AUTHORISED.
"Not authorised for port scanning" is true in both `log_only` and
`enforce`; "not scanned" is false today and only becomes true after the
planning#148 `enforce` flip. This file doesn't render any of the frontend
strings (no test framework there — see the issue body), but every backend
comment that touches this surface repeats the constraint on purpose, so a
future reader editing wording near this code trips over it before shipping
the wrong verb.

## Addresses

Every row here is an `ip_address` asset, so every value is drawn from
`_docaddr.alloc()` — a real documentation address, without replacement.
An earlier draft used opaque non-address strings, which the `_docaddr`
guard permits (they are not addresses, so no rule fires) but which put a
value that is not an address into a column typed as one — the same class
of defect planning#174 is open about. `alloc()` costs nothing here: the
loose-address pool is 315 wide, and only `alloc_cidr()`'s ten /29s are
scarce.

Run with:  python -m app.tests.test_probe_class_surface
       or: pytest app/tests/test_probe_class_surface.py
"""

import uuid
from datetime import datetime, timezone

from app.api.assets import _serialize_asset, load_bridge_sources
from app.connectors.base import DiscoveredAsset, PhaseResult
from app.core.database import SessionLocal
from app.models.app_settings import AppSetting
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.authorisation_decision import AuthorisationDecision
from app.models.scan import ScanRun, ScanStatus
from app.services import app_settings as settings_svc
from app.services import connector_config
from app.services import probe_authorisation as pa
from app.services import scan_executor
from app.tests import _decision_log
from app.tests._docaddr import alloc as alloc_ip

_PROBE_MODE_KEY = "probe_authorisation_mode"


# ── helpers ──────────────────────────────────────────────────────────────

def _mk_asset(db, value: str) -> AssetCanonical:
    now = datetime.now(timezone.utc)
    row = AssetCanonical(
        id=uuid.uuid4(), asset_type="ip_address", value=value,
        first_seen_at=now, last_seen_at=now,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _set_state(db, asset_id: uuid.UUID, attributes: dict) -> None:
    db.add(AssetState(asset_canonical_id=asset_id, attributes=attributes, projected_at=datetime.now(timezone.utc)))
    db.commit()


def _serialize(db, row: AssetCanonical) -> dict:
    bridge_sources = load_bridge_sources(db, [row.id])
    return _serialize_asset(row, None, bridge_sources.get(row.id))


def _cleanup(values: list[str]) -> None:
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


# ── 1-3. serializer: probe_class reflects the projected state ──────────────

def test_probe_class_reflects_each_projected_value():
    for probe_class in ("no_probe", "name_only", "direct_addressable"):
        value = alloc_ip()
        db = SessionLocal()
        try:
            asset = _mk_asset(db, value)
            _set_state(db, asset.id, {"probe_class": probe_class})

            result = _serialize(db, asset)

            assert result["probe_class"] == probe_class, result
        finally:
            db.close()
            _cleanup([value])


def test_probe_class_is_null_with_no_state_row():
    value = alloc_ip()
    db = SessionLocal()
    try:
        asset = _mk_asset(db, value)
        # deliberately no AssetState row

        result = _serialize(db, asset)

        assert "probe_class" in result and result["probe_class"] is None, result
    finally:
        db.close()
        _cleanup([value])


def test_probe_class_is_null_when_state_row_has_no_probe_class_key():
    value = alloc_ip()
    db = SessionLocal()
    try:
        asset = _mk_asset(db, value)
        _set_state(db, asset.id, {})  # projected, but not this attribute

        result = _serialize(db, asset)

        assert result["probe_class"] is None, result
    finally:
        db.close()
        _cleanup([value])


# ── 4. asset_metadata bridge-shape guard ────────────────────────────────────

def test_asset_metadata_does_not_gain_a_probe_class_key():
    """The bridged `asset_metadata` dict is a byte-compatible bridge to the
    dropped `metadata` column (metadata_bridge.py), pinned against a seeded
    payload by test_serializer_bridge.py — `probe_class` must stay top-level
    only, never folded in here, even when the asset has a real state row.
    This is the assertion that survives mutation: a naive implementation
    that wrote `probe_class` into `metadata` before returning the dict
    would still pass tests 1-3 above (the top-level key would just be a
    copy) but fail here."""
    value = alloc_ip()
    db = SessionLocal()
    try:
        asset = _mk_asset(db, value)
        _set_state(db, asset.id, {"probe_class": "direct_addressable"})

        result = _serialize(db, asset)

        assert "probe_class" not in result["asset_metadata"], result["asset_metadata"]
    finally:
        db.close()
        _cleanup([value])


# ── 5. gate: port_scan_unauthorised_ids is derived from the cap ────────────

class _NaabuStub:
    """`observer = "naabu"` reuses the real seeded observer row (addressing
    == "ip") so the connector-declaration check resolves it — same trick as
    test_probe_authorisation.py's `_IP_CONNECTOR`, reproduced locally per
    this file's self-contained-helpers convention rather than importing a
    private name out of that module."""
    observer = "naabu"

    def port_scan(self, assets, config):  # pragma: no cover — gate never calls this
        raise AssertionError("the gate must never call a connector's port_scan itself")


def test_gate_reports_port_scan_unauthorised_ids_derived_from_the_cap():
    """`port_scan_unauthorised_ids` must contain exactly the assets whose
    `probe_class` cap did not license `ip` addressing — `no_probe` (empty
    modes) and `name_only` ({"name", "ip_handshake"}, no "ip"), but NOT
    `direct_addressable` ({"ip", "name", "ip_handshake"}).

    MUTATION-PROVED (manually, not encoded here — see the PR report): this
    test fails if the implementation is changed from
    `"ip" not in caps[1].modes` to `not caps[1].allowed`, which would drop
    `name_only` from the set (name_only IS allowed — it just doesn't allow
    `ip`). Verified by making that exact edit, running this test, watching
    it fail on the name_only id being absent, and reverting.
    """
    values = {
        "no_probe": alloc_ip(),
        "name_only": alloc_ip(),
        "direct_addressable": alloc_ip(),
    }
    db = SessionLocal()
    try:
        assets_by_class = {}
        for probe_class, value in values.items():
            row = _mk_asset(db, value)
            _set_state(db, row.id, {"probe_class": probe_class})
            assets_by_class[probe_class] = row

        gate = pa.authorise_probes(
            db, connector_id="test-naabu", connector=_NaabuStub(),
            assets=[DiscoveredAsset(asset_type="ip_address", value=v) for v in values.values()],
            scope={},
        )

        expected = {assets_by_class["no_probe"].id, assets_by_class["name_only"].id}
        assert gate.port_scan_unauthorised_ids == expected, gate.port_scan_unauthorised_ids
        assert assets_by_class["direct_addressable"].id not in gate.port_scan_unauthorised_ids
    finally:
        db.close()
        _cleanup(list(values.values()))


# ── 6. executor: the count is stamped by a real pipeline run ───────────────

class _CapturingNaabuStub:
    """Phase 1.5 stand-in — same shape as
    test_swept_host_port_retirement.py's `_CaptureConnector`. `port_scan`
    finds nothing (empty `PhaseResult()`): the point of this test is that
    the GATE denied the asset before the connector was ever asked, not
    what the connector itself reports."""
    observer = "naabu"

    def __init__(self):
        self.calls: list[tuple[list, dict]] = []

    def port_scan(self, assets, config):
        self.calls.append((list(assets), config))
        return PhaseResult()


def _set_probe_mode(db, value: str | None) -> None:
    if value is None:
        db.query(AppSetting).filter(AppSetting.key == _PROBE_MODE_KEY).delete()
        db.commit()
    else:
        settings_svc.set_value(db, _PROBE_MODE_KEY, value)


def test_run_stamps_port_scan_unauthorised_count_from_a_real_pipeline_run():
    """Drives `scan_executor._run` (not `_run_pipeline` — the stamping line
    under test lives in `_run`, after the chunk loop) against one seeded
    `name_only` IP asset, with `skip_discovery=True` so Phase 1 seeds
    `all_assets` straight from `scope["ip_ranges"]` without a real discovery
    connector.

    VACUOUSNESS GUARD (planning#204's own warning, learned from planning#205
    where an e2e test's precondition never fired and it passed with the fix
    removed): this asserts the count is NON-ZERO, i.e. that the gate
    actually evaluated the seeded asset and denied it `ip` — a test that
    only checked `== 0` on an empty run would prove nothing. The stamping
    line itself was mutation-tested manually (removed, this test re-run and
    confirmed to fail, restored) — see the PR report, not encoded here since
    there is no clean way to mutate one line of `scan_executor.py` from
    inside a test without monkeypatching the whole function.
    """
    ip = alloc_ip()
    db = SessionLocal()
    scan_run_id = uuid.uuid4()
    asset_id: uuid.UUID | None = None
    naabu_row = connector_config.get_one(db, "naabu")
    had_naabu_row = naabu_row is not None
    original_enabled = naabu_row.enabled if naabu_row else None
    original_probe_mode = settings_svc.get(db, _PROBE_MODE_KEY)
    try:
        asset = AssetCanonical(asset_type="ip_address", value=ip)
        db.add(asset)
        db.commit()
        db.refresh(asset)
        asset_id = asset.id
        _set_state(db, asset_id, {"probe_class": "name_only"})

        scope = {"domains": [], "ip_ranges": [ip]}
        db.add(ScanRun(
            id=scan_run_id, status=ScanStatus.PENDING, scope=scope,
            options={"skip_discovery": True},
        ))
        db.commit()

        connector_config.set_enabled(db, "naabu", True)
        _set_probe_mode(db, "log_only")

        stub = _CapturingNaabuStub()
        scan_executor._run(db, scan_run_id, scope, {"naabu": stub})

        assert stub.calls, "Phase 1.5 never ran — check naabu enablement/skip_discovery wiring"

        db.expire_all()
        run = db.get(ScanRun, scan_run_id)
        assert run.status == ScanStatus.COMPLETED, run.status
        assert run.port_scan_unauthorised_count > 0, (
            "expected the gate to deny `ip` addressing to the seeded "
            "name_only asset and the executor to stamp a non-zero count; "
            f"got {run.port_scan_unauthorised_count}"
        )
    finally:
        if had_naabu_row:
            connector_config.set_enabled(db, "naabu", original_enabled)
        _set_probe_mode(db, original_probe_mode)
        # Decision rows first, keyed by scan_run_id (real run id, minted
        # above) — same ordering test_swept_host_port_retirement.py uses,
        # for the same reason: asset_canonical_id is ON DELETE SET NULL, so
        # deleting the asset first would silently orphan these instead of
        # erroring.
        _decision_log.cleanup_for_run(scan_run_id)
        db.query(ScanRun).filter(ScanRun.id == scan_run_id).delete()
        if asset_id is not None:
            db.query(AssetState).filter(AssetState.asset_canonical_id == asset_id).delete()
            db.query(AssetCanonical).filter(AssetCanonical.id == asset_id).delete()
        db.commit()
        db.close()


def _run():
    tests = [
        test_probe_class_reflects_each_projected_value,
        test_probe_class_is_null_with_no_state_row,
        test_probe_class_is_null_when_state_row_has_no_probe_class_key,
        test_asset_metadata_does_not_gain_a_probe_class_key,
        test_gate_reports_port_scan_unauthorised_ids_derived_from_the_cap,
        test_run_stamps_port_scan_unauthorised_count_from_a_real_pipeline_run,
    ]
    for fn in tests:
        fn()
        print(f"ok  {fn.__name__}")
    print("all passed")


if __name__ == "__main__":
    _run()
