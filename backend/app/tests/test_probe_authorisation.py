"""Unit coverage of the composed probe-authorisation gate (planning#148,
slice 1) — `app.services.probe_authorisation`.

Seeds `AssetCanonical` / `AssetState` rows directly via `SessionLocal` (not
through `write_assets`), same direct-seeding style as `test_projector.py` /
`test_claims_query.py` — the point of these tests is pinning behaviour at
the gate's own boundary, independent of the ingest path that feeds it.
Connectors are represented by a minimal `_StubConnector` rather than a real
`NaabuConnector`/`TlsxConnector` instance: the gate only ever reads
`.observer` off whatever object it's handed, so a stub is both sufficient
and avoids dragging in the scanner-worker HTTP dependency those real
connectors carry.

Three of `_scope_cap`/`_probe_class_cap`/`_posture_cap` are monkeypatched by
raw attribute assignment in `test_each_cap_independently_reduces_and_cannot_widen`
(this suite's established convention for module-level monkeypatching — see
`conftest.py`'s docstring) — `probe_authorisation` is registered in
`conftest._GUARDED_MODULES` so a mistake there can't leak into a later test
file the way `test_shared_infra_verifier.py` once did.

Run with:  python -m app.tests.test_probe_authorisation
       or: pytest app/tests/test_probe_authorisation.py

Requires a live DB connection with migration 0039 applied (observers seeded
— this suite reads the real `naabu`/`tlsx`/`dns_resolve` seed rows rather
than inventing fake ones, since the whole point is pinning behaviour
against the actual seeded addressing vocabulary).
"""

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

from app.connectors.base import DiscoveredAsset
from app.core.database import SessionLocal
from app.models.app_settings import AppSetting
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.authorisation_decision import AuthorisationDecision
from app.models.target import Target
from app.models.target_asset_link import TargetAssetLink
from app.services import app_settings
from app.services import probe_authorisation as pa
from app.tests import _decision_log

_MODE_KEY = "probe_authorisation_mode"


# ── helpers ──────────────────────────────────────────────────────────────

def _mk_ip_asset(db, value: str, parent_value: str | None = None) -> AssetCanonical:
    now = datetime.now(timezone.utc)
    row = AssetCanonical(
        id=uuid.uuid4(), asset_type="ip_address", value=value, parent_value=parent_value,
        first_seen_at=now, last_seen_at=now,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _set_state(db, asset_id: uuid.UUID, probe_class: str) -> None:
    """Create-or-update the one `asset_state` row for `asset_id` with the
    given `probe_class` — idempotent (a plain INSERT would collide on the
    primary key the second time the same asset needs a different
    probe_class within one test, e.g. the widen-check subtest below)."""
    existing = db.get(AssetState, asset_id)
    now = datetime.now(timezone.utc)
    if existing is None:
        db.add(AssetState(asset_canonical_id=asset_id, attributes={"probe_class": probe_class}, projected_at=now))
    else:
        existing.attributes = {"probe_class": probe_class}
        existing.projected_at = now
    db.commit()


def _set_mode(db, value: str | None) -> None:
    """Set the `probe_authorisation_mode` app_setting override, or delete
    the row entirely when `value is None` so `app_settings.get` falls back
    to `DEFAULTS["probe_authorisation_mode"]` ("log_only"). This setting is
    a single global row shared by the whole test process, so every test
    that touches it restores it to `None` (the "no override" state) in a
    `finally` block — leaving it set would silently change the gate mode
    for whatever test runs next."""
    if value is None:
        db.query(AppSetting).filter(AppSetting.key == _MODE_KEY).delete()
        db.commit()
    else:
        app_settings.set_value(db, _MODE_KEY, value)


def _da(value: str) -> DiscoveredAsset:
    return DiscoveredAsset(asset_type="ip_address", value=value)


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


def _mk_target(db, value: str, ma_pre_close: bool) -> Target:
    """planning#193 helper — a minimal `targets` row for linking to a
    canonical asset via `TargetAssetLink`, mirroring `_mk_ip_asset`'s
    minimal-fields style above. `type="domain"` is arbitrary; `_posture_cap`
    and `_resolve_ma_pre_close_ids` never read `.type`."""
    row = Target(id=uuid.uuid4(), type="domain", value=value, ma_pre_close=ma_pre_close)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _link(db, target_id: uuid.UUID, asset_canonical_id: uuid.UUID) -> None:
    db.add(TargetAssetLink(target_id=target_id, asset_canonical_id=asset_canonical_id))
    db.commit()


def _cleanup_targets(target_ids: list[uuid.UUID]) -> None:
    """Deletes `targets` rows by id, bounded exactly like `_cleanup` above.
    `target_asset_links` rows cascade-delete with their target
    (`ON DELETE CASCADE`, `target_asset_link.py`), so no separate link
    cleanup is needed — same reasoning `_cleanup` already relies on for
    `AssetCanonical`'s own cascades."""
    ids = [t for t in target_ids if t is not None]
    if not ids:
        return
    db = SessionLocal()
    try:
        db.query(Target).filter(Target.id.in_(ids)).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


class _StubConnector:
    """Minimal stand-in for a Phase 1.5 connector. The gate never calls
    `port_scan` itself (only `scan_executor` does, after the gate has
    already decided) — it only ever reads `.observer` off this object, so
    that's the only thing worth controlling per test. Passing
    `observer_name=None` omits the attribute entirely (simulating a
    connector that forgot to declare one), rather than setting it to
    `None`/`""` — `getattr(connector, "observer", None)` treats both the
    same way, but omitting it is the more honest simulation of the real
    defect this issue closes.
    """

    def __init__(self, observer_name: str | None):
        if observer_name is not None:
            self.observer = observer_name

    def port_scan(self, assets, config):  # pragma: no cover — gate never calls this
        raise AssertionError("the gate must never call a connector's port_scan itself")


# Real seeded observer names (migration 0039 OBSERVER_SEED) — see
# test_claims_schema.test_observers_seeded_with_20_rows_and_correct_addressing
# for the pinned addressing values these stubs rely on.
_IP_CONNECTOR = _StubConnector("naabu")  # addressing == "ip"
_NAME_CONNECTOR = _StubConnector("tlsx")  # addressing == "name"
_NONE_ADDR_CONNECTOR = _StubConnector("dns_resolve")  # addressing == "none"
_UNKNOWN_OBSERVER_CONNECTOR = _StubConnector("nope_not_seeded")
_UNDECLARED_CONNECTOR = _StubConnector(None)


# ── 1. descriptor, not boolean ───────────────────────────────────────────────

def test_probe_permission_is_a_descriptor_not_a_boolean():
    suffix = uuid.uuid4().hex[:10]
    v = f"pa-descriptor-{suffix}"
    hostname = f"pa-descriptor-{suffix}.example.com"
    db = SessionLocal()
    try:
        asset = _mk_ip_asset(db, v, parent_value=hostname)
        _set_state(db, asset.id, "name_only")

        gate = pa.authorise_probes(
            db, connector_id="test-name", connector=_NAME_CONNECTOR,
            assets=[_da(v)], scope={},
        )
        permission = gate.permissions[("ip_address", v)]

        assert type(permission) is pa.ProbePermission, type(permission)
        assert not isinstance(permission, bool), "ProbePermission must not collapse to a bool"
        assert permission.allowed is True
        assert permission.modes, "an allowed result must carry non-empty modes"
        assert permission.names == (hostname,), permission.names
    finally:
        db.close()
        _cleanup([v])


# ── 2. no_probe denies ───────────────────────────────────────────────────────

def test_no_probe_denies():
    suffix = uuid.uuid4().hex[:10]
    v = f"pa-noprobe-{suffix}"
    db = SessionLocal()
    try:
        asset = _mk_ip_asset(db, v)
        _set_state(db, asset.id, "no_probe")

        gate = pa.authorise_probes(
            db, connector_id="test-ip", connector=_IP_CONNECTOR,
            assets=[_da(v)], scope={},
        )
        permission = gate.permissions[("ip_address", v)]
        assert permission.allowed is False
        assert permission.rule_fired == "probe_class:no_probe"
        assert permission.modes == frozenset()
    finally:
        db.close()
        _cleanup([v])


# ── 3. name_only permits name, denies ip ────────────────────────────────────

def test_name_only_permits_name_and_denies_ip():
    suffix = uuid.uuid4().hex[:10]
    v = f"pa-nameonly-{suffix}"
    hostname = f"pa-nameonly-{suffix}.example.com"
    db = SessionLocal()
    try:
        asset = _mk_ip_asset(db, v, parent_value=hostname)
        _set_state(db, asset.id, "name_only")

        gate_ip = pa.authorise_probes(
            db, connector_id="test-ip", connector=_IP_CONNECTOR,
            assets=[_da(v)], scope={},
        )
        gate_name = pa.authorise_probes(
            db, connector_id="test-name", connector=_NAME_CONNECTOR,
            assets=[_da(v)], scope={},
        )

        ip_permission = gate_ip.permissions[("ip_address", v)]
        name_permission = gate_name.permissions[("ip_address", v)]

        assert ip_permission.allowed is False
        assert ip_permission.rule_fired == "addressing_not_permitted"
        assert ip_permission.modes == frozenset()

        assert name_permission.allowed is True
        assert name_permission.names == (hostname,)
    finally:
        db.close()
        _cleanup([v])


# ── 3b. `_probe_class_cap` called directly — planning#181 Tier 1 ───────────

def test_name_only_licenses_ip_handshake_but_never_full_ip():
    """planning#181 §4's carve-out. An address whose tenancy is undetermined
    projects to `name_only`, and the Tier 1b rung that would resolve that
    tenancy needs a bare-IP TLS handshake — denied by the very state the
    evidence would clear. `ip_handshake` breaks that circle WITHOUT granting
    `ip`: one handshake, no sweep, no payload."""
    cap = pa._probe_class_cap(
        None, asset_ref=None, canonical=object(),
        state=SimpleNamespace(attributes={"probe_class": "name_only"}),
    )
    assert cap.allowed is True
    assert cap.modes == frozenset({"name", "ip_handshake"})
    assert "ip" not in cap.modes, "ip_handshake must not imply full ip probing"
    assert cap.rule == "probe_class:name_only"


def test_direct_addressable_stays_the_full_addressing_set():
    """Load-bearing: `_compose` reports `unconstrained` only when nothing
    narrowed `modes` below ADDRESSING_MODES, so a `direct_addressable` asset
    that did not gain `ip_handshake` alongside the new mode would silently
    start reporting a narrowing rule instead."""
    cap = pa._probe_class_cap(
        None, asset_ref=None, canonical=object(),
        state=SimpleNamespace(attributes={"probe_class": "direct_addressable"}),
    )
    assert cap.modes == pa.ADDRESSING_MODES
    assert cap.rule == "probe_class:direct_addressable"


def test_no_probe_licenses_nothing_including_ip_handshake():
    cap = pa._probe_class_cap(
        None, asset_ref=None, canonical=object(),
        state=SimpleNamespace(attributes={"probe_class": "no_probe"}),
    )
    assert cap.allowed is False
    assert cap.modes == frozenset()


# ── 4. each cap independently reduces; no cap can widen another ────────────

def test_each_cap_independently_reduces_and_cannot_widen():
    """The issue's own acceptance test (planning#148 §1.4 / §5.4): each of
    the three caps must be independently capable of narrowing the composed
    result, and a permissive cap can never widen past a stricter one —
    `min()` composition, never `OR`.
    """
    suffix = uuid.uuid4().hex[:10]
    v = f"pa-eachcap-{suffix}"
    db = SessionLocal()
    real_scope_cap = pa._scope_cap
    real_probe_class_cap = pa._probe_class_cap
    real_posture_cap = pa._posture_cap
    try:
        asset = _mk_ip_asset(db, v)
        _set_state(db, asset.id, "direct_addressable")  # real cap: fully open, {"ip", "name", "ip_handshake"}

        # Baseline: everything real, fully permitted.
        baseline = pa.authorise_probes(
            db, connector_id="test-ip", connector=_IP_CONNECTOR,
            assets=[_da(v)], scope={},
        )
        assert baseline.permissions[("ip_address", v)].allowed is True

        # 1) scope_cap tightened alone -> composed denies.
        pa._scope_cap = lambda *a, **kw: pa.Cap(False, frozenset(), None, "scope:test_deny")
        try:
            gate = pa.authorise_probes(
                db, connector_id="test-ip", connector=_IP_CONNECTOR,
                assets=[_da(v)], scope={},
            )
            permission = gate.permissions[("ip_address", v)]
            assert permission.allowed is False
            assert permission.rule_fired == "scope:test_deny"
        finally:
            pa._scope_cap = real_scope_cap

        # 2) probe_class_cap tightened alone -> composed denies.
        pa._probe_class_cap = lambda *a, **kw: pa.Cap(False, frozenset(), None, "probe_class:test_deny")
        try:
            gate = pa.authorise_probes(
                db, connector_id="test-ip", connector=_IP_CONNECTOR,
                assets=[_da(v)], scope={},
            )
            permission = gate.permissions[("ip_address", v)]
            assert permission.allowed is False
            assert permission.rule_fired == "probe_class:test_deny"
        finally:
            pa._probe_class_cap = real_probe_class_cap

        # 3) posture_cap tightened alone -> composed denies.
        pa._posture_cap = lambda *a, **kw: pa.Cap(False, frozenset(), None, "posture:test_deny")
        try:
            gate = pa.authorise_probes(
                db, connector_id="test-ip", connector=_IP_CONNECTOR,
                assets=[_da(v)], scope={},
            )
            permission = gate.permissions[("ip_address", v)]
            assert permission.allowed is False
            assert permission.rule_fired == "posture:test_deny"
        finally:
            pa._posture_cap = real_posture_cap

        # 4) no cap can WIDEN another: force the real probe_class cap down to
        # name_only ({"name"} only), then monkeypatch scope_cap to explicitly
        # claim BOTH modes are fine. "ip" must still be denied to the
        # ip-addressing connector — a permissive cap intersecting with a
        # stricter one can never recover the mode the stricter one dropped.
        _set_state(db, asset.id, "name_only")
        pa._scope_cap = lambda *a, **kw: pa.Cap(True, pa.ADDRESSING_MODES, None, "scope:test_widen_attempt")
        try:
            gate = pa.authorise_probes(
                db, connector_id="test-ip", connector=_IP_CONNECTOR,
                assets=[_da(v)], scope={},
            )
            permission = gate.permissions[("ip_address", v)]
            assert permission.allowed is False, (
                "a permissive scope_cap claiming the full addressing set must not "
                "override probe_class's real name_only restriction"
            )
            assert permission.rule_fired == "addressing_not_permitted"
        finally:
            pa._scope_cap = real_scope_cap
    finally:
        pa._scope_cap = real_scope_cap
        pa._probe_class_cap = real_probe_class_cap
        pa._posture_cap = real_posture_cap
        db.close()
        _cleanup([v])


def test_posture_cap_receives_the_asset_and_can_decide_per_asset():
    """`_posture_cap` must be able to reach a *different* verdict for two
    assets in the same batch — posture is per-asset, not tenant-global.

    This is planning#132's load-bearing requirement and the reason the cap
    takes `asset_ref`/`canonical` rather than only `db`/`scope`. The M&A
    case forces it: an acquired company's cloud lands in its own Wiz
    Project (or its own Wiz tenant), and pre-close the acquirer may hold
    no authorisation to probe those assets at all — while the parent org's
    own estate stays fully probeable at the same instant. A posture cap
    that could only read a global setting could not express that.

    The real body is a permissive stub in this slice, so this test drives
    a stand-in that discriminates purely on the asset it is handed. What
    it pins is the *plumbing*: that the asset actually arrives, and that a
    per-asset verdict survives composition into per-asset permissions. If
    a later refactor narrows this signature back, this fails rather than
    silently making #132 tenant-global.
    """
    suffix = uuid.uuid4().hex[:10]
    allowed_value = f"pa-posture-ours-{suffix}"
    denied_value = f"pa-posture-ma-{suffix}"
    db = SessionLocal()
    real_posture_cap = pa._posture_cap
    seen: list = []
    try:
        for value in (allowed_value, denied_value):
            asset = _mk_ip_asset(db, value)
            _set_state(db, asset.id, "direct_addressable")

        def _per_asset_posture(db_, *, scope, asset_ref, canonical, ma_pre_close_ids, noise_class):
            # Record what actually arrived, then decide on it.
            # `ma_pre_close_ids` and `noise_class` are both accepted
            # (unused) purely to match the planning#193 / planning#196
            # signature `authorise_probes` now calls this function with —
            # a stand-in that dropped either would TypeError.
            seen.append((getattr(asset_ref, "value", None), canonical))
            if getattr(asset_ref, "value", None) == denied_value:
                return pa.Cap(False, frozenset(), None, "posture:ma_pre_close")
            return pa.Cap(True, None, None, "posture:permissive")

        pa._posture_cap = _per_asset_posture
        gate = pa.authorise_probes(
            db, connector_id="test-ip", connector=_IP_CONNECTOR,
            assets=[_da(allowed_value), _da(denied_value)], scope={},
        )

        ours = gate.permissions[("ip_address", allowed_value)]
        acquired = gate.permissions[("ip_address", denied_value)]
        assert ours.allowed is True, "parent-org asset must stay probeable"
        assert acquired.allowed is False, (
            "posture must be able to deny one asset while allowing another in "
            "the same batch — that is the M&A pre-close case"
        )
        assert acquired.rule_fired == "posture:ma_pre_close"

        # The asset really arrived (not None), and the canonical came with it.
        assert {v for v, _ in seen} == {allowed_value, denied_value}
        assert all(canonical is not None for _, canonical in seen), (
            "the resolved canonical must reach the posture cap too — #132 needs "
            "it to look up which estate/project the asset belongs to"
        )
    finally:
        pa._posture_cap = real_posture_cap
        db.close()
        _cleanup([allowed_value, denied_value])


# ── 5. undeclared / unknown observer denied, in both gate modes ────────────

def test_undeclared_and_unknown_observer_denied_in_both_modes():
    suffix = uuid.uuid4().hex[:10]
    v = f"pa-undeclared-{suffix}"
    db = SessionLocal()
    try:
        asset = _mk_ip_asset(db, v)
        _set_state(db, asset.id, "direct_addressable")  # would otherwise be fully permitted

        for mode_value in (None, "enforce"):  # None -> default (log_only)
            _set_mode(db, mode_value)

            gate = pa.authorise_probes(
                db, connector_id="test-undeclared", connector=_UNDECLARED_CONNECTOR,
                assets=[_da(v)], scope={},
            )
            permission = gate.permissions[("ip_address", v)]
            assert permission.allowed is False, f"mode={mode_value}"
            assert permission.rule_fired == "undeclared_observer", f"mode={mode_value}"
            assert gate.permitted == [], f"mode={mode_value}"

            gate = pa.authorise_probes(
                db, connector_id="test-unknown", connector=_UNKNOWN_OBSERVER_CONNECTOR,
                assets=[_da(v)], scope={},
            )
            permission = gate.permissions[("ip_address", v)]
            assert permission.allowed is False, f"mode={mode_value}"
            assert permission.rule_fired == "unknown_observer", f"mode={mode_value}"
            assert gate.permitted == [], f"mode={mode_value}"
    finally:
        _set_mode(db, None)
        db.close()
        _cleanup([v])


# ── 6. addressing == "none" observer denied ─────────────────────────────────

def test_observer_addressing_none_denied():
    suffix = uuid.uuid4().hex[:10]
    v = f"pa-noneaddr-{suffix}"
    db = SessionLocal()
    try:
        asset = _mk_ip_asset(db, v)
        _set_state(db, asset.id, "direct_addressable")

        gate = pa.authorise_probes(
            db, connector_id="test-none-addr", connector=_NONE_ADDR_CONNECTOR,
            assets=[_da(v)], scope={},
        )
        permission = gate.permissions[("ip_address", v)]
        assert permission.allowed is False
        assert permission.rule_fired == "observer_addressing_none"
        assert gate.permitted == []
    finally:
        db.close()
        _cleanup([v])


# ── 7. unprojected asset denied ──────────────────────────────────────────────

def test_unprojected_asset_denied():
    suffix = uuid.uuid4().hex[:10]
    v = f"pa-unprojected-{suffix}"
    db = SessionLocal()
    try:
        _mk_ip_asset(db, v)  # deliberately no asset_state row at all

        gate = pa.authorise_probes(
            db, connector_id="test-ip", connector=_IP_CONNECTOR,
            assets=[_da(v)], scope={},
        )
        permission = gate.permissions[("ip_address", v)]
        assert permission.allowed is False
        assert permission.rule_fired == "probe_class:unprojected"
    finally:
        db.close()
        _cleanup([v])


# ── 8. decision-log row written and reconstructs the decision ──────────────

def test_decision_log_row_written_and_reconstructs_decision():
    suffix = uuid.uuid4().hex[:10]
    v_allowed = f"pa-decisionlog-allowed-{suffix}"
    v_denied = f"pa-decisionlog-denied-{suffix}"
    db = SessionLocal()
    try:
        a_allowed = _mk_ip_asset(db, v_allowed)
        _set_state(db, a_allowed.id, "direct_addressable")
        a_denied = _mk_ip_asset(db, v_denied)
        _set_state(db, a_denied.id, "no_probe")

        gate = pa.authorise_probes(
            db, connector_id="test-ip", connector=_IP_CONNECTOR,
            assets=[_da(v_allowed), _da(v_denied)],
            scope={}, scan_run_id=uuid.uuid4(),
        )
        assert gate.permissions[("ip_address", v_allowed)].allowed is True
        assert gate.permissions[("ip_address", v_denied)].allowed is False

        rows = (
            db.query(AuthorisationDecision)
            .filter(AuthorisationDecision.asset_canonical_id.in_([a_allowed.id, a_denied.id]))
            .all()
        )
        assert len(rows) == 2, "one decision row per (asset, connector) evaluated"
        by_asset = {r.asset_canonical_id: r for r in rows}

        allowed_row = by_asset[a_allowed.id]
        assert allowed_row.allowed is True
        assert allowed_row.probe_modes, allowed_row.probe_modes
        assert allowed_row.rule_fired
        assert set(allowed_row.evidence_snapshot) >= {
            "connector_id", "observer", "observer_addressing", "probe_class",
            "tenancy", "gate_mode", "scan_run_id", "caps",
        }
        assert set(allowed_row.evidence_snapshot["caps"]) == {"scope", "probe_class", "posture"}
        assert allowed_row.evidence_snapshot["probe_class"] == "direct_addressable"

        denied_row = by_asset[a_denied.id]
        assert denied_row.allowed is False, "denials must be logged too"
        assert denied_row.rule_fired == "probe_class:no_probe"
        assert denied_row.probe_modes == []
    finally:
        db.close()
        _cleanup([v_allowed, v_denied])


# ── 9. log_only does not narrow, but logs the real verdict ─────────────────

def test_log_only_does_not_narrow_but_logs_real_verdict():
    suffix = uuid.uuid4().hex[:10]
    v = f"pa-logonly-{suffix}"
    db = SessionLocal()
    try:
        _set_mode(db, None)  # ensure default (log_only) — no override row
        asset = _mk_ip_asset(db, v)
        _set_state(db, asset.id, "no_probe")

        gate = pa.authorise_probes(
            db, connector_id="test-ip", connector=_IP_CONNECTOR,
            assets=[_da(v)], scope={},
        )
        assert gate.enforced is False
        assert len(gate.permitted) == 1 and gate.permitted[0].value == v, (
            "log_only must pass the full, unfiltered input through"
        )

        row = (
            db.query(AuthorisationDecision)
            .filter(AuthorisationDecision.asset_canonical_id == asset.id)
            .one()
        )
        assert row.allowed is False, "the decision log must record the real verdict even in log_only"
    finally:
        db.close()
        _cleanup([v])


# ── 10. enforce narrows ──────────────────────────────────────────────────────

def test_enforce_narrows():
    suffix = uuid.uuid4().hex[:10]
    v = f"pa-enforce-{suffix}"
    db = SessionLocal()
    try:
        asset = _mk_ip_asset(db, v)
        _set_state(db, asset.id, "no_probe")
        _set_mode(db, "enforce")

        gate = pa.authorise_probes(
            db, connector_id="test-ip", connector=_IP_CONNECTOR,
            assets=[_da(v)], scope={},
        )
        assert gate.enforced is True
        assert gate.permitted == [], "enforce must narrow the no_probe asset out of permitted"
    finally:
        _set_mode(db, None)
        db.close()
        _cleanup([v])


# ── 11. name-addressed probe with no authorised names is denied ────────────

def test_name_addressed_probe_with_no_authorised_names_denied():
    suffix = uuid.uuid4().hex[:10]
    v = f"pa-nonames-{suffix}"
    db = SessionLocal()
    try:
        asset = _mk_ip_asset(db, v, parent_value=None)
        _set_state(db, asset.id, "name_only")

        gate = pa.authorise_probes(
            db, connector_id="test-name", connector=_NAME_CONNECTOR,
            assets=[_da(v)], scope={},
        )
        permission = gate.permissions[("ip_address", v)]
        assert permission.allowed is False
        assert permission.rule_fired == "no_authorised_names"
        assert permission.names == ()
    finally:
        db.close()
        _cleanup([v])


# ── 12. dns_record assets: names come from the record's own hostname ───────

def test_dns_record_authorised_names_and_identity_key():
    """The `dns_record` half of `_resolve_authorised_names`, plus the
    composite-identity-key path through `_canonical_key_for` — both are
    exercised only by dns_record assets, which every other test in this
    file (all `ip_address`) leaves untouched.

    `_canonical_key` folds `record_type`/`content` into a dns_record's
    identity, so a `DiscoveredAsset` must carry those in `asset_metadata`
    to resolve to a *typed* canonical row. That is what the second half of
    this test pins: a bare in-batch asset (no record_type/content) does NOT
    silently resolve to some arbitrary typed row for the same hostname.
    """
    suffix = uuid.uuid4().hex[:10]
    host = f"pa-dns-{suffix}.example.com"
    # The `bare` half below denies as `unresolved_asset`, which logs a
    # decision row with a NULL `asset_canonical_id` that `_cleanup([host])`
    # cannot reach. Until planning#189 this leaked, and was masked: the
    # table-wide sweep in `test_unresolved_asset_is_distinct_from_unprojected`
    # happened to delete it on the way past. Running THIS test alone still
    # added a row. Each test cleans up after itself now.
    mark = _decision_log.watermark()
    db = SessionLocal()
    now = datetime.now(timezone.utc)
    try:
        row = AssetCanonical(
            id=uuid.uuid4(), asset_type="dns_record", value=host,
            record_type="A", content="192.0.2.10",
            first_seen_at=now, last_seen_at=now,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        _set_state(db, row.id, "name_only")

        typed = DiscoveredAsset(
            asset_type="dns_record", value=host,
            asset_metadata={"record_type": "A", "content": "192.0.2.10"},
        )
        gate = pa.authorise_probes(
            db, connector_id="test-name", connector=_NAME_CONNECTOR,
            assets=[typed], scope={},
        )
        permission = gate.permissions[("dns_record", host)]
        assert permission.allowed is True, permission.rule_fired
        assert permission.names == (host,), permission.names
        # planning#181 Tier 1b: name_only's composed modes now also include
        # ip_handshake (see probe_authorisation._probe_class_cap) — this
        # asset didn't change, the vocabulary a name_only state licenses did.
        assert permission.modes == frozenset({"name", "ip_handshake"})

        # A bare dns_record asset carries no record_type/content, so its
        # identity key can't match the typed row above. It must fail closed
        # as `unresolved_asset` — NOT resolve to the typed row anyway, and
        # NOT be mislabelled `probe_class:unprojected` (the asset that row
        # points at is projected; we simply never found the row).
        bare = DiscoveredAsset(asset_type="dns_record", value=host)
        bare_gate = pa.authorise_probes(
            db, connector_id="test-name", connector=_NAME_CONNECTOR,
            assets=[bare], scope={},
        )
        bare_permission = bare_gate.permissions[("dns_record", host)]
        assert bare_permission.allowed is False
        assert bare_permission.rule_fired == "unresolved_asset", bare_permission.rule_fired
    finally:
        db.close()
        _cleanup([host])
        _decision_log.cleanup_since(mark)


# ── 13. unresolved vs unprojected are distinct, logged denial rules ────────

def test_unresolved_asset_is_distinct_from_unprojected():
    """An asset with no canonical row at all denies as `unresolved_asset`;
    an asset WITH a canonical row but no projection denies as
    `probe_class:unprojected`. Both fail closed, but the log-only rollout
    is read to decide whether enforcing is safe, and these two call for
    completely different remedies — so they must never share a label.
    """
    suffix = uuid.uuid4().hex[:10]
    orphan = f"pa-orphan-{suffix}"
    projected_none = f"pa-noproj-{suffix}"
    mark = _decision_log.watermark()
    db = SessionLocal()
    try:
        _mk_ip_asset(db, projected_none)  # canonical row, deliberately no asset_state

        gate = pa.authorise_probes(
            db, connector_id="test-ip", connector=_IP_CONNECTOR,
            assets=[_da(orphan), _da(projected_none)], scope={},
        )
        assert gate.permissions[("ip_address", orphan)].rule_fired == "unresolved_asset"
        assert gate.permissions[("ip_address", projected_none)].rule_fired == "probe_class:unprojected"

        # The unresolvable one still gets a decision row, with a NULL
        # asset_canonical_id (AuthorisationDecision's own docstring allows
        # exactly this) — an unidentifiable probe candidate is the case the
        # audit trail most needs to record, not the one it may drop.
        orphan_rows = (
            db.query(AuthorisationDecision)
            .filter(AuthorisationDecision.asset_canonical_id.is_(None))
            .filter(AuthorisationDecision.rule_fired == "unresolved_asset")
            .filter(AuthorisationDecision.decided_at >= mark)
            .count()
        )
        assert orphan_rows >= 1
    finally:
        db.close()
        _cleanup([projected_none])
        # Was a table-wide DELETE of every NULL-id `unresolved_asset` row
        # (planning#189). The backend suite runs against the DEV database,
        # so that swept rows belonging to other tests — and would sweep a
        # REAL scan row, which takes exactly this shape whenever a scan
        # meets an address with no canonical row under a permissive scope
        # cap. Bounded to this test's own window now; the assertion above
        # is bounded the same way, for the same reason (planning#163).
        _decision_log.cleanup_since(mark)


# ── regression guard: every REGISTRY port_scan connector declares a valid
#    observer (the thing that stops the hasattr-only hole reopening) ───────

def test_registry_port_scan_connectors_all_declare_valid_observer():
    """Every connector in `app.api.connectors.REGISTRY` exposing `port_scan`
    (i.e. every current or future Phase 1.5 probe) must declare an
    `observer` class attribute that resolves to a seeded `observers` row
    with `addressing != "none"`.

    Placed in this file rather than `test_claims_schema.py`: that file only
    asserts schema/seed-data facts about the claims-layer tables themselves
    (row counts, CHECK constraints, the seeded addressing vocabulary) and
    deliberately has no application-layer connector awareness. This guard
    is the opposite — it's entirely about the connector layer's contract
    with THIS module, and the regression it exists to catch (a new
    `port_scan` connector shipped without an `observer` declaration,
    reopening the pre-#148 `hasattr(c, "port_scan")` hole) is a
    probe_authorisation defect, not a claims-schema one.
    """
    from app.models.observer import Observer

    from app.api.connectors import REGISTRY

    db = SessionLocal()
    try:
        addressing_by_name = dict(db.query(Observer.name, Observer.addressing).all())
    finally:
        db.close()

    offenders = []
    for cid, connector in REGISTRY.items():
        if not hasattr(connector, "port_scan"):
            continue
        slug = getattr(connector, "observer", None)
        if not slug:
            offenders.append((cid, "no `observer` attribute declared"))
            continue
        addressing = addressing_by_name.get(slug)
        if addressing is None:
            offenders.append((cid, f"observer {slug!r} is not a seeded observers row"))
        elif addressing == "none":
            offenders.append((cid, f"observer {slug!r} has addressing='none'"))

    assert not offenders, f"port_scan connector(s) with no valid observer declaration: {offenders}"


# ── 14. tenancy rides the decision row (planning#182 / planning#177) ───────

def test_tenancy_verdict_separates_the_three_name_only_denials():
    """planning#177's acceptance criterion 3, consumer half.

    Three IPs land at `name_only` for three different reasons — never
    enriched, enriched and unanswerable, and a genuine "not a single-tenant
    address" — and an ip-addressing connector is denied on all three with the
    IDENTICAL `rule_fired`. That is the failure #177 documented: the decision
    log could not tell a broken dependency from a policy outcome, so a vendor
    schema change read as a month of correct denials.

    `evidence_snapshot["tenancy"]["rule"]` is what separates them, and it sits
    at the TOP level of the snapshot on purpose: the #148 enforce flip is
    decided by counting these rows, so the deny-reason breakdown has to be one
    GROUP BY away rather than a JSON path spelunk.
    """
    suffix = uuid.uuid4().hex[:10]
    v_unenriched = f"pa-tenancy-unenriched-{suffix}"
    v_unanswerable = f"pa-tenancy-unanswerable-{suffix}"
    v_negative = f"pa-tenancy-negative-{suffix}"
    values = [v_unenriched, v_unanswerable, v_negative]
    db = SessionLocal()
    try:
        by_value = {}
        for value, tenancy in (
            (v_unenriched, {"tenancy": "undetermined", "rule": "no_rungs_reported", "rungs": []}),
            (v_unanswerable, {"tenancy": "undetermined", "rule": "all_rungs_undetermined",
                              "rungs": [{"observer": "tenancy_enricher", "claim_type": "tenancy",
                                         "tier": None, "tenancy": "undetermined",
                                         "reason": "service_class_unknown"}]}),
            (v_negative, {"tenancy": "not_single_tenant", "rule": "dissent_wins_outright",
                          "rungs": [{"observer": "tenancy_enricher", "claim_type": "tenancy",
                                     "tier": 0, "tenancy": "not_single_tenant",
                                     "reason": "provider_service_class_edge"}]}),
        ):
            asset = _mk_ip_asset(db, value)
            by_value[value] = asset.id
            db.add(AssetState(
                asset_canonical_id=asset.id,
                attributes={"probe_class": "name_only", "tenancy": tenancy},
                projected_at=datetime.now(timezone.utc),
            ))
        db.commit()

        gate = pa.authorise_probes(
            db, connector_id="test-ip", connector=_IP_CONNECTOR,
            assets=[_da(v) for v in values], scope={}, scan_run_id=uuid.uuid4(),
        )

        rows = (
            db.query(AuthorisationDecision)
            .filter(AuthorisationDecision.asset_canonical_id.in_(list(by_value.values())))
            .all()
        )
        by_asset = {r.asset_canonical_id: r for r in rows}
        assert len(by_asset) == 3

        # All three deny, and — this is the point — all three deny under the
        # SAME rule string. `rule_fired` alone cannot carry the distinction.
        for value in values:
            assert gate.permissions[("ip_address", value)].allowed is False
            assert by_asset[by_value[value]].rule_fired == "addressing_not_permitted"

        seen = {
            value: by_asset[by_value[value]].evidence_snapshot["tenancy"]["rule"]
            for value in values
        }
        assert seen == {
            v_unenriched: "no_rungs_reported",
            v_unanswerable: "all_rungs_undetermined",
            v_negative: "dissent_wins_outright",
        }
        assert len(set(seen.values())) == 3, "the three denials must stay distinguishable"

        negative = by_asset[by_value[v_negative]].evidence_snapshot["tenancy"]
        assert negative["tenancy"] == "not_single_tenant"
        assert negative["rungs"][0]["reason"] == "provider_service_class_edge"
    finally:
        db.close()
        _cleanup(values)


def test_tenancy_key_present_even_when_the_projection_says_nothing():
    """The key is always on the snapshot, so a count over
    `evidence_snapshot->'tenancy'` never has to special-case which branch
    wrote the row. Null is a legitimate value here — an unprojected asset, or
    a connector refused on its own declaration before any state was read."""
    suffix = uuid.uuid4().hex[:10]
    v = f"pa-tenancy-unprojected-{suffix}"
    db = SessionLocal()
    try:
        asset = _mk_ip_asset(db, v)  # no asset_state row at all
        pa.authorise_probes(
            db, connector_id="test-ip", connector=_IP_CONNECTOR,
            assets=[_da(v)], scope={}, scan_run_id=uuid.uuid4(),
        )
        row = (
            db.query(AuthorisationDecision)
            .filter(AuthorisationDecision.asset_canonical_id == asset.id)
            .one()
        )
        assert row.rule_fired == "probe_class:unprojected"
        assert "tenancy" in row.evidence_snapshot
        assert row.evidence_snapshot["tenancy"] is None

        undeclared = pa.authorise_probes(
            db, connector_id="test-undeclared", connector=_UNDECLARED_CONNECTOR,
            assets=[_da(v)], scope={}, scan_run_id=uuid.uuid4(),
        )
        assert undeclared.permissions[("ip_address", v)].allowed is False
        refused = (
            db.query(AuthorisationDecision)
            .filter(AuthorisationDecision.asset_canonical_id == asset.id)
            .order_by(AuthorisationDecision.decided_at.desc())
            .first()
        )
        assert "tenancy" in refused.evidence_snapshot
        assert refused.evidence_snapshot["tenancy"] is None
    finally:
        db.close()
        _cleanup([v])

# ── 15. planning#193 — posture cap's real body (pre-close M&A) ─────────────

def test_posture_cap_denies_an_asset_linked_to_a_pre_close_target():
    suffix = uuid.uuid4().hex[:10]
    v = f"pa193-linked-{suffix}"
    db = SessionLocal()
    target_id = None
    try:
        asset = _mk_ip_asset(db, v)
        target = _mk_target(db, f"pa193-target-{suffix}.example.com", ma_pre_close=True)
        target_id = target.id  # captured before any later commit expires/detaches the row
        _link(db, target.id, asset.id)

        ma_ids = pa._resolve_ma_pre_close_ids(db, {asset.id})
        cap = pa._posture_cap(db, scope={}, asset_ref=None, canonical=asset, ma_pre_close_ids=ma_ids, noise_class="target_host")
        assert cap.allowed is False
        assert cap.rule == "posture:ma_pre_close"
        assert cap.modes == frozenset()
    finally:
        db.close()
        _cleanup([v])
        _cleanup_targets([target_id])


def test_posture_cap_permits_unlinked_and_ordinary_linked_assets():
    suffix = uuid.uuid4().hex[:10]
    v_unlinked = f"pa193-unlinked-{suffix}"
    v_ordinary = f"pa193-ordinary-{suffix}"
    db = SessionLocal()
    target_id = None
    try:
        unlinked = _mk_ip_asset(db, v_unlinked)
        ordinary_asset = _mk_ip_asset(db, v_ordinary)
        target = _mk_target(db, f"pa193-ordinary-target-{suffix}.example.com", ma_pre_close=False)
        target_id = target.id  # captured before any later commit expires/detaches the row
        _link(db, target.id, ordinary_asset.id)

        ma_ids = pa._resolve_ma_pre_close_ids(db, {unlinked.id, ordinary_asset.id})
        assert ma_ids == frozenset(), "an ordinary target's link must not appear in the pre-close set"

        for asset in (unlinked, ordinary_asset):
            cap = pa._posture_cap(db, scope={}, asset_ref=None, canonical=asset, ma_pre_close_ids=ma_ids, noise_class="target_host")
            assert cap.allowed is True, asset.value
            assert cap.rule == "posture:permissive", asset.value
    finally:
        db.close()
        _cleanup([v_unlinked, v_ordinary])
        _cleanup_targets([target_id])


def test_posture_cap_any_link_wins_even_with_an_ordinary_target_also_linked():
    """`target_asset_links` is N-to-N — one pre-close link denies
    regardless of how many ordinary targets are ALSO linked to the same
    asset. Fail closed: another target's authorisation cannot overrule the
    statement that this one has not authorised probing."""
    suffix = uuid.uuid4().hex[:10]
    v = f"pa193-anylink-{suffix}"
    db = SessionLocal()
    pre_close_target_id = None
    ordinary_target_id = None
    try:
        asset = _mk_ip_asset(db, v)
        pre_close_target = _mk_target(db, f"pa193-preclose-{suffix}.example.com", ma_pre_close=True)
        ordinary_target = _mk_target(db, f"pa193-ordinary2-{suffix}.example.com", ma_pre_close=False)
        # captured before any later commit expires/detaches these rows
        pre_close_target_id, ordinary_target_id = pre_close_target.id, ordinary_target.id
        _link(db, pre_close_target.id, asset.id)
        _link(db, ordinary_target.id, asset.id)

        ma_ids = pa._resolve_ma_pre_close_ids(db, {asset.id})
        cap = pa._posture_cap(db, scope={}, asset_ref=None, canonical=asset, ma_pre_close_ids=ma_ids, noise_class="target_host")
        assert cap.allowed is False, "one pre-close link must deny even with an ordinary target also linked"
        assert cap.rule == "posture:ma_pre_close"
    finally:
        db.close()
        _cleanup([v])
        _cleanup_targets([pre_close_target_id, ordinary_target_id])


def test_posture_cap_permissive_when_canonical_is_none():
    """Documents the deliberate hole `_posture_cap`'s docstring argues for:
    an asset that never resolved to a canonical row cannot be checked
    against `ma_pre_close_ids` at all (there is no id to look up), and
    `_posture_cap` does not deny on that basis — `_scope_cap`'s
    `scope:unresolved_asset` is what closes this case instead. Pinned here
    so a future change to this behaviour is made on purpose, not by
    accident.

    planning#196 added the `noise_class` argument to `_posture_cap`; this
    call passes `"target_host"` — the noisiest class, denied outright
    under passive-only — deliberately, so the PERMISSIVE outcome asserted
    below is proven for the hardest case, not one that would pass anyway
    because the noise class happened to be permitted.
    """
    cap = pa._posture_cap(
        None, scope={}, asset_ref=None, canonical=None,
        ma_pre_close_ids=frozenset({uuid.uuid4()}), noise_class="target_host",
    )
    assert cap.allowed is True
    assert cap.rule == "posture:permissive"


def test_posture_denial_always_enforced_under_log_only():
    """The important one (spec case 5). Under `log_only`,
    `probe_authorisation_mode`'s graduated rollout does not apply to
    `posture:ma_pre_close` — it narrows `permitted` regardless, exactly
    like the connector-declaration check. An ordinary (non-posture) denial
    in the SAME call must NOT narrow `permitted` — only the posture axis
    is always-enforced, so this also guards against #193 accidentally
    becoming an early #148 enforce flip."""
    suffix = uuid.uuid4().hex[:10]
    v_posture = f"pa193-alwaysenf-posture-{suffix}"
    v_scope = f"pa193-alwaysenf-scope-{suffix}"
    db = SessionLocal()
    target_id = None
    real_scope_cap = pa._scope_cap
    try:
        _set_mode(db, None)  # ensure default (log_only) — no override row

        posture_asset = _mk_ip_asset(db, v_posture)
        _set_state(db, posture_asset.id, "direct_addressable")
        scope_asset = _mk_ip_asset(db, v_scope)
        _set_state(db, scope_asset.id, "direct_addressable")

        target = _mk_target(db, f"pa193-alwaysenf-target-{suffix}.example.com", ma_pre_close=True)
        target_id = target.id  # captured before any later commit expires/detaches the row
        _link(db, target.id, posture_asset.id)

        # scope_asset is not linked to any pre-close target (posture stays
        # permissive for it) but is force-denied by scope here, standing in
        # for an ordinary out-of-scope asset. The per-asset discrimination
        # mirrors test_posture_cap_receives_the_asset_and_can_decide_per_asset
        # above, just on `_scope_cap` instead of `_posture_cap`.
        def _scope_stub(db_, *, scope, asset_ref, canonical, scoped_ids, auth_mode):
            if getattr(asset_ref, "value", None) == v_scope:
                return pa.Cap(False, frozenset(), None, "scope:test_deny")
            return pa.Cap(True, None, None, "scope:test_permit")

        pa._scope_cap = _scope_stub
        try:
            gate = pa.authorise_probes(
                db, connector_id="test-ip", connector=_IP_CONNECTOR,
                assets=[_da(v_posture), _da(v_scope)], scope={},
            )
        finally:
            pa._scope_cap = real_scope_cap

        permitted_values = {a.value for a in gate.permitted}
        assert v_posture not in permitted_values, (
            "posture:ma_pre_close must narrow permitted even under log_only"
        )
        assert v_scope in permitted_values, (
            "an ordinary (non-posture) denial must NOT narrow permitted under "
            "log_only — only the posture axis is always-enforced"
        )
        assert gate.enforced is True, (
            "enforced must report True once a posture denial actually narrowed permitted"
        )
    finally:
        pa._scope_cap = real_scope_cap
        _set_mode(db, None)
        db.close()
        _cleanup([v_posture, v_scope])
        _cleanup_targets([target_id])


def test_rule_fired_prefers_posture_when_both_scope_and_posture_deny():
    """Guards the §2d precedence change in `_compose`: when posture denies,
    it must win the `rule_fired` slot even though scope → probe_class →
    posture is the nominal composition order — because under `log_only`
    posture is the only one of the three whose denial actually takes
    effect, and reporting a different rule would put a misleading reason
    in the table planning#189 established is read for policy decisions."""
    suffix = uuid.uuid4().hex[:10]
    v = f"pa193-precedence-{suffix}"
    db = SessionLocal()
    target_id = None
    real_scope_cap = pa._scope_cap
    try:
        asset = _mk_ip_asset(db, v)
        _set_state(db, asset.id, "direct_addressable")
        target = _mk_target(db, f"pa193-precedence-target-{suffix}.example.com", ma_pre_close=True)
        target_id = target.id  # captured before any later commit expires/detaches the row
        _link(db, target.id, asset.id)

        pa._scope_cap = lambda *a, **kw: pa.Cap(False, frozenset(), None, "scope:test_deny")
        try:
            gate = pa.authorise_probes(
                db, connector_id="test-ip", connector=_IP_CONNECTOR,
                assets=[_da(v)], scope={},
            )
        finally:
            pa._scope_cap = real_scope_cap

        permission = gate.permissions[("ip_address", v)]
        assert permission.allowed is False
        assert permission.rule_fired == "posture:ma_pre_close", (
            f"scope's denial must not win rule_fired over posture's: {permission.rule_fired!r}"
        )
        # Nothing is lost about scope's own verdict — it still rides the
        # per-cap evidence, just not the top-level rule_fired slot.
        assert permission.evidence["caps"]["scope"]["rule"] == "scope:test_deny"
    finally:
        pa._scope_cap = real_scope_cap
        db.close()
        _cleanup([v])
        _cleanup_targets([target_id])


def test_no_behaviour_change_when_nothing_is_ma_pre_close():
    """Regression guard (spec case 7): "did we accidentally flip #148
    early". With no `ma_pre_close` target anywhere in play, `log_only`
    must still return the fully unfiltered list with `enforced=False` —
    exactly what `test_log_only_does_not_narrow_but_logs_real_verdict`
    pins for the pre-#193 gate, replayed here to prove #193 didn't change
    it for the common case where posture never fires."""
    suffix = uuid.uuid4().hex[:10]
    v = f"pa193-noflag-{suffix}"
    db = SessionLocal()
    try:
        _set_mode(db, None)
        asset = _mk_ip_asset(db, v)
        _set_state(db, asset.id, "no_probe")  # denies under enforce, for an UNRELATED reason

        gate = pa.authorise_probes(
            db, connector_id="test-ip", connector=_IP_CONNECTOR,
            assets=[_da(v)], scope={},
        )
        assert gate.enforced is False
        assert len(gate.permitted) == 1 and gate.permitted[0].value == v
    finally:
        _set_mode(db, None)
        db.close()
        _cleanup([v])


def _run():
    tests = [
        test_probe_permission_is_a_descriptor_not_a_boolean,
        test_no_probe_denies,
        test_name_only_permits_name_and_denies_ip,
        test_name_only_licenses_ip_handshake_but_never_full_ip,
        test_direct_addressable_stays_the_full_addressing_set,
        test_no_probe_licenses_nothing_including_ip_handshake,
        test_each_cap_independently_reduces_and_cannot_widen,
        test_undeclared_and_unknown_observer_denied_in_both_modes,
        test_observer_addressing_none_denied,
        test_unprojected_asset_denied,
        test_decision_log_row_written_and_reconstructs_decision,
        test_log_only_does_not_narrow_but_logs_real_verdict,
        test_enforce_narrows,
        test_name_addressed_probe_with_no_authorised_names_denied,
        test_dns_record_authorised_names_and_identity_key,
        test_unresolved_asset_is_distinct_from_unprojected,
        test_registry_port_scan_connectors_all_declare_valid_observer,
        test_tenancy_verdict_separates_the_three_name_only_denials,
        test_tenancy_key_present_even_when_the_projection_says_nothing,
        test_posture_cap_denies_an_asset_linked_to_a_pre_close_target,
        test_posture_cap_permits_unlinked_and_ordinary_linked_assets,
        test_posture_cap_any_link_wins_even_with_an_ordinary_target_also_linked,
        test_posture_cap_permissive_when_canonical_is_none,
        test_posture_denial_always_enforced_under_log_only,
        test_rule_fired_prefers_posture_when_both_scope_and_posture_deny,
        test_no_behaviour_change_when_nothing_is_ma_pre_close,
    ]
    for fn in tests:
        fn()
        print(f"ok  {fn.__name__}")
    print("all passed")



if __name__ == "__main__":
    _run()
