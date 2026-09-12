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

from app.connectors.base import DiscoveredAsset
from app.core.database import SessionLocal
from app.models.app_settings import AppSetting
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.authorisation_decision import AuthorisationDecision
from app.services import app_settings
from app.services import probe_authorisation as pa

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
# test_claims_schema.test_observers_seeded_with_18_rows_and_correct_addressing
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
        _set_state(db, asset.id, "direct_addressable")  # real cap: fully open, {"ip", "name"}

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

        def _per_asset_posture(db_, *, scope, asset_ref, canonical):
            # Record what actually arrived, then decide on it.
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
            "gate_mode", "scan_run_id", "caps",
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
        assert permission.modes == frozenset({"name"})

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
            .count()
        )
        assert orphan_rows >= 1
    finally:
        db.query(AuthorisationDecision).filter(
            AuthorisationDecision.asset_canonical_id.is_(None),
            AuthorisationDecision.rule_fired == "unresolved_asset",
        ).delete(synchronize_session=False)
        db.commit()
        db.close()
        _cleanup([projected_none])


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


def _run():
    tests = [
        test_probe_permission_is_a_descriptor_not_a_boolean,
        test_no_probe_denies,
        test_name_only_permits_name_and_denies_ip,
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
    ]
    for fn in tests:
        fn()
        print(f"ok  {fn.__name__}")
    print("all passed")


if __name__ == "__main__":
    _run()
