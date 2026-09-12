"""Scope cap of the composed probe-authorisation gate (planning#128).

The bug this closes: `is_scan_authorised(db, apex_domain(value), auth_mode)`
resolves to an exact `Target.value == value` match, and `apex_domain()`
returns a bare IP unchanged. So under `acknowledge`:

  * an `ip_address` asset resolved from a hostname is not a `Target` row at
    all, and is silently dropped;
  * an IP *inside* a declared CIDR fails the same equality check against
    the CIDR row's own string value ("203.0.113.0/24" never equals any
    single address inside it), and is silently dropped.

Which is why `scan_authorisation_mode` could not be moved off `disabled`:
turning the gate on broke scanning. These tests pin the containment-based
replacement, so the mode is flippable.

Addresses are RFC-5737 documentation ranges throughout (CLAUDE.md).

Requires a live DB. Run with:
    python -m app.tests.test_scope_cap
    pytest app/tests/test_scope_cap.py
"""

import uuid
from datetime import datetime, timezone

from app.connectors.base import DiscoveredAsset
from app.core.database import SessionLocal
from app.models.app_settings import AppSetting
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.authorisation_decision import AuthorisationDecision
from app.models.target import Target, TargetType
from app.services import app_settings
from app.services import probe_authorisation as pa

_SCAN_MODE_KEY = "scan_authorisation_mode"
_GATE_MODE_KEY = "probe_authorisation_mode"


# ── helpers ──────────────────────────────────────────────────────────────

def _tag() -> str:
    """Every seeded value is uuid-suffixed. `targets.value` is unique, and
    fixed literals leak on a dirty exit and collide on the next run — the
    defect planning#156 records in test_target_scope.py. Not repeating it."""
    return uuid.uuid4().hex[:10]


def _mk_ip(db, value: str, parent_value: str | None = None) -> AssetCanonical:
    now = datetime.now(timezone.utc)
    row = AssetCanonical(
        id=uuid.uuid4(), asset_type="ip_address", value=value,
        parent_value=parent_value, first_seen_at=now, last_seen_at=now,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _set_state(db, asset_id, probe_class="direct_addressable") -> None:
    existing = db.get(AssetState, asset_id)
    now = datetime.now(timezone.utc)
    if existing is None:
        db.add(AssetState(asset_canonical_id=asset_id, attributes={"probe_class": probe_class}, projected_at=now))
    else:
        existing.attributes = {"probe_class": probe_class}
        existing.projected_at = now
    db.commit()


def _mk_target(db, value: str, ttype, verified: bool) -> Target:
    """Seed a Target, deleting any row that already holds this value first.

    `targets.value` is UNIQUE (`uq_targets_value`). A CIDR cannot be
    uuid-suffixed the way a hostname can — "192.0.2.0/24" has to stay a
    parseable network for containment to mean anything — so these tests
    necessarily reuse a fixed literal, which is exactly the shape that
    makes planning#156 bite: kill the process between the INSERT and the
    `finally` cleanup and the row survives, then the NEXT run's INSERT
    raises an IntegrityError, which poisons the session, which surfaces as
    a `PendingRollbackError` in whatever test touches that session next —
    somewhere else entirely, and looking nothing like the real cause.

    Deleting first makes the seed idempotent, so a dirty exit costs the
    next run nothing. This is the fix planning#156 wants applied to
    test_target_scope.py too; doing it here keeps this file from joining
    the problem."""
    db.query(Target).filter(Target.value == value).delete(synchronize_session=False)
    db.commit()
    row = Target(id=uuid.uuid4(), type=ttype, value=value, verified=verified)
    db.add(row)
    db.commit()
    return row


def _set_modes(db, scan_mode: str | None, gate_mode: str | None = "enforce") -> None:
    for key, value in ((_SCAN_MODE_KEY, scan_mode), (_GATE_MODE_KEY, gate_mode)):
        if value is None:
            db.query(AppSetting).filter(AppSetting.key == key).delete()
            db.commit()
        else:
            app_settings.set_value(db, key, value)


def _cleanup(values: list[str], target_values: list[str]) -> None:
    db = SessionLocal()
    try:
        rows = db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).all()
        ids = [r.id for r in rows]
        if ids:
            db.query(AuthorisationDecision).filter(
                AuthorisationDecision.asset_canonical_id.in_(ids)
            ).delete(synchronize_session=False)
            db.query(AssetState).filter(AssetState.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).delete(synchronize_session=False)
        if target_values:
            db.query(Target).filter(Target.value.in_(target_values)).delete(synchronize_session=False)
        _set_modes(db, None, None)
        db.commit()
    finally:
        db.close()


class _StubConnector:
    def __init__(self, observer_name):
        self.observer = observer_name


_IP_CONNECTOR = _StubConnector("naabu")  # addressing == "ip"


def _authorise(db, assets, scope):
    return pa.authorise_probes(
        db, connector_id="naabu", connector=_IP_CONNECTOR,
        assets=assets, scope=scope, scan_run_id=None,
    )


def _rule_for(result, value: str) -> str:
    return result.permissions[("ip_address", value)].rule_fired


# ── the regression this issue is named for ───────────────────────────────

def test_ip_inside_a_declared_cidr_is_authorised_under_acknowledge():
    """THE bug. `Target.value == "192.0.2.0/24"` never equals "192.0.2.7",
    so the old check dropped every address inside every declared CIDR."""
    tag = _tag()
    ip = "192.0.2.7"
    cidr = "192.0.2.0/24"
    db = SessionLocal()
    try:
        asset = _mk_ip(db, ip, parent_value=f"host-{tag}.example.com")
        _set_state(db, asset.id)
        _mk_target(db, cidr, TargetType.CIDR, verified=False)
        _set_modes(db, "acknowledge")

        result = _authorise(db, [DiscoveredAsset(asset_type="ip_address", value=ip)],
                            {"domains": [], "ip_ranges": [cidr]})
        assert result.permissions[("ip_address", ip)].allowed is True, _rule_for(result, ip)
    finally:
        db.close()
        _cleanup([ip], [cidr])


def test_ip_resolved_from_a_declared_domain_is_authorised_under_acknowledge():
    """The second half of the bug: an ip_address asset is never a Target row
    in its own right. Containment reaches it through `parent_value` — the
    terminal hostname dns_resolve resolved through."""
    tag = _tag()
    ip = "198.51.100.23"
    domain = f"scope-{tag}.example.com"
    db = SessionLocal()
    try:
        asset = _mk_ip(db, ip, parent_value=f"www.{domain}")
        _set_state(db, asset.id)
        _mk_target(db, domain, TargetType.DOMAIN, verified=False)
        _set_modes(db, "acknowledge")

        result = _authorise(db, [DiscoveredAsset(asset_type="ip_address", value=ip)],
                            {"domains": [domain], "ip_ranges": []})
        assert result.permissions[("ip_address", ip)].allowed is True, _rule_for(result, ip)
    finally:
        db.close()
        _cleanup([ip], [domain])


def test_ip_outside_every_declared_scope_entry_is_denied_under_acknowledge():
    """The gate has to actually deny, or fixing the containment bug would
    just be a permissive rewrite."""
    tag = _tag()
    ip = "203.0.113.99"
    cidr = "192.0.2.0/24"
    db = SessionLocal()
    try:
        asset = _mk_ip(db, ip, parent_value=f"elsewhere-{tag}.example.com")
        _set_state(db, asset.id)
        _mk_target(db, cidr, TargetType.CIDR, verified=False)
        _set_modes(db, "acknowledge")

        result = _authorise(db, [DiscoveredAsset(asset_type="ip_address", value=ip)],
                            {"domains": [], "ip_ranges": [cidr]})
        permission = result.permissions[("ip_address", ip)]
        assert permission.allowed is False
        assert permission.rule_fired == "scope:out_of_scope:acknowledge", permission.rule_fired
    finally:
        db.close()
        _cleanup([ip], [cidr])


# ── mode semantics ───────────────────────────────────────────────────────

def test_disabled_mode_is_permissive_and_costs_no_scope_query():
    """`disabled` is the shipped default and means "adding a target IS the
    authorisation". This slice must not change behaviour for anyone who has
    not opted in."""
    tag = _tag()
    ip = "203.0.113.44"
    db = SessionLocal()
    try:
        asset = _mk_ip(db, ip, parent_value=f"nothing-{tag}.example.com")
        _set_state(db, asset.id)
        _set_modes(db, "disabled")

        # No Target rows at all, empty scope — still allowed.
        result = _authorise(db, [DiscoveredAsset(asset_type="ip_address", value=ip)],
                            {"domains": [], "ip_ranges": []})
        assert result.permissions[("ip_address", ip)].allowed is True
        assert pa._resolve_scoped_ids(db, {"domains": ["x"], "ip_ranges": ["192.0.2.0/24"]}, "disabled") == frozenset()
    finally:
        db.close()
        _cleanup([ip], [])


def test_strict_requires_the_target_to_be_verified():
    tag = _tag()
    ip = "192.0.2.31"
    cidr = "192.0.2.0/24"
    db = SessionLocal()
    try:
        asset = _mk_ip(db, ip, parent_value=f"unverified-{tag}.example.com")
        _set_state(db, asset.id)
        _mk_target(db, cidr, TargetType.CIDR, verified=False)
        _set_modes(db, "strict")

        result = _authorise(db, [DiscoveredAsset(asset_type="ip_address", value=ip)],
                            {"domains": [], "ip_ranges": [cidr]})
        permission = result.permissions[("ip_address", ip)]
        assert permission.allowed is False
        assert permission.rule_fired == "scope:out_of_scope:strict", permission.rule_fired
    finally:
        db.close()
        _cleanup([ip], [cidr])


def test_strict_licenses_every_address_inside_a_VERIFIED_cidr():
    """Narrowing to verified targets happens BEFORE containment. Doing it
    after would be the string-equality bug wearing a different hat — a
    verified CIDR has to license the addresses inside it."""
    tag = _tag()
    ip = "192.0.2.32"
    cidr = "192.0.2.0/24"
    db = SessionLocal()
    try:
        asset = _mk_ip(db, ip, parent_value=f"verified-{tag}.example.com")
        _set_state(db, asset.id)
        _mk_target(db, cidr, TargetType.CIDR, verified=True)
        _set_modes(db, "strict")

        result = _authorise(db, [DiscoveredAsset(asset_type="ip_address", value=ip)],
                            {"domains": [], "ip_ranges": [cidr]})
        assert result.permissions[("ip_address", ip)].allowed is True, _rule_for(result, ip)
    finally:
        db.close()
        _cleanup([ip], [cidr])


def test_an_unrecognised_mode_fails_closed_like_strict():
    """`target_service.is_scan_authorised` treats anything it doesn't
    recognise as strict. The cap stays consistent with it rather than
    inventing a third behaviour for a typo'd setting."""
    tag = _tag()
    ip = "192.0.2.33"
    cidr = "192.0.2.0/24"
    db = SessionLocal()
    try:
        asset = _mk_ip(db, ip, parent_value=f"typo-{tag}.example.com")
        _set_state(db, asset.id)
        _mk_target(db, cidr, TargetType.CIDR, verified=False)
        _set_modes(db, "acknowldge")  # deliberate typo

        result = _authorise(db, [DiscoveredAsset(asset_type="ip_address", value=ip)],
                            {"domains": [], "ip_ranges": [cidr]})
        assert result.permissions[("ip_address", ip)].allowed is False
    finally:
        db.close()
        _cleanup([ip], [cidr])


# ── failure direction ────────────────────────────────────────────────────

def test_unresolved_asset_is_denied_under_a_distinct_rule():
    """An asset with no canonical row cannot be shown to be in scope, and
    "cannot be shown to be in scope" must not read as "is in scope". The
    rule is distinct from out_of_scope because the remedies differ and the
    log-only rollout is read to tell them apart."""
    ip = "192.0.2.77"  # deliberately never seeded as a canonical row
    cidr = "192.0.2.0/24"
    db = SessionLocal()
    try:
        _mk_target(db, cidr, TargetType.CIDR, verified=False)
        _set_modes(db, "acknowledge")

        result = _authorise(db, [DiscoveredAsset(asset_type="ip_address", value=ip)],
                            {"domains": [], "ip_ranges": [cidr]})
        permission = result.permissions[("ip_address", ip)]
        assert permission.allowed is False
        assert permission.rule_fired == "scope:unresolved_asset", permission.rule_fired
    finally:
        db.close()
        _cleanup([ip], [cidr])


def test_scope_denial_is_recorded_in_log_only_mode_too():
    """The whole point of the log-only rollout is that the deny rate is
    readable before anyone flips to enforce. A scope denial that only
    appeared once enforcing was already on would be useless for deciding
    whether enforcing is safe."""
    tag = _tag()
    ip = "203.0.113.55"
    cidr = "192.0.2.0/24"
    db = SessionLocal()
    try:
        asset = _mk_ip(db, ip, parent_value=f"logonly-{tag}.example.com")
        _set_state(db, asset.id)
        _mk_target(db, cidr, TargetType.CIDR, verified=False)
        _set_modes(db, "acknowledge", gate_mode="log_only")

        assets = [DiscoveredAsset(asset_type="ip_address", value=ip)]
        result = _authorise(db, assets, {"domains": [], "ip_ranges": [cidr]})

        # Nothing blocked...
        assert result.enforced is False
        assert len(result.permitted) == 1
        # ...but the real verdict was computed and recorded.
        assert result.permissions[("ip_address", ip)].allowed is False
        row = (
            db.query(AuthorisationDecision)
            .filter(AuthorisationDecision.asset_canonical_id == asset.id)
            .order_by(AuthorisationDecision.decided_at.desc())
            .first()
        )
        assert row is not None and row.allowed is False
    finally:
        db.close()
        _cleanup([ip], [cidr])


def test_scope_cap_never_binds_is_scan_authorised_or_apex_domain():
    """A guard against the fix regressing to the very pairing it replaced.

    Asserts on the module NAMESPACE, not its source text — the docstrings
    discuss both functions at length precisely to explain why they are not
    used, so a source scan would fire on the explanation rather than on a
    real call."""
    assert not hasattr(pa, "is_scan_authorised"), "scope cap must not import is_scan_authorised"
    assert not hasattr(pa, "apex_domain"), "scope cap must not import apex_domain"
    assert not hasattr(pa, "target_service"), "scope cap must not reach for target_service"


if __name__ == "__main__":
    for name, fn in sorted(list(globals().items())):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
    print("all scope cap tests passed")
