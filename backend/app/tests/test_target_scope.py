"""Tests for app.services.target_scope.target_scoped_asset_ids (planning#113,
epic#81 Phase D follow-up L1).

Requires a live DB connection — this exercises real SQLAlchemy queries
across Target/TargetAssetLink/AssetCanonical, not pure logic, so it's an
integration test like test_finding_writer_asset_disambiguation.py and
test_writer_concurrency.py, not a monkeypatched unit test.

Run with:  python -m app.tests.test_target_scope
       or: pytest app/tests/test_target_scope.py
"""

import ipaddress
import uuid

from app.connectors.base import DiscoveredAsset
from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.target import Target, TargetType
from app.services.asset_writer import write_assets
from app.services.target_scope import target_scoped_asset_ids
from app.services.target_service import is_scan_authorised
from app.tests import _docaddr


def _seed_target(db, value: str, target_type: str) -> Target:
    """Delete-then-insert one Target (planning#170, planning#156).

    `Target.value` is globally UNIQUE (uq_targets_value). Several values here
    are constants ("198.51.100.0/28") and the rest come from `_docaddr.alloc()`
    (planning#199), so a row stranded by a run that died before `_cleanup`
    makes the matching INSERT fail on a later run. Deleting first makes the
    seed idempotent, so a dirty exit costs the next run nothing.
    """
    db.query(Target).filter(Target.value == value).delete(synchronize_session=False)
    db.commit()
    target = Target(id=uuid.uuid4(), type=target_type, value=value, verified=True)
    db.add(target)
    db.commit()
    return target


def _mk_domain_target(db, value: str) -> Target:
    return _seed_target(db, value, TargetType.DOMAIN)


def _mk_ip_target(db, value: str, target_type: str = TargetType.IP) -> Target:
    return _seed_target(db, value, target_type)


def _cleanup(db, *, domains: list[str] = (), ips: list[str] = (), target_ids: list[uuid.UUID] = ()):
    if domains:
        db.query(AssetCanonical).filter(AssetCanonical.value.in_(domains)).delete(synchronize_session=False)
        db.query(Target).filter(Target.value.in_(domains)).delete(synchronize_session=False)
    if ips:
        db.query(AssetCanonical).filter(AssetCanonical.value.in_(ips)).delete(synchronize_session=False)
        db.query(Target).filter(Target.value.in_(ips)).delete(synchronize_session=False)
    if target_ids:
        db.query(Target).filter(Target.id.in_(target_ids)).delete(synchronize_session=False)
    db.commit()


def test_leg1_target_asset_link_covers_domain_and_its_resolved_ip():
    """The common shape dns_resolve._emit_assets produces: a domain target's
    discovery batch links BOTH the dns_record and the IP it resolves to
    (asset_writer._link_target_assets links every asset in the batch to
    every target_id passed) — leg 1 alone should already find both."""
    suffix = uuid.uuid4().hex[:10]
    domain = f"target-scope-{suffix}.example.com"
    host = f"www.{domain}"
    ip = "203.0.113.10"

    db = SessionLocal()
    try:
        target = _mk_domain_target(db, domain)
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(asset_type="dns_record", value=host, parent_value=domain,
                             asset_metadata={"record_type": "A", "content": ip}),
            DiscoveredAsset(asset_type="ip_address", value=ip, parent_value=host,
                             asset_metadata={}),
        ], target_ids=[target.id])

        host_asset = db.query(AssetCanonical).filter(AssetCanonical.value == host).one()
        ip_asset = db.query(AssetCanonical).filter(AssetCanonical.value == ip).one()

        ids = target_scoped_asset_ids(db, {"domains": [domain], "ip_ranges": []})
        assert host_asset.id in ids
        assert ip_asset.id in ids
    finally:
        _cleanup(db, domains=[domain, host], ips=[ip])
        db.close()


def test_leg2_apex_walk_covers_assets_with_no_target_asset_link():
    """Belt-and-suspenders leg — assets written WITHOUT threading
    target_ids through (no TargetAssetLink row at all) must still resolve
    via apex/parent_value string matching alone."""
    suffix = uuid.uuid4().hex[:10]
    domain = f"target-scope-{suffix}.example.com"
    host = f"mail.{domain}"
    ip = "203.0.113.11"

    db = SessionLocal()
    try:
        _mk_domain_target(db, domain)
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(asset_type="dns_record", value=host, parent_value=domain,
                             asset_metadata={"record_type": "A", "content": ip}),
            DiscoveredAsset(asset_type="ip_address", value=ip, parent_value=host,
                             asset_metadata={}),
        ])  # no target_ids — no TargetAssetLink rows

        host_asset = db.query(AssetCanonical).filter(AssetCanonical.value == host).one()
        ip_asset = db.query(AssetCanonical).filter(AssetCanonical.value == ip).one()

        ids = target_scoped_asset_ids(db, {"domains": [domain], "ip_ranges": []})
        assert host_asset.id in ids, "dns_record subdomain should match via apex suffix walk"
        assert ip_asset.id in ids, "ip_address should match via parent_value suffix walk"
    finally:
        _cleanup(db, domains=[domain, host], ips=[ip])
        db.close()


def test_unrelated_apex_not_included():
    suffix = uuid.uuid4().hex[:10]
    domain = f"target-scope-{suffix}.example.com"
    other = f"other-{suffix}.example.net"
    ip = "203.0.113.12"

    db = SessionLocal()
    try:
        _mk_domain_target(db, domain)
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(asset_type="dns_record", value=other, parent_value=None,
                             asset_metadata={"record_type": "A", "content": ip}),
        ])

        other_asset = db.query(AssetCanonical).filter(AssetCanonical.value == other).one()
        ids = target_scoped_asset_ids(db, {"domains": [domain], "ip_ranges": []})
        assert other_asset.id not in ids
    finally:
        _cleanup(db, domains=[domain], ips=[])
        db.query(AssetCanonical).filter(AssetCanonical.value == other).delete(synchronize_session=False)
        db.commit()
        db.close()


def test_leg3_bare_ip_target_has_no_target_asset_link_but_is_still_covered():
    """Regression this leg exists specifically to fix (planning#113 Fable
    review, regression 1): an IP/CIDR-scoped target never gets a
    TargetAssetLink row at all (only the domain-discovery loop populates
    that table) — without leg 3, this asset would be silently invisible to
    the whole helper."""
    ip = _docaddr.alloc()

    db = SessionLocal()
    try:
        _mk_ip_target(db, ip, TargetType.IP)
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(asset_type="ip_address", value=ip, parent_value=None, asset_metadata={}),
        ])  # no target_ids — mirrors reality: IP targets never link this way

        ip_asset = db.query(AssetCanonical).filter(AssetCanonical.value == ip).one()
        ids = target_scoped_asset_ids(db, {"domains": [], "ip_ranges": [ip]})
        assert ip_asset.id in ids
    finally:
        _cleanup(db, ips=[ip])
        db.close()


def test_leg3_cidr_containment():
    cidr = "198.51.100.0/28"
    inside_ip = "198.51.100.5"
    outside_ip = "198.51.100.99"

    db = SessionLocal()
    try:
        _mk_ip_target(db, cidr, TargetType.CIDR)
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(asset_type="ip_address", value=inside_ip, parent_value=None, asset_metadata={}),
            DiscoveredAsset(asset_type="ip_address", value=outside_ip, parent_value=None, asset_metadata={}),
        ])

        inside_asset = db.query(AssetCanonical).filter(AssetCanonical.value == inside_ip).one()
        outside_asset = db.query(AssetCanonical).filter(AssetCanonical.value == outside_ip).one()

        assert ipaddress.ip_address(inside_ip) in ipaddress.ip_network(cidr)
        assert ipaddress.ip_address(outside_ip) not in ipaddress.ip_network(cidr)

        ids = target_scoped_asset_ids(db, {"domains": [], "ip_ranges": [cidr]})
        assert inside_asset.id in ids
        assert outside_asset.id not in ids
    finally:
        _cleanup(db, ips=[cidr, inside_ip, outside_ip])
        db.close()


def test_empty_scope_returns_empty_set():
    db = SessionLocal()
    try:
        assert target_scoped_asset_ids(db, {"domains": [], "ip_ranges": []}) == set()
        assert target_scoped_asset_ids(db, {}) == set()
    finally:
        db.close()


def test_is_scan_authorised_ip_resolved_from_a_declared_domain_under_acknowledge():
    """Leg 2 of value_in_target_scope: an ip_address AssetCanonical whose
    parent_value is a subdomain of a declared domain target authorises the
    IP under acknowledge, even though the IP itself is never a declared
    target value (planning#128 step 1)."""
    suffix = uuid.uuid4().hex[:10]
    domain = f"target-scope-{suffix}.example.com"
    host = f"www.{domain}"
    ip = "203.0.113.13"

    db = SessionLocal()
    try:
        _mk_domain_target(db, domain)
        db.add(AssetCanonical(id=uuid.uuid4(), asset_type="ip_address", value=ip, parent_value=host))
        db.commit()

        assert is_scan_authorised(db, ip, "acknowledge") is True
    finally:
        _cleanup(db, domains=[domain], ips=[ip])
        db.close()


def test_is_scan_authorised_ip_inside_a_declared_cidr_under_acknowledge():
    """Leg 3 (arithmetic containment) — no asset row needed, the CIDR
    target alone is enough to authorise every address inside it."""
    cidr = "198.51.100.0/28"
    inside_ip = "198.51.100.5"

    db = SessionLocal()
    try:
        _mk_ip_target(db, cidr, TargetType.CIDR)
        assert is_scan_authorised(db, inside_ip, "acknowledge") is True
    finally:
        _cleanup(db, ips=[cidr])
        db.close()


def test_is_scan_authorised_subdomain_of_a_declared_apex_under_acknowledge():
    suffix = uuid.uuid4().hex[:10]
    domain = f"target-scope-{suffix}.example.com"

    db = SessionLocal()
    try:
        _mk_domain_target(db, domain)
        assert is_scan_authorised(db, f"api.{domain}", "acknowledge") is True
    finally:
        _cleanup(db, domains=[domain])
        db.close()


def test_is_scan_authorised_value_outside_all_scope_is_denied_under_acknowledge():
    suffix = uuid.uuid4().hex[:10]
    domain = f"target-scope-{suffix}.example.com"
    cidr = "198.51.100.0/28"
    outside_ip = "198.51.100.99"
    outside_name = f"outside-{suffix}.example.com"

    db = SessionLocal()
    try:
        _mk_domain_target(db, domain)
        _mk_ip_target(db, cidr, TargetType.CIDR)
        assert is_scan_authorised(db, outside_ip, "acknowledge") is False
        assert is_scan_authorised(db, outside_name, "acknowledge") is False
    finally:
        _cleanup(db, domains=[domain], ips=[cidr])
        db.close()


def test_is_scan_authorised_disabled_is_permissive():
    """`disabled` must short-circuit before any query — passing `None` as
    `db` proves it never touches the session."""
    assert is_scan_authorised(None, "anything.example.com", "disabled") is True


def test_is_scan_authorised_strict_requires_verification():
    cidr = "198.51.100.0/28"
    inside_ip = "198.51.100.5"

    db = SessionLocal()
    try:
        target = _mk_ip_target(db, cidr, TargetType.CIDR)
        target.verified = False
        db.commit()

        assert is_scan_authorised(db, inside_ip, "strict") is False
        assert is_scan_authorised(db, inside_ip, "acknowledge") is True
    finally:
        _cleanup(db, ips=[cidr])
        db.close()


def test_is_scan_authorised_strict_licenses_every_address_inside_a_verified_cidr():
    cidr = "198.51.100.0/28"
    inside_ip = "198.51.100.6"

    db = SessionLocal()
    try:
        _mk_ip_target(db, cidr, TargetType.CIDR)  # _seed_target: verified=True
        assert is_scan_authorised(db, inside_ip, "strict") is True
    finally:
        _cleanup(db, ips=[cidr])
        db.close()


def test_is_scan_authorised_unrecognised_mode_fails_closed_like_strict():
    cidr = "198.51.100.0/28"
    inside_ip = "198.51.100.7"

    db = SessionLocal()
    try:
        target = _mk_ip_target(db, cidr, TargetType.CIDR)
        target.verified = False
        db.commit()
        assert is_scan_authorised(db, inside_ip, "banana") is False

        target.verified = True
        db.commit()
        assert is_scan_authorised(db, inside_ip, "banana") is True
    finally:
        _cleanup(db, ips=[cidr])
        db.close()


def test_is_scan_authorised_normalises_case_and_trailing_dot():
    """Dropping the `apex_domain()` wrapper at the call sites also dropped
    the case-folding and trailing-dot stripping it did on the way past.
    `value_in_target_scope` reproduces it deliberately — both of these
    authorised under the old path and must keep authorising, or the fix
    would have traded one silent skip for another (planning#128 step 1)."""
    suffix = uuid.uuid4().hex[:10]
    domain = f"target-scope-{suffix}.example.com"

    db = SessionLocal()
    try:
        _mk_domain_target(db, domain)
        assert is_scan_authorised(db, f"API.{domain.upper()}", "acknowledge") is True
        assert is_scan_authorised(db, f"api.{domain}.", "acknowledge") is True
        assert is_scan_authorised(db, f"  api.{domain}  ", "acknowledge") is True
        # The declared value itself, mixed case.
        assert is_scan_authorised(db, domain.upper(), "acknowledge") is True
        # Normalisation must not turn an out-of-scope name into an in-scope one.
        assert is_scan_authorised(db, f"NOT{domain}", "acknowledge") is False
    finally:
        _cleanup(db, domains=[domain])
        db.close()


def _run():
    tests = [
        test_leg1_target_asset_link_covers_domain_and_its_resolved_ip,
        test_leg2_apex_walk_covers_assets_with_no_target_asset_link,
        test_unrelated_apex_not_included,
        test_leg3_bare_ip_target_has_no_target_asset_link_but_is_still_covered,
        test_leg3_cidr_containment,
        test_empty_scope_returns_empty_set,
        test_is_scan_authorised_ip_resolved_from_a_declared_domain_under_acknowledge,
        test_is_scan_authorised_ip_inside_a_declared_cidr_under_acknowledge,
        test_is_scan_authorised_subdomain_of_a_declared_apex_under_acknowledge,
        test_is_scan_authorised_value_outside_all_scope_is_denied_under_acknowledge,
        test_is_scan_authorised_disabled_is_permissive,
        test_is_scan_authorised_strict_requires_verification,
        test_is_scan_authorised_strict_licenses_every_address_inside_a_verified_cidr,
        test_is_scan_authorised_unrecognised_mode_fails_closed_like_strict,
        test_is_scan_authorised_normalises_case_and_trailing_dot,
    ]
    for fn in tests:
        try:
            fn()
            print(f"OK: {fn.__name__}")
        except AssertionError as exc:
            print(f"FAIL: {fn.__name__}: {exc}")
            raise SystemExit(1)
    print("ALL PASS")


if __name__ == "__main__":
    _run()
