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


def _mk_domain_target(db, value: str) -> Target:
    target = Target(id=uuid.uuid4(), type=TargetType.DOMAIN, value=value, verified=True)
    db.add(target)
    db.commit()
    return target


def _mk_ip_target(db, value: str, target_type: str = TargetType.IP) -> Target:
    target = Target(id=uuid.uuid4(), type=target_type, value=value, verified=True)
    db.add(target)
    db.commit()
    return target


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
    suffix = uuid.uuid4().hex[:6]
    ip = f"198.51.100.{20 + int(suffix, 16) % 50}"

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


def _run():
    tests = [
        test_leg1_target_asset_link_covers_domain_and_its_resolved_ip,
        test_leg2_apex_walk_covers_assets_with_no_target_asset_link,
        test_unrelated_apex_not_included,
        test_leg3_bare_ip_target_has_no_target_asset_link_but_is_still_covered,
        test_leg3_cidr_containment,
        test_empty_scope_returns_empty_set,
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
