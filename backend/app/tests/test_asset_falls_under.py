"""`target_scope.asset_falls_under`: the one predicate behind both read scope
and the LLM-scope resolver, exercised through `finding_writeup._targets_for_assets`
(planning#261). One case per behaviour; each builds the asset and the targets
it names and asserts exactly which targets it falls under.
"""

import uuid
from datetime import datetime, timezone

import pytest

from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.target import Target
from app.models.target_asset_link import TargetAssetLink
from app.services import finding_writeup as fw


def _tag() -> str:
    return uuid.uuid4().hex[:8]


@pytest.fixture
def db():
    s = SessionLocal()
    made = {"assets": [], "targets": []}
    s.made = made
    yield s
    s.rollback()
    try:
        if made["targets"]:
            s.query(TargetAssetLink).filter(TargetAssetLink.target_id.in_(made["targets"])).delete(
                synchronize_session=False)
            s.query(Target).filter(Target.id.in_(made["targets"])).delete(synchronize_session=False)
        if made["assets"]:
            s.query(AssetCanonical).filter(AssetCanonical.id.in_(made["assets"])).delete(synchronize_session=False)
        s.commit()
    finally:
        s.close()


def _asset(db, value, asset_type="dns_record", parent_value=None) -> AssetCanonical:
    now = datetime.now(timezone.utc)
    a = AssetCanonical(id=uuid.uuid4(), asset_type=asset_type, value=value, parent_value=parent_value,
                       tags=[], first_seen_at=now, last_seen_at=now, ignored=False)
    db.add(a)
    db.flush()
    db.made["assets"].append(a.id)
    return a


def _target(db, type_, value) -> Target:
    t = Target(id=uuid.uuid4(), type=type_, value=value)
    db.add(t)
    db.flush()
    db.made["targets"].append(t.id)
    return t


def _under(db, asset) -> set[uuid.UUID]:
    return {t.id for t in fw._targets_for_assets(db, [asset])[asset.id]}


def test_link_only_asset_falls_under_its_linked_target(db):
    t = _target(db, "domain", f"link-{_tag()}.example.com")
    other = _target(db, "domain", f"other-{_tag()}.example.com")
    a = _asset(db, f"unrelated-{_tag()}.example.org")
    now = datetime.now(timezone.utc)
    db.add(TargetAssetLink(target_id=t.id, asset_canonical_id=a.id, first_linked_at=now, last_observed_at=now))
    db.flush()
    assert _under(db, a) == {t.id}
    assert other.id not in _under(db, a)


def test_domain_exact_subdomain_and_parent_value(db):
    d = f"dom-{_tag()}.example.com"
    t = _target(db, "domain", d)
    assert _under(db, _asset(db, d)) == {t.id}
    assert _under(db, _asset(db, f"www.{d}")) == {t.id}
    assert _under(db, _asset(db, f"a.b.{d}")) == {t.id}
    # a name elsewhere whose parent_value is under the domain
    assert _under(db, _asset(db, f"elsewhere-{_tag()}.example.org", parent_value=f"x.{d}")) == {t.id}
    assert _under(db, _asset(db, f"elsewhere-{_tag()}.example.org", parent_value=d)) == {t.id}


def test_case_and_trailing_dot_are_normalised_on_both_sides(db):
    d = f"case-{_tag()}.example.com"
    t = _target(db, "domain", d.upper() + ".")
    assert _under(db, _asset(db, f"WWW.{d.upper()}.")) == {t.id}
    assert _under(db, _asset(db, d + ".")) == {t.id}


def test_boundary_is_a_label_boundary(db):
    d = f"bound-{_tag()}.example.com"
    t = _target(db, "domain", d)
    assert _under(db, _asset(db, f"bad{d}")) == set()
    assert _under(db, _asset(db, f"www.{d}")) == {t.id}  # the same fixture does match when it should


def test_underscore_is_literal_not_a_like_wildcard(db):
    tag = _tag()
    t = _target(db, "domain", f"a_b{tag}.example.com")
    assert _under(db, _asset(db, f"axb{tag}.example.com")) == set()
    assert _under(db, _asset(db, f"a_b{tag}.example.com")) == {t.id}  # reached: the literal does match


def test_ipv4_in_cidr_target(db):
    t = _target(db, "cidr", "192.0.2.0/24")
    assert t.id in _under(db, _asset(db, "192.0.2.77", "ip_address"))
    assert t.id not in _under(db, _asset(db, "198.51.100.77", "ip_address"))


def test_non_strict_ip_target_contains_its_network(db):
    t = _target(db, "cidr", "192.0.2.5/24")
    assert t.id in _under(db, _asset(db, "192.0.2.7", "ip_address"))


def test_bare_ip_target_equals_the_asset(db):
    t = _target(db, "ip", "192.0.2.201")
    assert t.id in _under(db, _asset(db, "192.0.2.201", "ip_address"))
    assert t.id not in _under(db, _asset(db, "192.0.2.202", "ip_address"))


def test_ipv6_in_cidr_target(db):
    t = _target(db, "cidr", "2001:db8::/32")
    assert t.id in _under(db, _asset(db, "2001:db8::1", "ip_address"))
    assert t.id not in _under(db, _asset(db, "2001:db9::1", "ip_address"))


def test_mixed_families_never_match(db):
    t6 = _target(db, "cidr", "2001:db8::/32")
    t4 = _target(db, "cidr", "192.0.2.0/24")
    v4 = _asset(db, "192.0.2.9", "ip_address")
    assert t6.id not in _under(db, v4) and t4.id in _under(db, v4)
    v6 = _asset(db, "2001:db8::9", "ip_address")
    assert t4.id not in _under(db, v6) and t6.id in _under(db, v6)


def test_asset_value_with_a_prefix_length_is_not_an_address(db):
    t = _target(db, "cidr", "192.0.2.0/24")
    assert t.id not in _under(db, _asset(db, "192.0.2.1/32", "ip_address"))


def test_target_that_is_not_an_address_matches_nothing_and_raises_nothing(db):
    bad = _target(db, "cidr", "not-an-ip")
    a = _asset(db, "192.0.2.50", "ip_address")
    assert bad.id not in _under(db, a)  # reached: the query ran against the bad row without error


def test_dns_record_with_an_ip_looking_value_gets_no_cidr_match(db):
    t = _target(db, "cidr", "192.0.2.0/24")
    assert t.id not in _under(db, _asset(db, "192.0.2.60", "dns_record"))
    assert t.id in _under(db, _asset(db, "192.0.2.60", "ip_address"))  # same value, right type
