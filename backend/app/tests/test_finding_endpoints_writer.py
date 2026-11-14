"""`write_findings` records where each finding was observed (planning#347):
one `finding_endpoints` row per (finding, address, port, protocol), NULLs
compared as equal, re-observation only moving `last_seen_at`, and every part
validated rather than repaired.

Integration test against the throwaway `constellus_test` database. Synthetic
data only. Time is controlled by replacing `finding_writer.datetime`, so the
two writes of a re-observation get distinct, known `now` values.

Run with:  backend/scripts/test.sh app/tests/test_finding_endpoints_writer.py
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import insert
from sqlalchemy.exc import IntegrityError

from app.connectors.base import DiscoveredAsset, DiscoveredFinding, ObservedEndpoint
from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.asset_edge import AssetEdge
from app.models.finding_canonical import FindingCanonical
from app.models.finding_endpoint import FindingEndpoint
from app.services import finding_writer
from app.services.asset_writer import write_assets
from app.services.finding_writer import write_findings
from app.tests import _docaddr

T0 = datetime(2020, 1, 1, 12, 0, tzinfo=timezone.utc)
T1 = T0 + timedelta(days=1)

V6_COMPRESSED = "2001:db8::1"
V6_EXPANDED = "2001:0db8:0000:0000:0000:0000:0000:0001"


_ADDRS: list[str] = []
_CIDR: list[str] = []


def _a(i: int) -> str:
    """The module's i-th documentation address, drawn on first use and reused
    (the shared `_docaddr` pool is small). Setup purges by value first and
    every test cleans up after itself."""
    while len(_ADDRS) <= i:
        _ADDRS.append(_docaddr.alloc())
    return _ADDRS[i]


def _purge(db, values: list[str]) -> None:
    db.rollback()
    asset_ids = [r[0] for r in db.query(AssetCanonical.id).filter(AssetCanonical.value.in_(values))]
    finding_ids = [
        r[0] for r in db.query(FindingCanonical.id).filter(FindingCanonical.asset_canonical_id.in_(asset_ids))
    ]
    if finding_ids:
        db.query(AssetEdge).filter(AssetEdge.target_id.in_(finding_ids)).delete(synchronize_session=False)
    if asset_ids:
        db.query(AssetEdge).filter(AssetEdge.source_id.in_(asset_ids)).delete(synchronize_session=False)
        db.query(AssetEdge).filter(AssetEdge.target_id.in_(asset_ids)).delete(synchronize_session=False)
    db.query(FindingCanonical).filter(FindingCanonical.id.in_(finding_ids)).delete(synchronize_session=False)
    db.query(AssetCanonical).filter(AssetCanonical.id.in_(asset_ids)).delete(synchronize_session=False)
    db.commit()


class _Clock:
    """Stands in for the `datetime` name inside finding_writer."""

    def __init__(self, t: datetime):
        self.t = t

    def now(self, tz=None):
        return self.t


@pytest.fixture
def clock(monkeypatch):
    c = _Clock(T0)
    monkeypatch.setattr(finding_writer, "datetime", c)
    return c


class _World:
    def __init__(self):
        self.db = SessionLocal()
        self.asset_values: list[str] = []

    def ip_asset(self, value: str | None = None) -> str:
        value = value or _a(0)
        self.asset_values.append(value)
        _purge(self.db, [value])
        write_assets(self.db, uuid.uuid4(), [DiscoveredAsset(asset_type="ip_address", value=value, parent_value=None)])
        return value

    def finding(self, asset_value, endpoints, fingerprint="fp-1") -> DiscoveredFinding:
        return DiscoveredFinding(
            asset_value=asset_value, finding_type="exposed_service", source="constellus",
            severity="low", title="t", description="d",
            detail={"fingerprint": fingerprint}, endpoints=list(endpoints),
        )

    def write(self, *findings: DiscoveredFinding):
        return write_findings(self.db, uuid.uuid4(), list(findings))

    def finding_rows(self, asset_value) -> list[FindingCanonical]:
        self.db.expire_all()
        return (
            self.db.query(FindingCanonical)
            .join(AssetCanonical, AssetCanonical.id == FindingCanonical.asset_canonical_id)
            .filter(AssetCanonical.value == asset_value)
            .all()
        )

    def endpoint_rows(self, finding_id) -> list[FindingEndpoint]:
        self.db.expire_all()
        return self.db.query(FindingEndpoint).filter(FindingEndpoint.finding_id == finding_id).all()

    def one_finding(self, asset_value) -> FindingCanonical:
        rows = self.finding_rows(asset_value)
        assert len(rows) == 1, f"expected the finding row to exist exactly once, got {len(rows)}"
        return rows[0]

    def shapes(self, finding_id) -> list[tuple]:
        return sorted(
            ((None if r.address is None else str(r.address)), r.port, r.protocol)
            for r in self.endpoint_rows(finding_id)
        )

    def cleanup(self):
        try:
            _purge(self.db, self.asset_values)
        finally:
            self.db.close()


@pytest.fixture
def world():
    w = _World()
    try:
        yield w
    finally:
        w.cleanup()


# 1 ------------------------------------------------------------------------


def test_one_finding_two_endpoints_two_rows(world, clock):
    asset = world.ip_asset()
    other = _a(1)
    world.write(world.finding(asset, [
        ObservedEndpoint(address=asset, port=80, protocol="tcp"),
        ObservedEndpoint(address=other, port=53, protocol="udp"),
    ]))
    f = world.one_finding(asset)
    rows = world.endpoint_rows(f.id)
    assert len(rows) == 2
    assert world.shapes(f.id) == sorted([(asset, 80, "tcp"), (other, 53, "udp")])
    for r in rows:
        assert r.first_seen_at == r.last_seen_at == T0


# 2 ------------------------------------------------------------------------


def test_reobserving_the_same_endpoint_moves_only_last_seen(world, clock):
    asset = world.ip_asset()
    ep = ObservedEndpoint(address=asset, port=443, protocol="tcp")
    world.write(world.finding(asset, [ep]))
    f = world.one_finding(asset)
    (first,) = world.endpoint_rows(f.id)
    assert first.last_seen_at == T0

    clock.t = T1
    world.write(world.finding(asset, [ep]))
    assert world.one_finding(asset).last_seen_at == T1, "second write did not reach the finding"
    rows = world.endpoint_rows(f.id)
    assert len(rows) == 1
    assert rows[0].id == first.id
    assert rows[0].first_seen_at == T0
    assert rows[0].last_seen_at == T1


# 3 ------------------------------------------------------------------------


def test_reobserving_with_a_different_endpoint_keeps_the_old_one_stale(world, clock):
    asset = world.ip_asset()
    old = ObservedEndpoint(address=asset, port=80, protocol="tcp")
    new = ObservedEndpoint(address=asset, port=8080, protocol="tcp")
    world.write(world.finding(asset, [old]))
    clock.t = T1
    world.write(world.finding(asset, [new]))

    f = world.one_finding(asset)
    assert f.last_seen_at == T1
    by_port = {r.port: r for r in world.endpoint_rows(f.id)}
    assert sorted(by_port) == [80, 8080]
    assert by_port[80].first_seen_at == by_port[80].last_seen_at == T0
    assert by_port[8080].first_seen_at == by_port[8080].last_seen_at == T1


# 4 ------------------------------------------------------------------------


def test_in_batch_duplicates_union_their_endpoints(world, clock):
    asset = world.ip_asset()
    a = world.finding(asset, [ObservedEndpoint(address=asset, port=80, protocol="tcp")])
    b = world.finding(asset, [ObservedEndpoint(address=asset, port=81, protocol="tcp")])
    world.write(a, b)
    f = world.one_finding(asset)
    assert world.shapes(f.id) == [(asset, 80, "tcp"), (asset, 81, "tcp")]


# 5 ------------------------------------------------------------------------


def test_null_parts_compare_equal_address_only(world, clock):
    asset = world.ip_asset()
    ep = ObservedEndpoint(address=asset)
    world.write(world.finding(asset, [ep]))
    clock.t = T1
    world.write(world.finding(asset, [ep]))
    f = world.one_finding(asset)
    assert f.last_seen_at == T1
    rows = world.endpoint_rows(f.id)
    assert len(rows) == 1
    assert (str(rows[0].address), rows[0].port, rows[0].protocol) == (asset, None, None)
    assert rows[0].last_seen_at == T1


def test_null_parts_compare_equal_port_only(world, clock):
    asset = world.ip_asset()
    ep = ObservedEndpoint(port=8443)
    world.write(world.finding(asset, [ep]))
    clock.t = T1
    world.write(world.finding(asset, [ep]))
    f = world.one_finding(asset)
    assert f.last_seen_at == T1
    rows = world.endpoint_rows(f.id)
    assert len(rows) == 1
    assert (rows[0].address, rows[0].port, rows[0].protocol) == (None, 8443, None)
    assert rows[0].first_seen_at == T0 and rows[0].last_seen_at == T1


# 6 ------------------------------------------------------------------------

_IP = "IP"  # placeholder, replaced by the module's asset address
_V6_NET = "2001:db8::/32"

_NORMALISATION = [
    # id, address, port, protocol, expected (address, port, protocol); None = no row
    ("port-true-with-address", _IP, True, None, (_IP, None, None)),
    ("port-zero-with-address", _IP, 0, None, (_IP, None, None)),
    ("port-65536-with-address", _IP, 65536, None, (_IP, None, None)),
    ("port-str-with-address", _IP, "443", None, (_IP, None, None)),
    ("port-true-alone", None, True, None, None),
    ("port-zero-alone", None, 0, None, None),
    ("port-65536-alone", None, 65536, None, None),
    ("port-str-alone", None, "443", None, None),
    ("port-1", _IP, 1, None, (_IP, 1, None)),
    ("port-65535", _IP, 65535, None, (_IP, 65535, None)),
    ("protocol-upper", _IP, 80, "TCP", (_IP, 80, "tcp")),
    ("protocol-padded", _IP, 80, " udp ", (_IP, 80, "udp")),
    ("protocol-http", _IP, 80, "http", (_IP, 80, None)),
    ("protocol-empty", _IP, 80, "", (_IP, 80, None)),
    ("address-garbage-with-port", "not-an-ip", 80, None, (None, 80, None)),
    ("address-empty-with-port", "", 80, None, (None, 80, None)),
    ("address-cidr-with-port", _V6_NET, 80, None, (None, 80, None)),
    ("address-garbage-alone", "not-an-ip", None, None, None),
    ("address-empty-alone", "", None, None, None),
    ("address-cidr-alone", _V6_NET, None, None, None),
    ("protocol-only", None, None, "tcp", None),
]


@pytest.mark.parametrize(
    "address,port,protocol,expected",
    [pytest.param(a, p, pr, e, id=i) for i, a, p, pr, e in _NORMALISATION],
)
def test_normalisation(world, clock, address, port, protocol, expected):
    asset = world.ip_asset()
    address = asset if address == _IP else address
    if expected is not None:
        expected = (asset if expected[0] == _IP else expected[0], expected[1], expected[2])
    world.write(world.finding(asset, [ObservedEndpoint(address=address, port=port, protocol=protocol)]))
    f = world.one_finding(asset)  # the finding exists whether or not an endpoint does
    assert world.shapes(f.id) == ([] if expected is None else [expected])


# 7 ------------------------------------------------------------------------


def test_same_ipv6_address_in_two_spellings_is_one_row(world, clock):
    asset = world.ip_asset()
    world.write(world.finding(asset, [
        ObservedEndpoint(address=V6_COMPRESSED, port=443, protocol="tcp"),
        ObservedEndpoint(address=V6_EXPANDED, port=443, protocol="tcp"),
    ]))
    f = world.one_finding(asset)
    assert world.shapes(f.id) == [(V6_COMPRESSED, 443, "tcp")]


# 8 ------------------------------------------------------------------------


def test_unresolvable_asset_writes_nothing(world, clock):
    ghost = f"ghost-{uuid.uuid4().hex[:10]}.example.com"
    control = world.ip_asset()
    before = world.db.query(FindingEndpoint).count()
    # the control write proves the writer ran and stored an endpoint in this very call
    result = world.write(
        world.finding(ghost, [ObservedEndpoint(port=80)]),
        world.finding(control, [ObservedEndpoint(address=control)]),
    )
    assert len(result) == 1
    assert world.finding_rows(ghost) == []
    assert world.db.query(AssetCanonical).filter(AssetCanonical.value == ghost).count() == 0
    c = world.one_finding(control)
    assert world.shapes(c.id) == [(control, None, None)]
    assert world.db.query(FindingEndpoint).count() == before + 1, "only the control finding's endpoint may be added"


# 9 ------------------------------------------------------------------------


def test_deleting_the_finding_deletes_its_endpoints(world, clock):
    asset = world.ip_asset()
    world.write(world.finding(asset, [
        ObservedEndpoint(address=asset, port=80), ObservedEndpoint(address=asset, port=81)]))
    f = world.one_finding(asset)
    fid = f.id
    assert len(world.endpoint_rows(fid)) == 2
    world.db.query(FindingCanonical).filter(FindingCanonical.id == fid).delete(synchronize_session=False)
    world.db.commit()
    assert world.finding_rows(asset) == []
    assert world.endpoint_rows(fid) == []


# 10 -----------------------------------------------------------------------


def _insert(db, finding_id, **over):
    values = {"finding_id": finding_id, "address": None, "port": None, "protocol": None,
              "first_seen_at": T0, "last_seen_at": T0}
    values.update(over)
    db.execute(insert(FindingEndpoint.__table__).values(**values))


def _constraint_violated(db, finding_id, **over) -> str:
    with pytest.raises(IntegrityError) as exc:
        _insert(db, finding_id, **over)
    db.rollback()
    return exc.value.orig.diag.constraint_name


def test_database_constraints_reject_bad_rows(world, clock):
    asset = world.ip_asset()
    world.write(world.finding(asset, []))
    fid = world.one_finding(asset).id
    ip = _a(1)
    if not _CIDR:
        _CIDR.append(_docaddr.alloc_cidr()[0])
    v4_net = _CIDR[0]

    # control: a valid row inserts, so each rejection below is about its one bad part
    _insert(world.db, fid, address=ip, port=80, protocol="tcp")
    world.db.commit()
    assert world.shapes(fid) == [(ip, 80, "tcp")]

    name = _constraint_violated
    assert name(world.db, fid) == "ck_finding_endpoints_address_or_port"
    assert name(world.db, fid, protocol="tcp") == "ck_finding_endpoints_address_or_port"
    assert name(world.db, fid, address=v4_net) == "ck_finding_endpoints_address_is_host"
    assert name(world.db, fid, address=_V6_NET) == "ck_finding_endpoints_address_is_host"
    assert name(world.db, fid, address=ip, port=0) == "ck_finding_endpoints_port_range"
    assert name(world.db, fid, address=ip, port=65536) == "ck_finding_endpoints_port_range"
    assert name(world.db, fid, address=ip, protocol="http") == "ck_finding_endpoints_protocol"
    assert name(world.db, fid, address=ip, first_seen_at=T1, last_seen_at=T0) == \
        "ck_finding_endpoints_last_after_first"
    # and the unique constraint treats NULLs as equal
    assert name(world.db, fid, address=ip, port=80, protocol="tcp") == "uq_finding_endpoints_endpoint"
    _insert(world.db, fid, address=ip)
    world.db.commit()
    assert name(world.db, fid, address=ip) == "uq_finding_endpoints_endpoint"
    assert len(world.endpoint_rows(fid)) == 2


# 11 -----------------------------------------------------------------------


def test_more_endpoints_than_one_insert_chunk_are_all_stored(world, clock, monkeypatch):
    monkeypatch.setattr(finding_writer, "_ENDPOINT_INSERT_CHUNK", 3)
    asset = world.ip_asset()
    ports = list(range(1000, 1008))
    world.write(world.finding(asset, [ObservedEndpoint(address=asset, port=p, protocol="tcp") for p in ports]))
    f = world.one_finding(asset)
    assert [r.port for r in sorted(world.endpoint_rows(f.id), key=lambda r: r.port)] == ports
