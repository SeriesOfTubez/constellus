"""The exposure path of a finding, through `GET /api/findings/{id}` (planning#347).

Integration test against the throwaway `constellus_test` database, as an admin
(read scope is covered by test_read_scope_api.py). Findings are written with
`finding_writer.write_findings` shaped as each real producer emits them;
hostnames and their DNS edges go through `write_assets`, the real writer. The
one exception: an address asset's port inventory is an `asset_state` row
inserted directly, because only the projector writes it and it has no producer
this test can run.

Synthetic data only: hostnames under example.org with a module-unique label,
addresses from `_docaddr` (six at most, drawn lazily and reused).

Run with:  backend/scripts/test.sh app/tests/test_exposure_path.py
"""

import ipaddress
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.connectors.base import DiscoveredAsset, DiscoveredFinding, ObservedEndpoint
from app.core.database import SessionLocal
from app.main import app
from app.models.asset_canonical import AssetCanonical
from app.models.asset_edge import AssetEdge
from app.models.asset_state import AssetState
from app.models.finding_canonical import FindingCanonical
from app.models.user import User
from app.schemas.exposure_path import ExposurePath
from app.services import exposure_path, finding_writer
from app.services.asset_writer import write_assets
from app.services.exposure_path import (
    EXTERNAL_SOURCES,
    _DERIVED_ADDRESSES,
    _DERIVED_HOSTNAMES,
    _NO_ADDRESS,
    _NO_HOSTNAME,
    _NO_INVENTORY_ENTRY,
)
from app.services.finding_writer import write_findings
from app.tests import _docaddr
from app.tests.test_edgar_ingest_api import _cleanup_user, _make_user

client = TestClient(app)

T0 = datetime(2020, 1, 1, 12, 0, tzinfo=timezone.utc)
T1 = T0 + timedelta(days=1)

_LABEL = f"xp-{uuid.uuid4().hex[:8]}.example.org"
_ADDRS: list[str] = []


def _a(i: int) -> str:
    """The module's i-th documentation address, drawn on first use and reused
    (the shared `_docaddr` pool is small). Setup purges by value first and
    every test cleans up after itself."""
    while len(_ADDRS) <= i:
        _ADDRS.append(_docaddr.alloc())
    return _ADDRS[i]


def _n(label: str) -> str:
    return f"{label}.{_LABEL}"


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


@pytest.fixture(scope="module")
def admin():
    headers, uid = _make_user("admin")
    yield headers
    _cleanup_user(uid)


class _World:
    def __init__(self):
        self.db = SessionLocal()
        self.values: list[str] = []
        self._fp = 0

    def assets(self, *, addresses=(), records=()):
        """Purge by value, then write through the real writer. `records` are
        (name, record_type, content) dns_record rows."""
        names = {r[0] for r in records}
        self.values.extend(list(addresses) + sorted(names))
        _purge(self.db, list(addresses) + sorted(names))
        batch = [DiscoveredAsset(asset_type="ip_address", value=v, parent_value=None) for v in addresses]
        batch += [
            DiscoveredAsset(asset_type="dns_record", value=n, parent_value=None,
                            asset_metadata={"record_type": rt, "content": c})
            for n, rt, c in records
        ]
        write_assets(self.db, uuid.uuid4(), batch)

    def asset_id(self, asset_type: str, value: str) -> uuid.UUID:
        self.db.expire_all()
        row = self.db.query(AssetCanonical).filter(
            AssetCanonical.asset_type == asset_type, AssetCanonical.value == value).one()
        return row.id

    def inventory(self, address: str, ports: list[dict]) -> None:
        """Direct `asset_state` upsert (see module docstring)."""
        aid = self.asset_id("ip_address", address)
        self.db.query(AssetState).filter(AssetState.asset_canonical_id == aid).delete(synchronize_session=False)
        self.db.add(AssetState(asset_canonical_id=aid, open_ports=ports, projected_at=T0))
        self.db.commit()

    def finding(self, asset_value, endpoints, *, source="constellus", finding_type="exposed_service",
                fingerprint=None) -> DiscoveredFinding:
        self._fp += 1
        return DiscoveredFinding(
            asset_value=asset_value, finding_type=finding_type, source=source,
            severity="low", title="t", description="d",
            detail={"fingerprint": fingerprint or f"fp-{self._fp}"}, endpoints=list(endpoints),
        )

    def write(self, *findings: DiscoveredFinding) -> list[uuid.UUID]:
        write_findings(self.db, uuid.uuid4(), list(findings))
        return [self.finding_id(f) for f in findings]

    def finding_id(self, f: DiscoveredFinding) -> uuid.UUID:
        self.db.expire_all()
        row = (
            self.db.query(FindingCanonical)
            .join(AssetCanonical, AssetCanonical.id == FindingCanonical.asset_canonical_id)
            .filter(AssetCanonical.value == f.asset_value, FindingCanonical.source == f.source,
                    FindingCanonical.finding_type == f.finding_type,
                    FindingCanonical.fingerprint == f.detail["fingerprint"])
            .one()
        )
        return row.id

    def cleanup(self):
        try:
            _purge(self.db, self.values)
        finally:
            self.db.close()


@pytest.fixture
def world():
    w = _World()
    try:
        yield w
    finally:
        w.cleanup()


def _detail(admin, finding_id) -> dict:
    r = client.get(f"/api/findings/{finding_id}", headers=admin)
    assert r.status_code == 200, r.text
    return r.json()


def _paths(admin, finding_id) -> list[ExposurePath]:
    body = _detail(admin, finding_id)
    return [ExposurePath.model_validate(p) for p in body["exposure_paths"]]


def _hops(path: ExposurePath) -> dict:
    assert [h.kind for h in path.hops] == ["internet", "host", "address", "port", "service", "finding"]
    return {h.kind: h for h in path.hops}


def _one(admin, finding_id) -> tuple[ExposurePath, dict]:
    paths = _paths(admin, finding_id)
    assert len(paths) == 1
    return paths[0], _hops(paths[0])


def _port(port, protocol="tcp", service="http", version="1.2", sources=("naabu", "httpx")) -> dict:
    return {"port": port, "protocol": protocol, "sources": list(sources), "last_seen_at": T0.isoformat(),
            "service": service, "service_version": version}


# 1 ------------------------------------------------------------------------


def test_version_match_on_address_walks_every_hop(world, admin):
    ip = _a(0)
    world.assets(addresses=[ip])
    world.inventory(ip, [_port(443, "tcp", "nginx", "1.18.0")])
    (fid,) = world.write(world.finding(
        ip, [ObservedEndpoint(address=ip, port=443, protocol="tcp")],
        source="version_match", finding_type="cve"))
    ip_id = world.asset_id("ip_address", ip)

    path, h = _one(admin, fid)
    assert path.observation == "current"
    assert path.endpoint_id is not None
    assert h["internet"].status == "observed" and h["internet"].sources == ["version_match"]
    assert h["address"].status == "observed" and h["address"].address == ip and h["address"].asset_id == ip_id
    assert h["address"].sources == ["version_match"]
    assert (h["port"].status, h["port"].port, h["port"].protocol, h["port"].reason) == ("observed", 443, "tcp", None)
    assert h["service"].status == "observed"
    assert (h["service"].service, h["service"].version) == ("nginx", "1.18.0")
    assert h["service"].sources == ["naabu", "httpx"]
    assert h["service"].asset_id == ip_id and h["service"].protocol == "tcp"
    assert h["finding"].status == "observed" and h["finding"].finding_id == fid
    assert h["finding"].finding_type == "cve" and h["finding"].sources == ["version_match"]


# 2 ------------------------------------------------------------------------


def test_address_with_no_hostname_has_unknown_host_hop(world, admin):
    ip = _a(0)
    world.assets(addresses=[ip])
    (fid,) = world.write(world.finding(ip, [ObservedEndpoint(address=ip, port=443, protocol="tcp")]))
    _, h = _one(admin, fid)
    assert h["address"].status == "observed"  # the path reached the address hop
    assert h["host"].status == "unknown"
    assert h["host"].reason == _NO_HOSTNAME
    assert h["host"].candidates == []


# 3 ------------------------------------------------------------------------


def test_exposed_service_without_protocol_keeps_it_null(world, admin):
    ip = _a(0)
    world.assets(addresses=[ip])
    world.inventory(ip, [_port(8080, "tcp", "http-alt", "9.9")])
    (fid,) = world.write(world.finding(ip, [ObservedEndpoint(address=ip, port=8080, protocol=None)]))

    body = _detail(admin, fid)
    raw_port = [h for h in body["exposure_paths"][0]["hops"] if h["kind"] == "port"][0]
    assert raw_port["protocol"] is None  # JSON null, not "tcp"
    path, h = _one(admin, fid)
    assert (h["port"].status, h["port"].port, h["port"].protocol) == ("observed", 8080, None)
    assert h["port"].reason == "The source recorded the port but not the protocol."
    assert h["service"].status == "observed"
    assert (h["service"].service, h["service"].version) == ("http-alt", "9.9")


# 4 ------------------------------------------------------------------------


def test_protocol_mismatch_with_inventory_leaves_service_unknown(world, admin):
    ip = _a(0)
    world.assets(addresses=[ip])
    world.inventory(ip, [_port(161, "tcp", "snmp", "3")])
    (fid,) = world.write(world.finding(
        ip, [ObservedEndpoint(address=ip, port=161, protocol="udp")], source="shodan", finding_type="cve"))
    _, h = _one(admin, fid)
    assert h["port"].status == "observed" and h["port"].protocol == "udp"
    assert h["service"].status == "unknown"
    assert h["service"].reason == "The port inventory lists this port number as tcp; the finding was seen on udp."
    assert h["service"].service is None and h["service"].version is None


# 5 ------------------------------------------------------------------------


def test_shodan_findings_without_a_port_have_no_port_or_service(world, admin):
    ip = _a(0)
    world.assets(addresses=[ip])
    world.inventory(ip, [_port(443)])
    cve = world.finding(ip, [ObservedEndpoint(address=ip)], source="shodan", finding_type="cve")
    tag = world.finding(ip, [ObservedEndpoint(address=ip)], source="shodan", finding_type="malware")
    for fid in world.write(cve, tag):
        path, h = _one(admin, fid)
        assert path.observation == "current" and h["address"].status == "observed"
        assert h["port"].status == "unknown" and h["port"].reason == "The source did not record a port."
        assert h["port"].port is None
        assert h["service"].status == "unknown"
        assert h["service"].reason == "No port is recorded, so no service can be matched to it."


# 6 ------------------------------------------------------------------------


def test_nuclei_on_hostname_with_recorded_address(world, admin):
    ip, name = _a(0), _n("www")
    world.assets(addresses=[ip], records=[(name, "A", ip)])
    (fid,) = world.write(world.finding(
        name, [ObservedEndpoint(address=ip, port=443, protocol=None)],
        source="nuclei", finding_type="exposed-panel-detect"))
    name_id = world.asset_id("dns_record", name)
    ip_id = world.asset_id("ip_address", ip)

    _, h = _one(admin, fid)
    assert h["host"].status == "observed" and h["host"].hostname == name and h["host"].asset_id == name_id
    assert h["host"].candidates == []
    assert h["address"].status == "observed" and h["address"].address == ip and h["address"].asset_id == ip_id
    assert h["address"].candidates == []
    assert h["internet"].status == "observed" and h["internet"].sources == ["nuclei"]


# 7 ------------------------------------------------------------------------


def test_hostname_finding_with_port_only_derives_address_candidates(world, admin):
    ip1, ip2, name = _a(0), _a(1), _n("multi")
    world.assets(addresses=[ip1, ip2], records=[(name, "A", ip1), (name, "A", ip2)])
    (fid,) = world.write(world.finding(
        name, [ObservedEndpoint(address=None, port=443, protocol=None)],
        source="nuclei", finding_type="tech-detect"))

    _, h = _one(admin, fid)
    assert h["host"].status == "observed"
    a = h["address"]
    assert a.status == "derived" and a.reason == _DERIVED_ADDRESSES
    assert a.address is None and a.asset_id is None and a.candidates_truncated is False
    assert [c.value for c in a.candidates] == sorted([ip1, ip2])
    for c in a.candidates:
        assert c.asset_type == "ip_address" and c.distance == 1 and c.record_type == "A"
        assert c.link_first_seen_at is not None and c.link_last_seen_at is not None
        assert c.asset_id == world.asset_id("ip_address", c.value)
    # the port was observed even though the address was not
    assert h["port"].status == "observed" and h["port"].port == 443


def test_hostname_through_a_cname_gives_distance_two_candidate(world, admin):
    ip, front, back = _a(0), _n("front"), _n("back")
    world.assets(addresses=[ip], records=[(front, "CNAME", back), (back, "A", ip)])
    (fid,) = world.write(world.finding(
        front, [ObservedEndpoint(address=None, port=443, protocol=None)],
        source="nuclei", finding_type="tech-detect"))
    _, h = _one(admin, fid)
    a = h["address"]
    assert a.status == "derived" and a.reason == _DERIVED_ADDRESSES
    assert len(a.candidates) == 1
    c = a.candidates[0]
    assert (c.value, c.asset_type, c.distance, c.record_type) == (ip, "ip_address", 2, "A")


# 8 ------------------------------------------------------------------------


def test_dangling_dns_without_endpoints_is_not_recorded(world, admin):
    name = _n("dangle")
    world.assets(records=[(name, "CNAME", _n("gone"))])
    (fid,) = world.write(world.finding(name, [], finding_type="dangling_dns"))
    path, h = _one(admin, fid)
    assert path.observation == "not_recorded" and path.endpoint_id is None
    assert h["host"].status == "observed" and h["host"].hostname == name
    assert h["address"].status == "unknown" and h["address"].reason == _NO_ADDRESS
    assert h["port"].status == "not_applicable" and h["service"].status == "not_applicable"
    assert h["finding"].finding_type == "dangling_dns"


def test_dangling_dns_with_an_origin_address_observes_the_address(world, admin):
    ip, name = _a(0), _n("dangle")
    world.assets(records=[(name, "CNAME", _n("gone"))])
    (fid,) = world.write(world.finding(name, [ObservedEndpoint(address=ip)], finding_type="dangling_dns"))
    path, h = _one(admin, fid)
    assert path.observation == "current" and path.endpoint_id is not None
    assert h["address"].status == "observed" and h["address"].address == ip
    assert h["port"].status == "not_applicable" and h["service"].status == "not_applicable"


# 9 ------------------------------------------------------------------------


def test_single_hostname_pointing_at_address_is_derived_not_observed(world, admin):
    ip, name = _a(0), _n("only")
    world.assets(addresses=[ip], records=[(name, "A", ip)])
    (fid,) = world.write(world.finding(ip, [ObservedEndpoint(address=ip, port=443, protocol="tcp")]))
    _, h = _one(admin, fid)
    host = h["host"]
    assert host.status == "derived" and host.reason == _DERIVED_HOSTNAMES
    assert host.hostname is None and host.asset_id is None
    assert host.candidates_truncated is False
    assert len(host.candidates) == 1
    c = host.candidates[0]
    assert (c.value, c.asset_type, c.distance, c.record_type) == (name, "dns_record", 1, "A")
    assert c.asset_id == world.asset_id("dns_record", name)


# 10 -----------------------------------------------------------------------


def test_cname_above_a_hostname_is_a_distance_two_candidate_ordered_by_distance_then_value(world, admin):
    ip = _a(0)
    n1, n2, via = _n("m1"), _n("m2"), _n("aaa-via")
    # "aaa-via" sorts before both direct names by value, so only the distance
    # can put it last.
    world.assets(addresses=[ip], records=[(n1, "A", ip), (n2, "A", ip), (via, "CNAME", n1)])
    (fid,) = world.write(world.finding(ip, [ObservedEndpoint(address=ip, port=443, protocol="tcp")]))
    _, h = _one(admin, fid)
    cands = h["host"].candidates
    assert h["host"].status == "derived"
    assert [(c.value, c.distance, c.record_type) for c in cands] == [
        (n1, 1, "A"), (n2, 1, "A"), (via, 2, "CNAME")]
    assert [c.value for c in cands[:2]] == sorted([n1, n2])


# 11 -----------------------------------------------------------------------


def test_cname_loop_above_an_address_terminates(world, admin):
    ip, a, b = _a(0), _n("loop-a"), _n("loop-b")
    world.assets(addresses=[ip], records=[(a, "CNAME", b), (b, "CNAME", a), (a, "A", ip)])
    (fid,) = world.write(world.finding(ip, [ObservedEndpoint(address=ip, port=443, protocol="tcp")]))
    _, h = _one(admin, fid)  # a 200 with a well-formed body
    cands = h["host"].candidates
    assert h["host"].status == "derived"
    assert sorted(c.value for c in cands) == sorted([a, b]), "each name must appear exactly once"


# 12 -----------------------------------------------------------------------


def test_two_ports_on_one_address_give_two_paths(world, admin):
    ip = _a(0)
    world.assets(addresses=[ip])
    (fid,) = world.write(world.finding(ip, [
        ObservedEndpoint(address=ip, port=8443, protocol="tcp"),
        ObservedEndpoint(address=ip, port=80, protocol="tcp"),
    ]))
    paths = _paths(admin, fid)
    assert len(paths) == 2
    # equal last_seen_at, so the builder's order falls to address then port ascending
    assert [_hops(p)["port"].port for p in paths] == [80, 8443]
    assert len({p.endpoint_id for p in paths}) == 2
    assert all(p.observation == "current" for p in paths)


# 13 -----------------------------------------------------------------------


def test_endpoint_missing_from_the_latest_observation_is_not_reobserved(world, admin, clock):
    ip = _a(0)
    world.assets(addresses=[ip])
    p1 = ObservedEndpoint(address=ip, port=80, protocol="tcp")
    p2 = ObservedEndpoint(address=ip, port=8443, protocol="tcp")
    f = world.finding(ip, [p1, p2], fingerprint="fp-reobs")
    world.write(f)
    clock.t = T1
    (fid,) = world.write(world.finding(ip, [p1], fingerprint="fp-reobs"))

    paths = _paths(admin, fid)
    assert len(paths) == 2
    by_port = {_hops(p)["port"].port: p for p in paths}
    assert by_port[80].observation == "current" and by_port[80].last_seen_at == T1
    assert by_port[8443].observation == "not_reobserved" and by_port[8443].last_seen_at == T0
    assert paths[0].observation == "current" and paths[1].observation == "not_reobserved"


# 14 -----------------------------------------------------------------------


def test_candidates_are_capped_and_flagged(world, monkeypatch):
    ip = _a(0)
    names = [_n("c1"), _n("c2"), _n("c3")]
    world.assets(addresses=[ip], records=[(n, "A", ip) for n in names])
    (fid,) = world.write(world.finding(ip, [ObservedEndpoint(address=ip, port=443, protocol="tcp")]))
    finding = world.db.get(FindingCanonical, fid)
    asset = world.db.get(AssetCanonical, finding.asset_canonical_id)
    _, uid = _make_user("admin")
    try:
        admin_user = world.db.get(User, uid)
        _check_cap(world, monkeypatch, finding, asset, admin_user, names)
    finally:
        _cleanup_user(uid)


def _check_cap(world, monkeypatch, finding, asset, admin_user, names):

    def host_hop():
        (path,) = exposure_path.build_exposure_paths(world.db, admin_user, finding, asset)
        return _hops(path)["host"]

    monkeypatch.setattr(exposure_path, "MAX_CANDIDATES", 2)
    capped = host_hop()
    assert capped.status == "derived" and len(capped.candidates) == 2 and capped.candidates_truncated is True
    assert [c.value for c in capped.candidates] == sorted(names)[:2]

    monkeypatch.setattr(exposure_path, "MAX_CANDIDATES", 3)
    full = host_hop()
    assert len(full.candidates) == 3 and full.candidates_truncated is False


# 15 -----------------------------------------------------------------------


def test_source_outside_the_external_list_has_unknown_internet_hop(world, admin):
    ip = _a(0)
    world.assets(addresses=[ip])
    assert "test-inside" not in EXTERNAL_SOURCES
    (fid,) = world.write(world.finding(ip, [ObservedEndpoint(address=ip, port=443, protocol="tcp")],
                                       source="test-inside"))
    _, h = _one(admin, fid)
    assert h["address"].status == "observed"  # the rest of the path was built
    assert h["internet"].status == "unknown"
    assert h["internet"].reason == "It is not on record whether this source looks from the internet."
    assert h["internet"].sources == []


def test_external_sources_are_exactly_the_classified_ones():
    # A new producer must be classified here deliberately: add it to
    # EXTERNAL_SOURCES only if it observes from outside the network, and update
    # this expectation in the same change.
    assert EXTERNAL_SOURCES == {"nuclei", "shodan", "version_match", "constellus"}


# 16 -----------------------------------------------------------------------


def test_inventory_edge_cases(world, admin):
    ip = _a(0)
    world.assets(addresses=[ip])
    world.inventory(ip, [{"port": 22, "protocol": "tcp", "sources": ["naabu"], "last_seen_at": T0.isoformat(),
                          "service": None, "service_version": None}])
    f22 = world.finding(ip, [ObservedEndpoint(address=ip, port=22, protocol="tcp")])
    f23 = world.finding(ip, [ObservedEndpoint(address=ip, port=23, protocol="tcp")])
    id22, id23 = world.write(f22, f23)

    _, h = _one(admin, id22)
    assert h["port"].status == "observed"
    assert h["service"].status == "unknown"
    assert h["service"].reason == "The port is in the port inventory, but no service was identified on it."
    assert h["service"].sources == ["naabu"]
    assert h["service"].service is None and h["service"].version is None

    _, h = _one(admin, id23)
    assert h["port"].port == 23
    assert h["service"].status == "unknown" and h["service"].reason == _NO_INVENTORY_ENTRY

    # no asset_state row at all
    world.db.query(AssetState).filter(
        AssetState.asset_canonical_id == world.asset_id("ip_address", ip)).delete(synchronize_session=False)
    world.db.commit()
    _, h = _one(admin, id22)
    assert h["port"].status == "observed"
    assert h["service"].status == "unknown" and h["service"].reason == _NO_INVENTORY_ENTRY


# 17 -----------------------------------------------------------------------


def test_list_route_does_not_carry_exposure_paths(world, admin):
    ip = _a(0)
    world.assets(addresses=[ip])
    (fid,) = world.write(world.finding(ip, [ObservedEndpoint(address=ip, port=443, protocol="tcp")]))
    asset_id = world.asset_id("ip_address", ip)
    r = client.get(f"/api/findings/?asset_canonical_id={asset_id}", headers=admin)
    assert r.status_code == 200
    rows = [x for x in r.json() if x["id"] == str(fid)]
    assert len(rows) == 1
    row = rows[0]
    assert "exposure_paths" not in row
    detail = _detail(admin, fid)
    assert "exposure_paths" in detail and len(detail["exposure_paths"]) == 1
    # The list's CVE roll-up adds these two keys to its rows only
    # (api/findings.py `_rollup_cve_findings`); every other list key is in the detail.
    assert set(row) - {"sources", "rolled_up_ids"} <= set(detail)


# 18 -----------------------------------------------------------------------


def test_openapi_documents_exposure_paths_on_the_detail_response():
    spec = app.openapi()
    ok = spec["paths"]["/api/findings/{finding_id}"]["get"]["responses"]["200"]
    ref = ok["content"]["application/json"]["schema"]["$ref"]
    detail = spec["components"]["schemas"][ref.rsplit("/", 1)[-1]]
    assert detail["title"] == "FindingDetailResponse"
    items = detail["properties"]["exposure_paths"]["items"]["$ref"]
    path_schema = spec["components"]["schemas"][items.rsplit("/", 1)[-1]]
    assert items.endswith("/ExposurePath")
    assert {"observation", "hops", "endpoint_id"} <= set(path_schema["properties"])


# 20 -- gaps: inventory fallback, cname edges, depth guard, protocol, one name -----


def _host_inventory(world, name, ports):
    """Direct `asset_state` upsert on a hostname asset (see module docstring)."""
    aid = world.asset_id("dns_record", name)
    world.db.query(AssetState).filter(AssetState.asset_canonical_id == aid).delete(synchronize_session=False)
    world.db.add(AssetState(asset_canonical_id=aid, open_ports=ports, projected_at=T0))
    world.db.commit()
    return aid


def test_inventory_falls_back_to_the_findings_own_hostname(world, admin):
    ip, name = _a(0), _n("fallback")
    world.assets(addresses=[ip], records=[(name, "A", ip)])
    host_id = _host_inventory(world, name, [_port(443, "tcp", "envoy", "1.1")])
    ip_id = world.asset_id("ip_address", ip)
    (fid,) = world.write(world.finding(
        name, [ObservedEndpoint(address=ip, port=443, protocol=None)], source="nuclei",
        finding_type="tech-detect"))

    _, h = _one(admin, fid)
    assert h["address"].asset_id == ip_id  # the address asset exists, it just has no entry for 443
    assert h["service"].status == "observed" and h["service"].service == "envoy"
    assert h["service"].asset_id == host_id

    # when the address asset has the port too, its entry wins
    world.inventory(ip, [_port(443, "tcp", "nginx", "2.2")])
    _, h = _one(admin, fid)
    assert h["service"].status == "observed" and h["service"].service == "nginx"
    assert h["service"].asset_id == ip_id


def test_cname_typed_cdn_boundary_edge_is_walked(world, admin):
    ip, front, back = _a(0), _n("cdnfront"), _n("cdnback")
    _purge(world.db, [ip, front, back])
    world.values.extend([ip, front, back])
    write_assets(world.db, uuid.uuid4(), [
        DiscoveredAsset(asset_type="ip_address", value=ip, parent_value=None),
        DiscoveredAsset(asset_type="dns_record", value=back, parent_value=None,
                        asset_metadata={"record_type": "A", "content": ip}),
        DiscoveredAsset(asset_type="dns_record", value=front, parent_value=None,
                        asset_metadata={"record_type": "CNAME", "content": back, "cdn": True, "cdn_domain": back}),
    ])
    front_id = world.asset_id("dns_record", front)
    edges = world.db.query(AssetEdge).filter(AssetEdge.source_id == front_id).all()
    assert [e.edge_type for e in edges] == ["cname"], "precondition: the boundary edge is typed cname"

    (fid,) = world.write(world.finding(ip, [ObservedEndpoint(address=ip, port=443, protocol="tcp")]))
    _, h = _one(admin, fid)
    assert h["host"].status == "derived"
    assert [(c.value, c.distance, c.record_type) for c in h["host"].candidates] == [
        (back, 1, "A"), (front, 2, "CNAME")]


def test_chain_depth_guard_stops_the_walk(world, admin, monkeypatch):
    ip = _a(0)
    n1, n2, n3 = _n("d1"), _n("d2"), _n("d3")
    world.assets(addresses=[ip], records=[(n3, "CNAME", n2), (n2, "CNAME", n1), (n1, "A", ip)])
    (fid,) = world.write(world.finding(ip, [ObservedEndpoint(address=ip, port=443, protocol="tcp")]))

    monkeypatch.setattr(exposure_path, "MAX_CHAIN_DEPTH", 2)
    _, h = _one(admin, fid)
    assert [(c.value, c.distance) for c in h["host"].candidates] == [(n1, 1), (n2, 2)]

    monkeypatch.setattr(exposure_path, "MAX_CHAIN_DEPTH", 3)
    _, h = _one(admin, fid)
    assert [(c.value, c.distance) for c in h["host"].candidates] == [(n1, 1), (n2, 2), (n3, 3)]


def test_tcp_finding_against_a_udp_inventory_entry_leaves_service_unknown(world, admin):
    ip = _a(0)
    world.assets(addresses=[ip])
    world.inventory(ip, [_port(53, "udp", "domain", "9")])
    (fid,) = world.write(world.finding(
        ip, [ObservedEndpoint(address=ip, port=53, protocol="tcp")], source="shodan", finding_type="cve"))
    _, h = _one(admin, fid)
    assert h["port"].status == "observed" and h["port"].protocol == "tcp"
    assert h["service"].status == "unknown"
    assert h["service"].reason == "The port inventory lists this port number as udp; the finding was seen on tcp."
    assert h["service"].service is None and h["service"].version is None


def test_a_name_with_several_records_is_one_host_candidate(world, admin):
    ip, name = _a(0), _n("records")
    world.assets(addresses=[ip], records=[(name, "A", ip), (name, "AAAA", ip), (name, "TXT", "hello")])
    ip_id = world.asset_id("ip_address", ip)
    rows = world.db.query(AssetCanonical.id).filter(
        AssetCanonical.asset_type == "dns_record", AssetCanonical.value == name).all()
    assert len(rows) == 3, "precondition: one asset row per record"
    links = world.db.query(AssetEdge).filter(
        AssetEdge.target_id == ip_id, AssetEdge.source_id.in_([r[0] for r in rows])).count()
    assert links == 2, "precondition: two rows of the name link to the address"

    (fid,) = world.write(world.finding(ip, [ObservedEndpoint(address=ip, port=443, protocol="tcp")]))
    _, h = _one(admin, fid)
    assert h["host"].status == "derived"
    assert [c.value for c in h["host"].candidates] == [name]
    assert h["host"].candidates_truncated is False


# 19 -----------------------------------------------------------------------
def test_host_address_gives_one_form_per_address():
    """An INET value, an interface form and a full-length IPv6 form all come
    out as the one compressed host address the asset lookup compares with.
    (`_docaddr` allocates IPv4 only, so the IPv6 lookup has no database test.)"""
    v4 = _a(0)
    assert exposure_path._host_address(v4) == v4
    assert exposure_path._host_address(f"{v4}/32") == v4
    assert exposure_path._host_address(ipaddress.ip_address(v4)) == v4
    full = ipaddress.ip_address("2001:db8::1").exploded
    assert full != "2001:db8::1"
    assert exposure_path._host_address(full) == "2001:db8::1"
    assert exposure_path._host_address("not an address") is None
    assert exposure_path._host_address(None) is None
