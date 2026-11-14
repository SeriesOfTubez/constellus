"""Each finding producer records the endpoints its source actually recorded
(planning#347). The rule under test: an endpoint part is what the source said;
where it did not say, the part is None -- never a default, never inferred.

The version_match test is a DB integration test (it runs `match_versions` and
reads `finding_endpoints` back); the rest are pure.

Run with:  pytest app/tests/test_finding_endpoints_producers.py
"""

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

from app.connectors.base import DiscoveredAsset, DiscoveredFinding, ObservedEndpoint
from app.connectors.nuclei import NucleiConnector
from app.connectors.shodan import _cve_endpoints
from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.cpe_cve_range import CpeCveRange
from app.models.finding_canonical import FindingCanonical
from app.models.finding_endpoint import FindingEndpoint
from app.services import dangling_dns_analyzer as dda
from app.services import exposure_analyzer as ea
from app.services import projector, version_matcher
from app.services.asset_writer import write_assets
from app.tests import _docaddr


_ADDRS: list[str] = []


def _a(i: int) -> str:
    """The module's i-th documentation address, drawn on first use and then
    reused: the shared `_docaddr` pool is small, and every test here cleans up
    its rows by value (and purges before inserting)."""
    while len(_ADDRS) <= i:
        _ADDRS.append(_docaddr.alloc())
    return _ADDRS[i]


# --------------------------------------------------------------------------- nuclei


def _nuclei(**over) -> list:
    item = {
        "template-id": "tmpl-x",
        "info": {"name": "n", "severity": "low"},
        "host": "www.example.com",
        "matched-at": "http://www.example.com:8999/",
        "scheme": "http",
        "type": "http",
    }
    item.update(over)
    for k in [k for k, v in item.items() if v is _ABSENT]:
        del item[k]
    out = NucleiConnector()._parse_findings([item])
    assert len(out) == 1, "item was dropped by the parser; the test never reached the endpoint code"
    return out


_ABSENT = object()


def test_nuclei_hostname_host_with_ip_and_explicit_port():
    ip = _a(0)
    (f,) = _nuclei(ip=ip, port="8999")
    assert f.endpoints == [ObservedEndpoint(address=ip, port=8999, protocol=None)]
    assert f.detail["port"] == f.endpoints[0].port == 8999


def test_nuclei_https_matched_at_without_port_is_443():
    ip = _a(0)
    (f,) = _nuclei(ip=ip, port=_ABSENT, **{"matched-at": "https://www.example.com/"})
    assert f.endpoints == [ObservedEndpoint(address=ip, port=443, protocol=None)]
    assert f.detail["port"] == 443


def test_nuclei_no_ip_hostname_host_has_no_address():
    (f,) = _nuclei(ip=_ABSENT)
    assert f.endpoints == [ObservedEndpoint(address=None, port=8999, protocol=None)]


def test_nuclei_no_ip_ip_literal_host_is_the_address():
    host = _a(1)
    (f,) = _nuclei(ip=_ABSENT, host=host, **{"matched-at": f"http://{host}:8999/"})
    assert f.endpoints == [ObservedEndpoint(address=host, port=8999, protocol=None)]


def test_nuclei_ip_not_a_literal_is_not_recorded():
    (f,) = _nuclei(ip="not-an-ip")
    assert f.endpoints == [ObservedEndpoint(address=None, port=8999, protocol=None)]


def test_nuclei_ip_not_a_literal_falls_through_to_ip_literal_host():
    host = _a(1)
    (f,) = _nuclei(ip="not-an-ip", host=host)
    assert f.endpoints[0].address == host


def test_nuclei_ip_field_wins_over_an_ip_literal_host():
    ip, host = _a(0), _a(1)
    (f,) = _nuclei(ip=ip, host=host, **{"matched-at": f"http://{host}:8999/"})
    assert f.endpoints == [ObservedEndpoint(address=ip, port=8999, protocol=None)]


def test_nuclei_port_falls_back_to_nuclei_port_field():
    bare = {"matched-at": "www.example.com"}
    (f,) = _nuclei(ip=_ABSENT, port="8443", **bare)
    assert f.endpoints == [ObservedEndpoint(address=None, port=8443, protocol=None)]
    assert f.detail["port"] == 8443


def test_nuclei_port_field_invalid_or_absent_means_no_port():
    bare = {"matched-at": "www.example.com"}
    for port in ("0", "abc", "65536", "-1", _ABSENT):
        (f,) = _nuclei(ip=_ABSENT, port=port, **bare)
        assert f.detail["port"] is None, port
        assert f.endpoints == [], port
    # an address alone still yields an address-only endpoint
    ip = _a(0)
    (f,) = _nuclei(ip=ip, port="abc", **bare)
    assert f.endpoints == [ObservedEndpoint(address=ip, port=None, protocol=None)]


def test_nuclei_ipv6_ip():
    # RFC 3849 documentation prefix; _docaddr only hands out IPv4.
    v6 = "2001:db8::1"
    (f,) = _nuclei(ip=v6, port="8999")
    assert f.endpoints == [ObservedEndpoint(address=v6, port=8999, protocol=None)]


def test_nuclei_port_field_as_int_on_bare_hostname():
    (f,) = _nuclei(ip=_ABSENT, port=8443, **{"matched-at": "www.example.com"})
    assert f.detail["port"] == 8443
    assert f.endpoints == [ObservedEndpoint(address=None, port=8443, protocol=None)]


def test_nuclei_port_field_bool_is_not_a_port():
    bare = {"matched-at": "www.example.com"}
    (f,) = _nuclei(ip=_ABSENT, port=True, **bare)
    assert f.detail["port"] is None
    assert f.endpoints == []
    ip = _a(0)
    (f,) = _nuclei(ip=ip, port=True, **bare)
    assert f.detail["port"] is None
    assert f.endpoints == [ObservedEndpoint(address=ip, port=None, protocol=None)]


def test_nuclei_ip_not_a_string_is_not_recorded():
    for bad in (12345, ["x"], {"a": 1}, True):
        (f,) = _nuclei(ip=bad)
        assert f.endpoints == [ObservedEndpoint(address=None, port=8999, protocol=None)], bad
    host = _a(1)
    (f,) = _nuclei(ip=12345, host=host)
    assert f.endpoints[0].address == host


# --------------------------------------------------------------------------- shodan


def test_shodan_cve_in_two_services_lowercases_transport():
    ip = _a(0)
    host = {"data": [
        {"port": 443, "transport": "tcp", "vulns": {"CVE-2099-0001": {}}},
        {"port": 53, "transport": "UDP", "vulns": {"CVE-2099-0001": {}, "CVE-2099-0002": {}}},
        {"port": 22, "transport": "tcp", "vulns": {"CVE-2099-0002": {}}},
    ]}
    assert _cve_endpoints(host, ip, "CVE-2099-0001") == [
        ObservedEndpoint(address=ip, port=443, protocol="tcp"),
        ObservedEndpoint(address=ip, port=53, protocol="udp"),
    ]


def test_shodan_cve_only_host_level_is_address_only():
    ip = _a(0)
    host = {"vulns": {"CVE-2099-0001": {}}, "data": [{"port": 80, "transport": "tcp", "vulns": {"CVE-2099-0009": {}}}]}
    assert _cve_endpoints(host, ip, "CVE-2099-0001") == [ObservedEndpoint(address=ip)]
    assert _cve_endpoints({}, ip, "CVE-2099-0001") == [ObservedEndpoint(address=ip)]


def test_shodan_missing_transport_is_none_not_tcp():
    ip = _a(0)
    host = {"data": [{"port": 80, "vulns": {"CVE-2099-0001": {}}}, {"port": 81, "transport": "", "vulns": ["CVE-2099-0001"]}]}
    assert _cve_endpoints(host, ip, "CVE-2099-0001") == [
        ObservedEndpoint(address=ip, port=80, protocol=None),
        ObservedEndpoint(address=ip, port=81, protocol=None),
    ]


def test_shodan_vulns_as_list_on_service():
    ip = _a(0)
    host = {"data": [{"port": 8080, "transport": "tcp", "vulns": ["CVE-2099-0001"]}]}
    assert _cve_endpoints(host, ip, "CVE-2099-0001") == [ObservedEndpoint(address=ip, port=8080, protocol="tcp")]


def test_shodan_bad_ports_skipped_and_duplicates_collapse():
    ip = _a(0)
    v = {"CVE-2099-0001": {}}
    host = {"data": [
        {"port": True, "transport": "tcp", "vulns": v},
        {"port": 0, "transport": "tcp", "vulns": v},
        {"port": 65536, "transport": "tcp", "vulns": v},
        {"port": "80", "transport": "tcp", "vulns": v},
        {"port": 25, "transport": "tcp", "vulns": v},
        {"port": 25, "transport": "TCP", "vulns": v},
    ]}
    assert _cve_endpoints(host, ip, "CVE-2099-0001") == [ObservedEndpoint(address=ip, port=25, protocol="tcp")]
    # every service rejected -> falls back to the address-only endpoint
    assert _cve_endpoints({"data": host["data"][:4]}, ip, "CVE-2099-0001") == [ObservedEndpoint(address=ip)]


def test_shodan_enrich_emits_endpoints_for_cve_and_tag_findings(monkeypatch):
    """Through `enrich`, with the HTTP layer stubbed. Asserts the findings were
    actually produced (the path was reached) before checking their endpoints."""
    from app.connectors import shodan

    ip = _a(0)
    host = {
        "ip_str": ip,
        "tags": ["malware"],
        "vulns": {"CVE-2099-0001": {"cvss": 5.0}},
        "data": [{"port": 443, "transport": "UDP", "vulns": {"CVE-2099-0001": {}}}],
    }
    monkeypatch.setattr(shodan, "connector_get", lambda *a, **k: SimpleNamespace(
        status_code=200, json=lambda: host, text="", headers={}, raise_for_status=lambda: None))
    monkeypatch.setattr(shodan, "_is_public_ip", lambda v: True)  # documentation addresses are not public
    monkeypatch.setattr(shodan, "_sleep_between", lambda *a, **k: None)
    monkeypatch.setattr(shodan, "_detect_plan_and_delay", lambda key: ("test", 0.0))
    conn = shodan.ShodanConnector()
    result = conn.enrich(
        [DiscoveredAsset(asset_type="ip_address", value=ip, parent_value=None)],
        {"api_key": "k", "import_vulns": True},
    )
    by_type = {f.finding_type: f for f in result.findings}
    assert set(by_type) == {"cve", "malware"}, "enrich produced no findings; stub did not reach the code"
    assert by_type["cve"].endpoints == [ObservedEndpoint(address=ip, port=443, protocol="udp")]
    assert by_type["malware"].endpoints == [ObservedEndpoint(address=ip)]


# --------------------------------------------------------------------------- version_match


def _cleanup_vm(asset_value: str, cve_id: str) -> None:
    db = SessionLocal()
    try:
        from app.models.asset_edge import AssetEdge

        ids = [r[0] for r in db.query(AssetCanonical.id).filter(AssetCanonical.value == asset_value)]
        fids = [r[0] for r in db.query(FindingCanonical.id).filter(FindingCanonical.asset_canonical_id.in_(ids))]
        db.query(AssetEdge).filter(AssetEdge.target_id.in_(fids)).delete(synchronize_session=False)
        db.query(AssetEdge).filter(AssetEdge.source_id.in_(ids)).delete(synchronize_session=False)
        db.query(FindingCanonical).filter(FindingCanonical.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.value == asset_value).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _run_version_match(monkeypatch, ports: list[dict], since=None):
    ip = _a(0)
    cve = f"CVE-2099-{uuid.uuid4().int % 90000 + 10000}"
    _cleanup_vm(ip, cve)  # delete-then-insert: a failed earlier test cannot poison this one
    db = SessionLocal()
    try:
        write_assets(db, uuid.uuid4(), [DiscoveredAsset(asset_type="ip_address", value=ip, parent_value=None)])
        asset = db.query(AssetCanonical).filter(AssetCanonical.value == ip).one()
        rng = CpeCveRange(cve_id=cve, vendor="apache", product="http_server",
                          version_end_excluding="9.9.9", all_versions=False)
        monkeypatch.setattr(projector, "open_ports_by_asset", lambda _db, ids: {asset.id: ports})
        monkeypatch.setattr(version_matcher, "ranges_for_product", lambda _db, v, p: [rng])
        version_matcher.match_versions(db, uuid.uuid4(), {asset.id}, since)
        db.commit()
        findings = db.query(FindingCanonical).filter(
            FindingCanonical.asset_canonical_id == asset.id, FindingCanonical.cve_id == cve).all()
        rows = []
        for f in findings:
            rows += db.query(FindingEndpoint).filter(FindingEndpoint.finding_id == f.id).all()
        return ip, cve, findings, rows
    finally:
        db.close()


def _sw_entry(port, **extra):
    e = {"port": port, "software": [{"vendor": "apache", "product": "http_server", "version": "2.4.1"}]}
    e.update(extra)
    return e


def test_version_match_two_ports_one_finding_two_endpoints(monkeypatch):
    ip = cve = None
    try:
        ip, cve, findings, rows = _run_version_match(
            monkeypatch, [_sw_entry(80, protocol="tcp"), _sw_entry(8080, protocol="tcp")])
        assert len(findings) == 1, "findings were multiplied per port"
        assert sorted((str(r.address), r.port, r.protocol) for r in rows) == [(ip, 80, "tcp"), (ip, 8080, "tcp")]
    finally:
        if ip:
            _cleanup_vm(ip, cve)


def test_version_match_port_without_protocol_key_is_null(monkeypatch):
    ip = cve = None
    try:
        ip, cve, findings, rows = _run_version_match(
            monkeypatch, [_sw_entry(80, protocol="udp"), _sw_entry(8080)])
        assert len(findings) == 1
        assert sorted((r.port, r.protocol) for r in rows) == [(80, "udp"), (8080, None)]
    finally:
        if ip:
            _cleanup_vm(ip, cve)


def test_version_match_single_port_single_endpoint(monkeypatch):
    ip = cve = None
    try:
        ip, cve, findings, rows = _run_version_match(monkeypatch, [_sw_entry(443, protocol="tcp")])
        assert len(findings) == 1
        assert [(str(r.address), r.port, r.protocol) for r in rows] == [(ip, 443, "tcp")]
    finally:
        if ip:
            _cleanup_vm(ip, cve)


def test_version_match_missing_or_non_int_port_is_one_address_only_endpoint(monkeypatch):
    ip = cve = None
    no_port = _sw_entry(None)
    del no_port["port"]
    try:
        ip, cve, findings, rows = _run_version_match(monkeypatch, [no_port, _sw_entry("80")])
        assert len(findings) == 1, "version_match produced no finding; the endpoint path was not reached"
        assert [(str(r.address), r.port, r.protocol) for r in rows] == [(ip, None, None)]
    finally:
        if ip:
            _cleanup_vm(ip, cve)


def test_version_match_stale_port_contributes_no_endpoint(monkeypatch):
    ip = cve = None
    since = datetime(2024, 1, 1, tzinfo=timezone.utc)
    try:
        ip, cve, findings, rows = _run_version_match(
            monkeypatch,
            [_sw_entry(80, protocol="tcp", last_seen_at="2020-01-01T00:00:00Z"),
             _sw_entry(8080, protocol="tcp", last_seen_at="2024-06-01T00:00:00Z")],
            since=since,
        )
        assert len(findings) == 1, "the fresh port's match did not produce the finding"
        assert [(str(r.address), r.port, r.protocol) for r in rows] == [(ip, 8080, "tcp")]
    finally:
        if ip:
            _cleanup_vm(ip, cve)


# --------------------------------------------------------------------------- exposed_service


def _rule() -> ea.ExposureRule:
    return ea.ExposureRule(
        id="exposed-test", name="Test service", severity="high", ports=frozenset({2323}),
        services=frozenset({"test"}), rationale="r", remediation="x", references=(),
    )


def _exposure(asset_value, entry):
    return ea._build_finding(
        asset_value=asset_value, port=entry["port"], protocol=entry.get("protocol") or "tcp",
        service=None, service_version=None, rule=_rule(), confidence="confirmed",
        severity="high", override_label=None,
        observed_protocol=entry.get("protocol") if isinstance(entry.get("protocol"), str) else None,
    )


def test_exposed_service_endpoint_carries_raw_protocol():
    ip = _a(0)
    f = _exposure(ip, {"port": 2323, "protocol": "udp"})
    assert f.endpoints == [ObservedEndpoint(address=ip, port=2323, protocol="udp")]
    assert f.detail["protocol"] == "udp"


def test_exposed_service_no_protocol_key_endpoint_none_detail_tcp():
    ip = _a(0)
    f = _exposure(ip, {"port": 2323})
    assert f.endpoints == [ObservedEndpoint(address=ip, port=2323, protocol=None)]
    assert f.detail["protocol"] == "tcp"


def test_exposed_service_call_site_passes_raw_protocol(monkeypatch):
    """The real call site in analyze_exposures: stub the inputs and capture
    what it hands `_build_finding`, so a regression to `or "tcp"` is caught."""
    ip = _a(0)
    asset = SimpleNamespace(id=uuid.uuid4(), value=ip, tags=[], parent_value=None)
    seen = []

    class _Q:
        def filter(self, *a, **k): return self
        def all(self): return [asset]

    class _DB:
        def query(self, *a, **k): return _Q()

    monkeypatch.setattr(ea, "_is_public_ip", lambda v: True)
    monkeypatch.setattr(projector, "open_ports_by_asset", lambda db, ids: {asset.id: [{"port": 2323}]})
    monkeypatch.setattr(ea, "_classify_ports", lambda ports, since: (list(ports), []))
    monkeypatch.setattr(ea, "_match_entry", lambda rs, port, svc: (_rule(), "confirmed"))
    monkeypatch.setattr(ea, "write_findings", lambda db, rid, fs, **k: seen.extend(fs) or set())
    monkeypatch.setattr(ea, "_resolve_closed_exposures", lambda db, r: set())
    monkeypatch.setattr(ea, "_load_ruleset", lambda: SimpleNamespace(rules=[_rule()]))
    ea.analyze_exposures(_DB(), uuid.uuid4(), {asset.id}, datetime.now(timezone.utc))
    assert len(seen) == 1, "analyze_exposures never reached the call site"
    assert seen[0].endpoints == [ObservedEndpoint(address=ip, port=2323, protocol=None)]
    assert seen[0].detail["protocol"] == "tcp"


# --------------------------------------------------------------------------- dangling


def _dangling(layer, **extra):
    record = SimpleNamespace(value="host.example.com", id=uuid.uuid4())
    tr = {"tier": dda.TIER_MEDIUM, "layer": layer, "signals": []}
    tr.update(extra)
    return dda._build_finding(record, tr)


def test_dangling_origin_layers_carry_address_only_endpoint():
    for layer in (dda.LAYER_AFFINITY_CORROBORATED_ALIVE, dda.LAYER_AFFINITY_NOT_AFFINE,
                  dda.LAYER_AFFINITY_UNREACHABLE):
        ip = _a(0)
        f = _dangling(layer, origin_ip=ip)
        assert f.detail["origin_ip"] == ip, layer
        assert f.endpoints == [ObservedEndpoint(address=ip)], layer


def test_dangling_fingerprint_layer_has_no_endpoint():
    f = _dangling(dda.LAYER_FINGERPRINT, signal={"template_id": "t", "finding_id": uuid.uuid4()})
    assert "origin_ip" not in f.detail
    assert f.endpoints == []


def test_dangling_endpoint_comes_only_from_origin_ip():
    """Every other address-like value in the fixture differs from origin_ip, so
    the endpoint can only have been taken from it."""
    origin, decoy_a, decoy_b = _a(0), _a(1), _a(2)
    record = SimpleNamespace(value="host.example.com", id=uuid.uuid4(), content=decoy_a, address=decoy_b)
    tr = {
        "tier": dda.TIER_MEDIUM, "layer": dda.LAYER_AFFINITY_NOT_AFFINE, "origin_ip": origin,
        "signals": [{"address": decoy_a, "origin": decoy_b, "hostname": "other.example.com"}],
    }
    f = dda._build_finding(record, tr)
    assert f.detail["origin_ip"] == origin, "the finding was not built from the origin_ip under test"
    assert f.endpoints == [ObservedEndpoint(address=origin)]
    assert f.endpoints[0].address not in (decoy_a, decoy_b, record.value)


def test_shodan_host_level_cve_through_the_writer_is_one_address_only_row():
    from app.models.asset_edge import AssetEdge
    from app.services.finding_writer import write_findings

    ip = _a(0)
    cve = "CVE-2099-0001"
    host = {"vulns": {cve: {}}, "data": [{"port": 80, "transport": "tcp", "vulns": {"CVE-2099-0009": {}}}]}
    _cleanup_vm(ip, cve)
    db = SessionLocal()
    try:
        write_assets(db, uuid.uuid4(), [DiscoveredAsset(asset_type="ip_address", value=ip, parent_value=None)])
        write_findings(db, uuid.uuid4(), [DiscoveredFinding(
            asset_value=ip, finding_type="cve", source="shodan", severity="low", title=cve, cve_id=cve,
            endpoints=_cve_endpoints(host, ip, cve),
        )])
        (finding,) = db.query(FindingCanonical).join(
            AssetCanonical, AssetCanonical.id == FindingCanonical.asset_canonical_id
        ).filter(AssetCanonical.value == ip).all()
        rows = db.query(FindingEndpoint).filter(FindingEndpoint.finding_id == finding.id).all()
        assert [(str(r.address), r.port, r.protocol) for r in rows] == [(ip, None, None)]
    finally:
        db.rollback()
        ids = [r[0] for r in db.query(AssetCanonical.id).filter(AssetCanonical.value == ip)]
        fids = [r[0] for r in db.query(FindingCanonical.id).filter(FindingCanonical.asset_canonical_id.in_(ids))]
        db.query(AssetEdge).filter(AssetEdge.target_id.in_(fids)).delete(synchronize_session=False)
        db.query(AssetEdge).filter(AssetEdge.source_id.in_(ids)).delete(synchronize_session=False)
        db.query(FindingCanonical).filter(FindingCanonical.id.in_(fids)).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.id.in_(ids)).delete(synchronize_session=False)
        db.commit()
        db.close()
