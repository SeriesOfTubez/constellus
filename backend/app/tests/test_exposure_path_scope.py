"""Read scope on the exposure path (planning#347), through `GET /api/findings/{id}`.

The finding itself is readable by every persona here; what is under test is
everything the path derives about OTHER assets (sibling hostnames, address
assets, port inventories). Every "hidden" assertion is paired, in the same
test, with the admin (or `viewer+E1`) request against the same rows showing the
thing that is absent for the viewer, so the path was reached.

Personas: `admin`; `viewer`, who cannot read assets under this module's
engagement; `viewer+E1`, a viewer with a role assignment to that engagement.
The engagement has one domain target. Hostnames under it are hidden from the
plain viewer by name; address assets are hidden by a `TargetAssetLink` to it.

Synthetic data only: hostnames under example.org / example.net with a
module-unique label; addresses are `_a(0)`..`_a(3)` of test_exposure_path.py
(readable: 0, 1; hidden by link: 2, 3). Both modules purge those by value.

Run with:  backend/scripts/test.sh app/tests/test_exposure_path_scope.py
"""

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.connectors.base import ObservedEndpoint
from app.core.database import SessionLocal
from app.main import app
from app.models.asset_canonical import AssetCanonical
from app.models.asset_edge import AssetEdge
from app.models.asset_state import AssetState
from app.models.finding_canonical import FindingCanonical
from app.models.role_assignment import RoleAssignment
from app.models.target import Target
from app.models.target_asset_link import TargetAssetLink
from app.models.user import User
from app.schemas.exposure_path import ExposurePath
from app.services import exposure_path
from app.services.exposure_path import _NO_HOSTNAME, _NO_INVENTORY_ENTRY
from app.tests._engagement import cleanup_engagement, make_engagement
from app.tests.test_edgar_ingest_api import _cleanup_user, _make_user
from app.tests.test_exposure_path import _a, _host_inventory, _port, _purge, _World

client = TestClient(app)

_LABEL = f"xps-{uuid.uuid4().hex[:8]}"
_PORT = 8443
_DOMAIN = f"{_LABEL}.example.net"


# -- fixtures --------------------------------------------------------------------


class _Scope:
    """One restricting engagement with one domain target. Hostnames under the
    target domain are hidden from a plain viewer by name; an address asset is
    hidden by a `TargetAssetLink` to the target (the read rule's link leg)."""

    def __init__(self):
        self.domain = _DOMAIN
        self.engagement_id = None
        self.target_id = None

    def build(self):
        db = SessionLocal()
        try:
            self._purge_target(db)
            e = make_engagement(db, "pre_close")
            self.engagement_id = e.id
            t = Target(id=uuid.uuid4(), type="domain", value=self.domain, engagement_id=e.id)
            db.add(t)
            db.commit()
            self.target_id = t.id
        finally:
            db.close()
        return self

    def _purge_target(self, db):
        db.rollback()
        ids = [r[0] for r in db.query(Target.id).filter(Target.value == self.domain)]
        if ids:
            db.query(TargetAssetLink).filter(TargetAssetLink.target_id.in_(ids)).delete(synchronize_session=False)
            db.query(Target).filter(Target.id.in_(ids)).delete(synchronize_session=False)
            db.commit()

    def link(self, db, value: str) -> None:
        """Hide the ip_address asset `value` by link."""
        aid = db.query(AssetCanonical.id).filter(
            AssetCanonical.asset_type == "ip_address", AssetCanonical.value == value).one()[0]
        now = datetime.now(timezone.utc)
        db.add(TargetAssetLink(target_id=self.target_id, asset_canonical_id=aid,
                               first_linked_at=now, last_observed_at=now))
        db.commit()

    def close(self):
        db = SessionLocal()
        try:
            self._purge_target(db)
            if self.engagement_id is not None:
                cleanup_engagement(db, self.engagement_id)
        finally:
            db.close()


@pytest.fixture(scope="module")
def w():
    scope = _Scope().build()
    yield scope
    scope.close()


@pytest.fixture(scope="module")
def tokens(w):
    admin, admin_id = _make_user("admin")
    viewer, viewer_id = _make_user("viewer")
    scoped, scoped_id = _make_user("viewer")
    db = SessionLocal()
    try:
        db.add(RoleAssignment(user_id=scoped_id, role="viewer", engagement_id=w.engagement_id))
        db.commit()
    finally:
        db.close()
    yield {"admin": admin, "viewer": viewer, "viewer+E1": scoped}
    for uid in (admin_id, viewer_id, scoped_id):
        _cleanup_user(uid)


def _unlink(db, values: list[str]) -> None:
    db.rollback()
    ids = [r[0] for r in db.query(AssetCanonical.id).filter(AssetCanonical.value.in_(values))]
    if ids:
        db.query(TargetAssetLink).filter(TargetAssetLink.asset_canonical_id.in_(ids)).delete(
            synchronize_session=False)
        db.commit()


class _ScopedWorld(_World):
    """`_World` that drops target links before purging, in setup and teardown
    (module 1 uses the same addresses; each side purges by value)."""

    def assets(self, *, addresses=(), records=()):
        _unlink(self.db, list(addresses) + sorted({r[0] for r in records}))
        super().assets(addresses=addresses, records=records)

    def cleanup(self):
        try:
            _unlink(self.db, self.values)
        finally:
            super().cleanup()


@pytest.fixture
def world():
    wd = _ScopedWorld()
    try:
        yield wd
    finally:
        wd.cleanup()


# -- helpers -----------------------------------------------------------------------


def _names(tag: str, domain: str | None = None) -> tuple[str, str]:
    """(readable, hidden-from-viewer) hostnames."""
    return f"open{tag}-{_LABEL}.example.org", f"hid{tag}-{_LABEL}.{domain or _DOMAIN}"


def _get(tokens, who, finding_id):
    return client.get(f"/api/findings/{finding_id}", headers=tokens[who])


def _body(tokens, who, finding_id) -> dict:
    r = client.get(f"/api/findings/{finding_id}", headers=tokens[who])
    assert r.status_code == 200, r.text
    return r.json()


def _hop(body: dict, kind: str) -> dict:
    (path,) = body["exposure_paths"]
    return [h for h in path["hops"] if h["kind"] == kind][0]


def _strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from _strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _strings(v)


def _assert_absent(body: dict, *needles: str) -> None:
    found = list(_strings(body))
    assert found, "empty response"
    for needle in needles:
        assert needle, "empty needle would match everything"
        assert needle not in found
        for s in found:
            assert needle not in s, "a withheld value reached the response"


def _drop(world, values: list[str]) -> None:
    """Delete these assets (and their edges, and port inventories)."""
    _unlink(world.db, values)
    ids = [r[0] for r in world.db.query(AssetCanonical.id).filter(AssetCanonical.value.in_(values))]
    assert ids, "nothing to drop"
    world.db.query(AssetState).filter(AssetState.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
    world.db.commit()
    _purge(world.db, values)


def _vp(addr, port=_PORT, protocol="tcp"):
    return [ObservedEndpoint(address=addr, port=port, protocol=protocol)]


# -- A1 ----------------------------------------------------------------------------


def test_a1_sibling_hostname_is_withheld(world, tokens, w):
    addr = _a(0)
    open_n, hid_n = _names("1")
    world.assets(addresses=[addr], records=[(open_n, "A", addr), (hid_n, "A", addr)])
    (fid,) = world.write(world.finding(addr, _vp(addr), source="version_match", finding_type="cve"))
    hid_id = world.asset_id("dns_record", hid_n)

    for who in ("admin", "viewer+E1"):
        host = _hop(_body(tokens, who, fid), "host")
        assert host["status"] == "derived"
        assert sorted(c["value"] for c in host["candidates"]) == sorted([open_n, hid_n])

    body = _body(tokens, "viewer", fid)
    host = _hop(body, "host")
    assert host["status"] == "derived"
    assert [c["value"] for c in host["candidates"]] == [open_n]
    assert host["candidates_truncated"] is False
    _assert_absent(body, hid_n, str(hid_id))
    ExposurePath.model_validate(body["exposure_paths"][0])


# -- A2 ----------------------------------------------------------------------------


def test_a2_withheld_name_is_indistinguishable_from_absence(world, tokens, w):
    addr = _a(0)
    open_n, hid_n = _names("2")
    world.assets(addresses=[addr], records=[(open_n, "A", addr), (hid_n, "A", addr)])
    (fid,) = world.write(world.finding(addr, _vp(addr), source="version_match", finding_type="cve"))

    admin_host = _hop(_body(tokens, "admin", fid), "host")
    assert len(admin_host["candidates"]) == 2  # the hidden name exists
    before = _body(tokens, "viewer", fid)["exposure_paths"]
    assert [c["value"] for c in _hop({"exposure_paths": before}, "host")["candidates"]] == [open_n]

    _drop(world, [hid_n])
    assert len(_hop(_body(tokens, "admin", fid), "host")["candidates"]) == 1  # and now it is gone
    after = _body(tokens, "viewer", fid)["exposure_paths"]
    assert before == after


# -- A3 ----------------------------------------------------------------------------


def test_a3_only_a_withheld_hostname_reads_as_no_hostname(world, tokens, w):
    addr = _a(0)
    _, hid_n = _names("3")
    world.assets(addresses=[addr], records=[(hid_n, "A", addr)])
    (fid,) = world.write(world.finding(addr, _vp(addr), source="version_match", finding_type="cve"))

    admin_host = _hop(_body(tokens, "admin", fid), "host")
    assert admin_host["status"] == "derived" and [c["value"] for c in admin_host["candidates"]] == [hid_n]

    viewer_host = _hop(_body(tokens, "viewer", fid), "host")
    assert viewer_host["status"] == "unknown"
    assert viewer_host["reason"] == _NO_HOSTNAME
    assert viewer_host["candidates"] == []

    _drop(world, [hid_n])
    assert _hop(_body(tokens, "admin", fid), "host")["status"] == "unknown"  # no name at all now
    assert _hop(_body(tokens, "viewer", fid), "host") == viewer_host


# -- A4 ----------------------------------------------------------------------------


def test_a4_walk_does_not_pass_through_a_withheld_name(world, tokens, w):
    addr = _a(0)
    top_n, hid_n = f"top4-{_LABEL}.example.org", _names("4")[1]
    world.assets(addresses=[addr], records=[(top_n, "CNAME", hid_n), (hid_n, "A", addr)])
    (fid,) = world.write(world.finding(addr, _vp(addr), source="version_match", finding_type="cve"))

    admin_host = _hop(_body(tokens, "admin", fid), "host")
    assert [(c["value"], c["distance"]) for c in admin_host["candidates"]] == [(hid_n, 1), (top_n, 2)]

    viewer_body = _body(tokens, "viewer", fid)
    viewer_host = _hop(viewer_body, "host")
    assert viewer_host["status"] == "unknown" and viewer_host["reason"] == _NO_HOSTNAME
    assert viewer_host["candidates"] == []
    _assert_absent(viewer_body, top_n, hid_n)

    _drop(world, [top_n, hid_n])
    assert _hop(_body(tokens, "viewer", fid), "host") == viewer_host


# -- A5 ----------------------------------------------------------------------------


def test_a5_truncation_flag_does_not_count_withheld_names(world, tokens, w, monkeypatch):
    addr = _a(0)
    open_n, hid_n = _names("5")
    world.assets(addresses=[addr], records=[(open_n, "A", addr), (hid_n, "A", addr)])
    (fid,) = world.write(world.finding(addr, _vp(addr), source="version_match", finding_type="cve"))
    monkeypatch.setattr(exposure_path, "MAX_CANDIDATES", 1)

    admin_host = _hop(_body(tokens, "admin", fid), "host")
    assert len(admin_host["candidates"]) == 1 and admin_host["candidates_truncated"] is True
    viewer_host = _hop(_body(tokens, "viewer", fid), "host")
    assert [c["value"] for c in viewer_host["candidates"]] == [open_n]
    assert viewer_host["candidates_truncated"] is False


# -- A6 ----------------------------------------------------------------------------


def test_a6_withheld_address_asset(world, tokens, w):
    addr, hidden = _a(0), _a(2)
    host_n = f"host6-{_LABEL}.example.org"
    world.assets(addresses=[addr, hidden], records=[(host_n, "A", addr)])
    world.inventory(hidden, [_port(_PORT, "tcp", "nginx", "1.2")])
    w.link(world.db, hidden)
    host_id = world.asset_id("dns_record", host_n)
    host_ports = [
        e for (ports,) in world.db.query(AssetState.open_ports).filter(AssetState.asset_canonical_id == host_id)
        for e in (ports or [])
    ]
    assert host_ports == [], "precondition: the hostname asset's own port inventory is empty (a state row may exist)"
    (fid,) = world.write(world.finding(
        host_n, [ObservedEndpoint(address=hidden, port=_PORT, protocol=None)], source="nuclei",
        finding_type="tech-detect"))
    hidden_id = world.asset_id("ip_address", hidden)

    for who in ("admin", "viewer+E1"):
        full = _body(tokens, who, fid)
        assert _hop(full, "address")["status"] == "observed"
        assert _hop(full, "address")["asset_id"] == str(hidden_id)
        svc = _hop(full, "service")
        assert svc["status"] == "observed" and svc["service"] == "nginx" and svc["asset_id"] == str(hidden_id)

    body = _body(tokens, "viewer", fid)
    address = _hop(body, "address")
    assert address["status"] == "observed" and address["address"] == hidden and address["asset_id"] is None
    service = _hop(body, "service")
    assert service["status"] == "unknown" and service["reason"] == _NO_INVENTORY_ENTRY
    assert service["service"] is None and service["version"] is None and service["sources"] == []
    assert service["asset_id"] is None
    _assert_absent(body, str(hidden_id))

    _drop(world, [hidden])
    assert _body(tokens, "viewer", fid)["exposure_paths"] == body["exposure_paths"]
    # the admin no longer gets the asset or the service either
    assert _hop(_body(tokens, "admin", fid), "service")["status"] == "unknown"


# -- A7 ----------------------------------------------------------------------------


def test_a7_derived_addresses_are_scoped(world, tokens, w):
    addr2, hidden = _a(1), _a(3)
    multi_n = f"multi7-{_LABEL}.example.org"
    world.assets(addresses=[addr2, hidden], records=[(multi_n, "A", addr2), (multi_n, "A", hidden)])
    (fid,) = world.write(world.finding(
        multi_n, [ObservedEndpoint(address=None, port=_PORT, protocol=None)], source="nuclei",
        finding_type="tech-detect"))
    w.link(world.db, hidden)
    hidden_id = world.asset_id("ip_address", hidden)

    for who in ("admin", "viewer+E1"):
        full_addr = _hop(_body(tokens, who, fid), "address")
        assert full_addr["status"] == "derived"
        assert sorted(c["value"] for c in full_addr["candidates"]) == sorted([addr2, hidden])

    body = _body(tokens, "viewer", fid)
    viewer_addr = _hop(body, "address")
    assert viewer_addr["status"] == "derived"
    assert [c["value"] for c in viewer_addr["candidates"]] == [addr2]
    _assert_absent(body, hidden, str(hidden_id))


# -- A8 ----------------------------------------------------------------------------


def test_a8_without_assets_read_permission_nothing_about_other_assets(world, monkeypatch):
    addr = _a(0)
    n1, n2 = f"open8a-{_LABEL}.example.org", f"open8b-{_LABEL}.example.org"
    world.assets(addresses=[addr], records=[(n1, "A", addr), (n2, "A", addr)])
    world.inventory(addr, [_port(_PORT, "tcp", "nginx", "1.2")])
    (fid,) = world.write(world.finding(addr, _vp(addr), source="version_match", finding_type="cve"))
    own_id = world.asset_id("ip_address", addr)
    _, uid = _make_user("admin")
    try:
        user = world.db.get(User, uid)
        finding = world.db.get(FindingCanonical, fid)
        asset = world.db.get(AssetCanonical, finding.asset_canonical_id)

        def hops():
            (path,) = exposure_path.build_exposure_paths(world.db, user, finding, asset)
            return {h.kind: h for h in path.hops}

        h = hops()  # precondition: with the permission, the same call lists both and finds the service
        assert sorted(c.value for c in h["host"].candidates) == sorted([n1, n2])
        assert h["service"].status == "observed"

        monkeypatch.setattr(exposure_path, "has_permission", lambda *a, **k: False)
        h = hops()
        assert h["host"].status == "unknown" and h["host"].reason == _NO_HOSTNAME and h["host"].candidates == []
        assert h["service"].status == "unknown" and h["service"].reason == _NO_INVENTORY_ENTRY
        assert h["address"].status == "observed" and h["address"].asset_id == own_id
    finally:
        _cleanup_user(uid)


# -- A9 ----------------------------------------------------------------------------


def test_a9_unreadable_finding_is_still_404(world, tokens, w):
    addr = _a(0)
    _, hid_n = _names("9")
    world.assets(addresses=[addr], records=[(hid_n, "A", addr)])
    (fid,) = world.write(world.finding(hid_n, _vp(addr), source="nuclei", finding_type="tech-detect"))

    r = _get(tokens, "admin", fid)
    assert r.status_code == 200 and len(r.json()["exposure_paths"]) == 1
    assert _get(tokens, "viewer+E1", fid).status_code == 200
    r = _get(tokens, "viewer", fid)
    assert r.status_code == 404
    assert "exposure_paths" not in r.json()


# -- A10 ---------------------------------------------------------------------------


def test_a10_walk_does_not_expand_through_a_withheld_record_row_of_a_readable_name(world, tokens, w):
    addr = _a(0)
    n = f"open10-{_LABEL}.example.org"
    top = f"top10-{_LABEL}.example.org"
    # n has a readable A row and a second (TXT) row; top has one TXT row, which
    # makes no edge of its own, so the only edge from top is the one inserted below.
    world.assets(addresses=[addr], records=[(n, "A", addr), (n, "TXT", "v10"), (top, "TXT", "t10")])
    world.db.expire_all()
    n_rows = {
        r.id: r for r in world.db.query(AssetCanonical).filter(
            AssetCanonical.asset_type == "dns_record", AssetCanonical.value == n)
    }
    assert len(n_rows) == 2
    addr_id = world.asset_id("ip_address", addr)
    a_row = world.db.query(AssetEdge.source_id).filter(
        AssetEdge.target_id == addr_id, AssetEdge.source_id.in_(list(n_rows))).one()[0]
    hidden_row = next(i for i in n_rows if i != a_row)
    top_id = world.asset_id("dns_record", top)

    now = datetime.now(timezone.utc)
    world.db.add(TargetAssetLink(target_id=w.target_id, asset_canonical_id=hidden_row,
                                 first_linked_at=now, last_observed_at=now))
    world.db.add(AssetEdge(source_type="asset_canonical", source_id=top_id, target_type="asset_canonical",
                           target_id=hidden_row, edge_type="resolves_to",
                           edge_metadata={"record_type": "CNAME"}))
    world.db.commit()
    assert world.db.query(AssetEdge).filter(AssetEdge.source_id == top_id).count() == 1, (
        "precondition: exactly one edge has top's row as source")

    (fid,) = world.write(world.finding(addr, _vp(addr), source="version_match", finding_type="cve"))

    for who in ("admin", "viewer+E1"):
        host = _hop(_body(tokens, who, fid), "host")
        assert [(c["value"], c["distance"]) for c in host["candidates"]] == [(n, 1), (top, 2)]

    body = _body(tokens, "viewer", fid)
    host = _hop(body, "host")
    assert host["status"] == "derived"
    assert [(c["value"], c["distance"]) for c in host["candidates"]] == [(n, 1)]
    _assert_absent(body, top, str(top_id), str(hidden_row))


# -- A11 ---------------------------------------------------------------------------


def test_a11_own_hostname_inventory_needs_assets_read(world, monkeypatch):
    addr = _a(0)
    host_n = f"host11-{_LABEL}.example.org"
    world.assets(addresses=[addr], records=[(host_n, "A", addr)])
    host_id = _host_inventory(world, host_n, [_port(_PORT, "tcp", "envoy", "1.1")])
    addr_id = world.asset_id("ip_address", addr)
    addr_ports = [
        e for (ports,) in world.db.query(AssetState.open_ports).filter(AssetState.asset_canonical_id == addr_id)
        for e in (ports or [])
    ]
    assert addr_ports == [], "precondition: the address asset has no entry for the port"
    (fid,) = world.write(world.finding(
        host_n, [ObservedEndpoint(address=addr, port=_PORT, protocol=None)], source="nuclei",
        finding_type="tech-detect"))
    _, uid = _make_user("admin")
    try:
        user = world.db.get(User, uid)
        finding = world.db.get(FindingCanonical, fid)
        asset = world.db.get(AssetCanonical, finding.asset_canonical_id)

        def service():
            (path,) = exposure_path.build_exposure_paths(world.db, user, finding, asset)
            return {h.kind: h for h in path.hops}["service"]

        before = service()
        assert before.status == "observed" and before.service == "envoy" and before.asset_id == host_id

        monkeypatch.setattr(exposure_path, "has_permission", lambda *a, **k: False)
        after = service()
        assert after.status == "unknown" and after.reason == _NO_INVENTORY_ENTRY
        assert after.service is None and after.version is None
    finally:
        _cleanup_user(uid)
