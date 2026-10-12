"""Redirect-following through the probe gate (planning#268).

Real `assets_canonical` / `asset_state` rows and the REAL gate
(`authorise_probes`) throughout; nothing here monkeypatches the gate. The two
seams that are spied are the TRANSPORT: `httpx.post` (the worker call, as seen
from `app.connectors.httpx_probe`) and `socket.getaddrinfo` (our own DNS).

Every hostname carries a per-test suffix and lives under `example.com` or a
sibling `.example` name; every address is RFC 5737.

The two guards a mutation would target, and the test that pins each:
  * `ProbePermission.allowed` (not `GateResult.permitted`): test_log_only_...
  * tightest-wins across a hostname's dns_record rows: test_tightest_wins_...

Run with:  pytest app/tests/test_redirect_follow.py
"""

import socket
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

import httpx

from app.connectors import httpx_probe
from app.connectors.base import DiscoveredAsset
from app.connectors.httpx_probe import HttpxConnector
from app.core.database import SessionLocal
from app.models.app_settings import AppSetting
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.authorisation_decision import AuthorisationDecision
from app.models.claim import AssetClaim
from app.models.engagement import Engagement
from app.models.http_redirect_hop import HttpRedirectHop
from app.models.observer import Observer
from app.models.scan import ScanRun, ScanStatus
from app.models.target import Target
from app.models.target_asset_link import TargetAssetLink
from app.services import app_settings, web_classifier
from app.services import redirect_follow as rf
from app.tests import _decision_log, _docaddr
from app.tests._engagement import make_engagement

_MODE_KEY = "probe_authorisation_mode"


# -- environment ----------------------------------------------------------------

class _Env:
    """One test's rows, spies and cleanup."""

    def __init__(self):
        self.db = SessionLocal()
        self.sfx = uuid.uuid4().hex[:8]
        self.mark = _decision_log.watermark()
        self.target_ids: list[uuid.UUID] = []
        self.worker_calls: list[dict] = []   # one entry per fetch target posted
        self.post_count = 0
        self.dns_lookups: list[str] = []
        self.dns_answers: dict[str, list[str]] = {}
        self.fetch_behaviour = lambda target: {"status_code": 200, "title": "Page", "location": None}
        self.connector = HttpxConnector()
        run = ScanRun(id=uuid.uuid4(), status=ScanStatus.PENDING, scope={})
        self.db.add(run)
        self.db.commit()
        self.run_id = run.id
        self._real_post = httpx_probe.httpx.post
        self._real_gai = socket.getaddrinfo
        httpx_probe.httpx.post = self._post
        socket.getaddrinfo = self._gai

    # spies
    def _post(self, url, json=None, headers=None, timeout=None, **kw):
        assert url.endswith("/httpx/fetch"), url
        self.post_count += 1
        results = []
        for target in json["targets"]:
            self.worker_calls.append(target)
            results.append({"id": target["id"], "error": None, "title": None, "location": None,
                            "status_code": None, **self.fetch_behaviour(target)})

        class _Resp:
            def raise_for_status(self):
                return None

            def json(self):
                return {"results": results}

        return _Resp()

    def _gai(self, host, port, *args, **kwargs):
        if host in self.dns_answers:
            self.dns_lookups.append(host)
            return [
                (socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 (a, port, 0, 0) if ":" in a else (a, port))
                for a in self.dns_answers[host]
            ]
        if isinstance(host, str) and self.sfx in host:
            self.dns_lookups.append(host)
            raise socket.gaierror("unexpected lookup of a test host")
        return self._real_gai(host, port, *args, **kwargs)

    # rows
    def name(self, label: str, domain: str = "example.com") -> str:
        return f"{label}-{self.sfx}.{domain}"

    def _state(self, asset_id, probe_class: str, open_ports=None) -> None:
        self.db.add(AssetState(
            asset_canonical_id=asset_id, attributes={"probe_class": probe_class},
            open_ports=open_ports or [], projected_at=datetime.now(timezone.utc),
        ))
        self.db.commit()

    def ip(self, value: str, *, parent: str | None = None, probe_class: str = "direct_addressable",
           open_ports=None) -> AssetCanonical:
        now = datetime.now(timezone.utc)
        row = AssetCanonical(id=uuid.uuid4(), asset_type="ip_address", value=value, parent_value=parent,
                             first_seen_at=now, last_seen_at=now)
        self.db.add(row)
        self.db.commit()
        self._state(row.id, probe_class, open_ports)
        return row

    def dns(self, value: str, *, record_type: str = "A", content: str = "192.0.2.10",
            probe_class: str = "name_only", row_id: uuid.UUID | None = None) -> AssetCanonical:
        now = datetime.now(timezone.utc)
        row = AssetCanonical(id=row_id or uuid.uuid4(), asset_type="dns_record", value=value, record_type=record_type,
                             content=content, first_seen_at=now, last_seen_at=now)
        self.db.add(row)
        self.db.commit()
        self._state(row.id, probe_class)
        return row

    def target(self, value: str, *, pre_close: bool = False) -> Target:
        engagement_id = make_engagement(self.db, "pre_close").id if pre_close else None
        row = Target(id=uuid.uuid4(), type="domain", value=value, engagement_id=engagement_id)
        self.db.add(row)
        self.db.commit()
        self.target_ids.append(row.id)
        return row

    def link(self, target: Target, asset: AssetCanonical) -> None:
        self.db.add(TargetAssetLink(target_id=target.id, asset_canonical_id=asset.id))
        self.db.commit()

    # the unit under test
    def follow(self, patches, *, owned=frozenset(), target_ids=None, timeout: float = 5.0) -> dict:
        stats = rf.follow_redirects(
            self.db, connector=self.connector, patches=patches, scope={}, scan_run_id=self.run_id,
            owned_domains=owned, target_ids=target_ids or [], timeout=timeout,
        )
        self.db.commit()
        return stats

    def hops(self, asset: AssetCanonical, port: int = 80) -> list[HttpRedirectHop]:
        self.db.expire_all()
        return (
            self.db.query(HttpRedirectHop)
            .filter(HttpRedirectHop.origin_asset_id == asset.id, HttpRedirectHop.origin_port == port)
            .order_by(HttpRedirectHop.hop_index).all()
        )

    def canonical(self, value: str) -> list[AssetCanonical]:
        self.db.expire_all()
        return self.db.query(AssetCanonical).filter(AssetCanonical.value == value).all()

    def close(self) -> None:
        httpx_probe.httpx.post = self._real_post
        socket.getaddrinfo = self._real_gai
        db = self.db
        try:
            db.rollback()
            db.query(AssetCanonical).filter(AssetCanonical.value.like(f"%{self.sfx}%")).delete(synchronize_session=False)
            ip_ids = [r[0] for r in db.query(AssetCanonical.id).filter(AssetCanonical.parent_value.like(f"%{self.sfx}%")).all()]
            if ip_ids:
                db.query(AssetCanonical).filter(AssetCanonical.id.in_(ip_ids)).delete(synchronize_session=False)
            db.commit()
            if self.target_ids:
                engagement_ids = [r[0] for r in db.query(Target.engagement_id).filter(Target.id.in_(self.target_ids)).all()
                                  if r[0] is not None]
                db.query(Target).filter(Target.id.in_(self.target_ids)).delete(synchronize_session=False)
                db.commit()
                if engagement_ids:
                    db.query(Engagement).filter(Engagement.id.in_(engagement_ids)).delete(synchronize_session=False)
                    db.commit()
            db.query(HttpRedirectHop).filter(HttpRedirectHop.scan_run_id == self.run_id).delete(synchronize_session=False)
            _decision_log.cleanup_for_run(self.run_id)
            db.query(ScanRun).filter(ScanRun.id == self.run_id).delete(synchronize_session=False)
            db.commit()
            _decision_log.cleanup_since(self.mark)
        finally:
            db.close()


@contextmanager
def _env():
    env = _Env()
    try:
        yield env
    finally:
        env.close()


def _patch(value: str, port: int = 80, *, status: int = 302, location: str | None = "login.php",
           scheme: str = "http", asset_type: str = "ip_address", extra_meta: dict | None = None) -> DiscoveredAsset:
    entry = {"port": port, "service": scheme, "http_status": status}
    if location is not None:
        entry["http_location"] = location
    meta = {"open_ports": [entry], **(extra_meta or {})}
    return DiscoveredAsset(asset_type=asset_type, value=value, asset_metadata=meta)


def _set_mode(db, value: str | None) -> None:
    if value is None:
        db.query(AppSetting).filter(AppSetting.key == _MODE_KEY).delete()
        db.commit()
    else:
        app_settings.set_value(db, _MODE_KEY, value)


# -- 1. the lab shape ------------------------------------------------------------

def test_lab_shape_bare_relative_location_is_fetched_on_the_origin_ip():
    with _env() as env:
        ip = _docaddr.alloc()
        origin = env.ip(ip, parent=env.name("lab"), open_ports=[
            {"port": 80, "service": "http", "http_status": 302, "http_location": "login.php"},
        ])
        env.fetch_behaviour = lambda t: {"status_code": 200, "title": "Sign in"}

        stats = env.follow([_patch(ip)])

        assert len(env.worker_calls) == 1
        call = env.worker_calls[0]
        assert call["path"] == "/login.php", call
        assert call["ip"] == ip and call["host"] is None
        assert call["scheme"] == "http" and call["port"] == 80
        rows = env.hops(origin)
        assert len(rows) == 1
        row = rows[0]
        assert row.hop_index == 1 and row.followed is True and row.reason is None
        assert row.http_status == 200 and row.http_title == "Sign in"
        assert row.url == f"http://{ip}/login.php"
        assert row.hop_asset_id == origin.id
        assert row.origin_scheme == "http" and row.scan_run_id == env.run_id
        assert stats["chains"] == 1 and stats["followed"] == 1 and stats["refused"] == {}

        # Hop data never lands on the origin's own port entry.
        env.db.expire_all()
        entry = env.db.get(AssetState, origin.id).open_ports[0]
        assert "http_title" not in entry
        # The gate really decided (not skipped): one decision row for the hop.
        assert env.db.query(AuthorisationDecision).filter(
            AuthorisationDecision.asset_canonical_id == origin.id
        ).count() >= 1


def test_ip_literal_hop_without_authorised_names_is_denied_by_the_name_addressed_gate():
    """httpx is name-addressing: an IP with no parent_value has no authorised
    name, so the gate denies it and nothing is fetched. Pins the consequence
    of the spec's 'allowed iff the permission allows' for IP literals."""
    with _env() as env:
        ip = _docaddr.alloc()
        origin = env.ip(ip, parent=None)
        env.follow([_patch(ip)])
        rows = env.hops(origin)
        assert [(r.followed, r.reason) for r in rows] == [(False, "no_authorised_names")]
        assert env.worker_calls == []


def test_ip_literal_with_no_canonical_row_is_unresolved_and_mints_nothing():
    with _env() as env:
        origin_ip, other = _docaddr.alloc(), "203.0.113.77"
        origin = env.ip(origin_ip, parent=env.name("o"))
        env.follow([_patch(origin_ip, location=f"http://{other}/x")])
        rows = env.hops(origin)
        assert [(r.followed, r.reason, r.hop_asset_id) for r in rows] == [(False, "unresolved_asset", None)]
        assert env.worker_calls == []
        assert env.canonical(other) == []


# -- 2. an out-of-scope hostname -------------------------------------------------

def test_unknown_hostname_is_not_fetched_not_resolved_and_becomes_a_no_probe_node():
    with _env() as env:
        ip_a, ip_b = _docaddr.alloc(), _docaddr.alloc()
        a = env.ip(ip_a, parent=env.name("a"))
        b = env.ip(ip_b, parent=env.name("b"))
        stranger = env.name("login", "fabrikam-other.example")
        env.dns_answers[stranger] = ["203.0.113.9"]  # would resolve, if we ever looked

        env.follow([
            _patch(ip_a, location=f"https://{stranger}/"),
            _patch(ip_b, location="/ok"),
        ])

        # The path was REACHED: the other origin's relative hop did fetch.
        assert [c["path"] for c in env.worker_calls] == ["/ok"]
        assert env.dns_lookups == [], "no DNS lookup for a host the gate never allowed"
        rows = env.hops(a)
        assert [(r.followed, r.reason, r.url) for r in rows] == [(False, "unresolved_asset", f"https://{stranger}/")]
        assert env.hops(b)[0].followed is True

        minted = env.canonical(stranger)
        assert len(minted) == 1 and minted[0].asset_type == "dns_record"
        assert rows[0].hop_asset_id == minted[0].id
        claim = (
            env.db.query(AssetClaim, Observer.name)
            .join(Observer, Observer.id == AssetClaim.observer_id)
            .filter(AssetClaim.asset_canonical_id == minted[0].id, AssetClaim.claim_type == "third_party_dependency")
            .one()
        )
        assert claim[1] == "redirect"
        assert claim[0].claim_value.get("discovered_via") == "redirect"
        assert env.db.get(AssetState, minted[0].id).attributes.get("probe_class") == "no_probe"


# -- 3. an unknown hostname under an owned domain ---------------------------------

def test_unknown_owned_hostname_is_recorded_as_a_discovered_name_and_never_fetched():
    with _env() as env:
        ip = _docaddr.alloc()
        origin = env.ip(ip, parent=env.name("o"))
        apex = f"{env.sfx}.example.com"
        target = env.target(apex)
        host = f"new.{apex}"
        env.dns_answers[host] = ["203.0.113.10"]

        stats = env.follow([_patch(ip, location=f"https://{host}/portal")],
                           owned=frozenset({apex}), target_ids=[target.id])

        assert env.worker_calls == [] and env.dns_lookups == []
        minted = env.canonical(host)
        assert len(minted) == 1
        assert env.hops(origin)[0].hop_asset_id == minted[0].id
        assert env.hops(origin)[0].reason == "unresolved_asset"
        assert stats["leads_minted"] == 1
        names = [
            n for (n,) in env.db.query(Observer.name)
            .join(AssetClaim, AssetClaim.observer_id == Observer.id)
            .filter(AssetClaim.asset_canonical_id == minted[0].id).all()
        ]
        assert names and set(names) == {"redirect"}
        # Owned: NOT a third-party node.
        assert env.db.query(AssetClaim).filter(
            AssetClaim.asset_canonical_id == minted[0].id, AssetClaim.claim_type == "third_party_dependency"
        ).count() == 0
        assert env.db.query(TargetAssetLink).filter(
            TargetAssetLink.target_id == target.id, TargetAssetLink.asset_canonical_id == minted[0].id
        ).count() == 1


# -- 4 / 5. posture, tightest wins -------------------------------------------------

def test_pre_close_hop_asset_is_refused_with_the_gates_own_rule():
    with _env() as env:
        ip = _docaddr.alloc()
        origin = env.ip(ip, parent=env.name("o"))
        host = env.name("deal")
        asset = env.dns(host)
        env.link(env.target(env.name("tgt"), pre_close=True), asset)
        env.dns_answers[host] = ["203.0.113.11"]

        env.follow([_patch(ip, location=f"https://{host}/")])

        rows = env.hops(origin)
        assert [(r.followed, r.reason, r.hop_asset_id) for r in rows] == [(False, "posture:passive_only", asset.id)]
        assert env.worker_calls == [] and env.dns_lookups == []


def test_tightest_wins_across_a_hostnames_dns_record_rows():
    """The restricting row is the FIRST candidate (lowest id) for one host and
    the LAST for the other, so a check that only looks at one end is caught."""
    with _env() as env:
        ip = _docaddr.alloc()
        origin = env.ip(ip, parent=env.name("o"))
        clean = env.name("clean")
        tgt = env.target(env.name("tgt"), pre_close=True)
        env.dns(clean, record_type="A", content="192.0.2.11")
        env.dns(clean, record_type="AAAA", content="2001:db8::11")
        env.dns_answers[clean] = ["203.0.113.13"]

        def uid(n):
            return uuid.UUID(int=(0x0C0FFEE << 64) | n)

        for label, restricted_id, other_id in (("first", uid(1), uid(2)), ("last", uid(4), uid(3))):
            host = env.name(f"mixed-{label}")
            env.dns_answers[host] = ["203.0.113.12"]
            env.dns(host, record_type="A", content="192.0.2.10", row_id=other_id)
            restricted = env.dns(host, record_type="AAAA", content="2001:db8::10", row_id=restricted_id)
            env.link(tgt, restricted)   # only ONE of the two rows is pre_close
            env.follow([_patch(ip, location=f"https://{host}/")])
            assert [(r.followed, r.reason) for r in env.hops(origin)] == [(False, "posture:passive_only")], label
            assert env.worker_calls == [], label

        # Control: the same shape with no restricting row IS fetched, so the
        # refusals above are the restricting row's doing, not the shape's.
        env.follow([_patch(ip, location=f"https://{clean}/")])
        assert [(r.followed, r.reason) for r in env.hops(origin)] == [(True, None)]
        assert [c["host"] for c in env.worker_calls] == [clean]


# -- 6. SSRF -----------------------------------------------------------------------

def test_ssrf_blocked_resolution_is_refused_after_the_gate_allows():
    with _env() as env:
        ip = _docaddr.alloc()
        origin = env.ip(ip, parent=env.name("o"))
        metadata, mixed, fine = env.name("meta"), env.name("mix"), env.name("fine")
        for h in (metadata, mixed, fine):
            env.dns(h)
        env.dns_answers[metadata] = ["169.254.169.254"]
        env.dns_answers[mixed] = ["203.0.113.14", "10.0.0.5"]
        env.dns_answers[fine] = ["203.0.113.15"]

        for host, expect_fetch in ((metadata, False), (mixed, False), (fine, True)):
            env.worker_calls.clear()
            env.follow([_patch(ip, location=f"https://{host}/x")])
            rows = env.hops(origin)
            if expect_fetch:
                assert [(r.followed, r.reason) for r in rows] == [(True, None)], host
                assert [c["ip"] for c in env.worker_calls] == ["203.0.113.15"]
                assert env.worker_calls[0]["host"] == fine
            else:
                assert [(r.followed, r.reason) for r in rows] == [(False, "ssrf_blocked")], host
                assert env.worker_calls == []
        assert metadata in env.dns_lookups  # the SSRF check did run its lookup


def test_dns_failure_is_refused_as_dns_failed():
    with _env() as env:
        ip = _docaddr.alloc()
        origin = env.ip(ip, parent=env.name("o"))
        host = env.name("gone")
        env.dns(host)   # allowed by the gate; no dns_answers entry => gaierror
        env.follow([_patch(ip, location=f"https://{host}/")])
        assert [(r.followed, r.reason) for r in env.hops(origin)] == [(False, "dns_failed")]
        assert env.worker_calls == []


def test_worker_blocked_is_stored_as_unfollowed_ssrf_blocked():
    with _env() as env:
        ip = _docaddr.alloc()
        origin = env.ip(ip, parent=env.name("o"))
        env.fetch_behaviour = lambda t: {"error": "blocked"}
        env.follow([_patch(ip)])
        assert [(r.followed, r.reason, r.http_status) for r in env.hops(origin)] == [(False, "ssrf_blocked", None)]


def test_a_non_redirect_status_with_a_location_header_ends_the_chain():
    """Only a 3xx is followed: a 200 (or 201) that happens to send a
    Location header is a final answer, not a redirect."""
    with _env() as env:
        ip = _docaddr.alloc()
        origin = env.ip(ip, parent=env.name("o"))
        env.fetch_behaviour = lambda t: {"status_code": 200, "title": "Home", "location": "/next"}
        env.follow([_patch(ip)])
        assert len(env.worker_calls) == 1
        assert [(r.hop_index, r.followed, r.http_status) for r in env.hops(origin)] == [(1, True, 200)]


def test_worker_unavailable_is_not_recorded_as_followed():
    """`followed` means a request went out; an unreachable worker sent none."""
    with _env() as env:
        ip = _docaddr.alloc()
        origin = env.ip(ip, parent=env.name("o"))
        env.fetch_behaviour = lambda t: {"error": "worker_unavailable"}
        env.follow([_patch(ip)])
        assert len(env.worker_calls) == 1  # reached the fetch step
        assert [(r.followed, r.reason, r.http_status) for r in env.hops(origin)] == [
            (False, "worker_unavailable", None)
        ]


def test_worker_timeout_is_still_followed_with_null_status_and_counted():
    with _env() as env:
        ip = _docaddr.alloc()
        origin = env.ip(ip, parent=env.name("o"))
        env.fetch_behaviour = lambda t: {"error": "timeout"}
        stats = env.follow([_patch(ip)])
        rows = env.hops(origin)
        assert [(r.followed, r.reason, r.http_status) for r in rows] == [(True, None, None)]
        assert stats["fetch_errors"] == {"timeout": 1}


# -- 7. log_only does not let a denied hop through ----------------------------------

def test_log_only_still_refuses_a_hop_the_gate_denies():
    """Jason's #268 decision: hops follow the gate's REAL verdict in both
    modes. Under log_only `GateResult.permitted` is the unfiltered input, so
    an implementation reading it would fetch this no_probe host."""
    with _env() as env:
        _set_mode(env.db, "log_only")
        try:
            assert app_settings.get(env.db, _MODE_KEY) == "log_only"
            ip = _docaddr.alloc()
            origin = env.ip(ip, parent=env.name("o"))
            denied, allowed = env.name("vendor"), env.name("ours")
            env.dns(denied, probe_class="no_probe")
            env.dns(allowed)
            env.dns_answers[denied] = ["203.0.113.16"]
            env.dns_answers[allowed] = ["203.0.113.17"]

            env.follow([_patch(ip, location=f"https://{denied}/")])
            assert [(r.followed, r.reason) for r in env.hops(origin)] == [(False, "probe_class:no_probe")]
            assert env.worker_calls == [] and env.dns_lookups == []

            env.follow([_patch(ip, location=f"https://{allowed}/")])   # control: the path is reachable
            assert [(r.followed, r.reason) for r in env.hops(origin)] == [(True, None)]
        finally:
            _set_mode(env.db, None)


# -- 8. hop cap and loop ------------------------------------------------------------

def test_hop_cap_makes_exactly_five_fetches_and_refuses_the_sixth():
    with _env() as env:
        ip = _docaddr.alloc()
        origin = env.ip(ip, parent=env.name("o"))

        def chase(target):
            n = int(target["path"].removeprefix("/p"))
            return {"status_code": 302, "location": f"/p{n + 1}"}

        env.fetch_behaviour = chase
        stats = env.follow([_patch(ip, location="/p1")])

        assert [c["path"] for c in env.worker_calls] == ["/p1", "/p2", "/p3", "/p4", "/p5"]
        rows = env.hops(origin)
        assert [r.hop_index for r in rows] == [1, 2, 3, 4, 5, 6]
        assert all(r.followed for r in rows[:5])
        assert (rows[5].followed, rows[5].reason, rows[5].url) == (False, "hop_cap", f"http://{ip}/p6")
        assert stats["followed"] == 5 and stats["refused"] == {"hop_cap": 1}


def test_a_to_b_to_a_is_refused_as_a_loop():
    with _env() as env:
        ip = _docaddr.alloc()
        origin = env.ip(ip, parent=env.name("o"))
        env.fetch_behaviour = lambda t: {"status_code": 302, "location": "/"}   # back to the origin
        env.follow([_patch(ip, location="/b")])
        assert len(env.worker_calls) == 1
        assert [(r.hop_index, r.followed, r.reason) for r in env.hops(origin)] == [(1, True, None), (2, False, "loop")]


# -- 9. replacement -------------------------------------------------------------------

def test_a_reprobed_endpoint_replaces_its_chain_and_unprobed_endpoints_keep_theirs():
    with _env() as env:
        ip = _docaddr.alloc()
        origin = env.ip(ip, parent=env.name("o"))
        env.follow([
            DiscoveredAsset(asset_type="ip_address", value=ip, asset_metadata={"open_ports": [
                {"port": 80, "service": "http", "http_status": 302, "http_location": "/a"},
                {"port": 8080, "service": "http", "http_status": 302, "http_location": "/b"},
            ]}),
        ])
        assert len(env.hops(origin, 80)) == 1 and len(env.hops(origin, 8080)) == 1

        # Next run probes only port 80, and it no longer redirects.
        env.follow([_patch(ip, 80, status=200, location=None)])
        assert env.hops(origin, 80) == []
        assert len(env.hops(origin, 8080)) == 1

        # Probed again and still redirecting elsewhere: replaced, not appended.
        env.follow([_patch(ip, 8080, location="/c")])
        rows = env.hops(origin, 8080)
        assert len(rows) == 1 and rows[0].url.endswith("/c")


# -- 10. parsing ----------------------------------------------------------------------

BASE = "http://198.51.100.1:80/"


def _ok(location, base=BASE):
    hop, _ = rf.parse_hop(base, location)
    assert hop is not None, location
    return hop


def _refused(location, base=BASE):
    hop, shown = rf.parse_hop(base, location)
    assert hop is None, (location, hop)
    assert 1 <= len(shown) <= rf.MAX_URL_LEN
    return shown


def test_parse_bare_relative_location_resolves_per_rfc_3986():
    hop = _ok("login.php")
    assert (hop.url, hop.path, hop.host, hop.port, hop.scheme, hop.is_ip) == (
        "http://198.51.100.1/login.php", "/login.php", "198.51.100.1", 80, "http", True)
    assert _ok("../x", "http://198.51.100.1/a/b/c").path == "/a/x"
    assert _ok("?q=1", "http://198.51.100.1/p").path == "/p?q=1"
    assert _ok("/abs").path == "/abs"


def test_parse_refuses_unsupported_destinations():
    for loc in (
        "javascript:alert(1)", "ftp://host.example.com/x", "file:///etc/passwd", "data:text/html,hi",
        "https://user:pw@host.example.com/", "https://user@host.example.com/",
        "https:///nohost", "https://:443/", "http://host.example.com:0/", "http://host.example.com:99999/",
        "http://host.example.com:abc/", "http://[fe80::1%25eth0]/", "https://host.example.com//double",
        "https://host.example.com/" + "a" * 2100,
    ):
        _refused(loc)


def test_parse_drops_fragment_keeps_query_and_lowercases_host():
    hop = _ok("HTTPS://Login.Example.COM/Path?A=1&b=2#frag")
    assert hop.url == "https://login.example.com/Path?A=1&b=2"
    assert hop.path == "/Path?A=1&b=2" and hop.host == "login.example.com" and hop.port == 443


def test_parse_strips_a_trailing_dot_and_keeps_a_non_default_port():
    hop = _ok("https://login.example.com.:8443/x")
    assert hop.host == "login.example.com" and hop.port == 8443
    assert hop.url == "https://login.example.com:8443/x"


def test_parse_percent_encodes_non_ascii_and_spaces_but_not_existing_escapes():
    hop = _ok("/café menu?q=ü&x=%41")
    assert hop.path == "/caf%C3%A9%20menu?q=%C3%BC&x=%41"
    assert all(0x21 <= ord(c) <= 0x7E for c in hop.path)


def test_parse_normalises_ip_literals_including_ipv6():
    hop = _ok("http://[2001:DB8:0:0:0:0:0:1]:8080/x")
    assert hop.is_ip and hop.host == "2001:db8::1" and hop.port == 8080
    assert hop.url == "http://[2001:db8::1]:8080/x"
    v4 = _ok("http://203.0.113.5/")
    assert v4.is_ip and v4.host == "203.0.113.5" and v4.path == "/"
    assert rf.origin_url("https", "2001:db8::1", 8443) == "https://[2001:db8::1]:8443/"


def test_parse_idna_hostname_is_punycoded():
    assert _ok("https://bücher.example.com/").host == "xn--bcher-kva.example.com"


def test_parse_url_longer_than_the_cap_after_normalisation_is_refused():
    # Under the cap raw, over it once every non-ASCII char becomes %XX%XX.
    assert _refused("/" + "é" * 700)
    assert _ok("/" + "a" * 2000).url.endswith("a" * 2000)


# -- connector: fetch_urls --------------------------------------------------------------

def test_fetch_urls_chunks_at_200_and_reports_worker_unavailable_per_target():
    posts: list[int] = []
    real = httpx_probe.httpx.post

    class _Resp:
        def __init__(self, ids):
            self.ids = ids

        def raise_for_status(self):
            return None

        def json(self):
            return {"results": [{"id": i, "status_code": 200, "title": None, "location": None, "error": None}
                                for i in self.ids]}

    def fake_post(url, json=None, headers=None, timeout=None, **kw):
        posts.append(len(json["targets"]))
        assert json["concurrency"] == 5 and url.endswith("/httpx/fetch")
        if len(posts) == 2:
            raise httpx.ConnectError("down")
        return _Resp([t["id"] for t in json["targets"]])

    httpx_probe.httpx.post = fake_post
    try:
        targets = [{"id": f"t{i}", "ip": "203.0.113.1", "port": 80, "scheme": "http", "path": "/", "host": None}
                   for i in range(250)]
        out = HttpxConnector().fetch_urls(targets, timeout=5.0)
    finally:
        httpx_probe.httpx.post = real
    assert posts == [200, 50]
    assert [r["id"] for r in out] == [t["id"] for t in targets]
    assert {r["error"] for r in out[:200]} == {None}
    assert {r["error"] for r in out[200:]} == {"worker_unavailable"}


# -- 11. classifier ----------------------------------------------------------------------

def _hop_row(asset, port, index, *, followed=True, title=None, reason=None, run_id=None):
    return HttpRedirectHop(
        origin_asset_id=asset.id, origin_port=port, origin_scheme="http", hop_index=index,
        url=f"http://198.51.100.99/h{index}", followed=followed, reason=reason,
        http_status=200 if followed else None, http_title=title if followed else None,
    )


def test_classifier_input_carries_the_last_followed_hop_title_and_omits_it_otherwise():
    with _env() as env:
        asset = env.ip(_docaddr.alloc(), parent=env.name("o"), open_ports=[
            {"port": 80, "service": "http", "http_status": 302, "http_title": "Moved", "http_location": "/a"},
            {"port": 8080, "service": "http", "http_status": 200, "http_title": "Own"},
            {"port": 8443, "service": "https", "http_status": 302, "http_location": "/z"},
        ])
        env.db.add_all([
            _hop_row(asset, 80, 1, title="First hop"),
            _hop_row(asset, 80, 2, title="Last titled hop"),
            _hop_row(asset, 80, 3, followed=False, reason="hop_cap"),
            _hop_row(asset, 8443, 1, title=None),          # followed but untitled: nothing to say
        ])
        env.db.commit()
        env.db.refresh(asset)

        by_port = {e["port"]: web_classifier.build_input(asset, e) for e in web_classifier.web_endpoints(env.db, asset)}
        assert by_port[80]["endpoint"]["title_after_redirect"] == "Last titled hop"
        assert by_port[80]["endpoint"]["title"] == "Moved"          # the endpoint's own title is untouched
        assert "title_after_redirect" not in by_port[8080]["endpoint"]
        assert "title_after_redirect" not in by_port[8443]["endpoint"]
        # No chain, no change: the endpoint without a chain hashes as it did before.
        before = web_classifier.build_input(asset, {"port": 8080, "service": "http", "http_status": 200,
                                                    "http_title": "Own"})
        assert web_classifier.input_hash(by_port[8080]) == web_classifier.input_hash(before)
        assert "title_after_redirect" in web_classifier._SYSTEM_PROMPT
