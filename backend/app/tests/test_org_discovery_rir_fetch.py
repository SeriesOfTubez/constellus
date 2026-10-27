"""RIR lookup cache + fixed-URL fetcher (planning#278 S3b1).

The transport (`rir_fetch.connector_get`) is replaced with a recording fake;
nothing leaves the process. Synthetic handles and domains only.

Run with:  scripts/test.sh app/tests/test_org_discovery_rir_fetch.py
"""

import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from app.core.database import SessionLocal
from app.models.rir_lookup_cache import RirLookupCache
from app.services.org_discovery import rir_fetch as rf
from app.tests._org_world import hexid


class FakeResponse:
    def __init__(self, status_code=200, payload=None, raw=None):
        self.status_code = status_code
        self._payload = {"ok": True} if payload is None else payload
        self._raw = raw

    def json(self):
        if self._raw is not None:
            return json.loads(self._raw)
        return self._payload


class Transport:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        self.responses: list = []

    def __call__(self, url, **kw):
        self.calls.append((url, kw))
        item = self.responses.pop(0) if self.responses else FakeResponse()
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture
def transport(monkeypatch):
    t = Transport()
    monkeypatch.setattr(rf, "connector_get", t)
    return t


@pytest.fixture
def db():
    session = SessionLocal()
    created: list[str] = []
    session.created_paths = created
    try:
        yield session
    finally:
        session.rollback()
        session.query(RirLookupCache).filter(RirLookupCache.path.like("%rirf-%")).delete(synchronize_session=False)
        session.commit()
        session.close()


def _h() -> str:
    return f"RIRF-{hexid()}".upper()


def _path() -> str:
    # handle contains "rirf-" (case-insensitive match is not needed: lower the LIKE target via the handle itself)
    return rf.arin_poc(f"rirf-{hexid()}")


def _row(db, path):
    db.expire_all()
    return db.get(RirLookupCache, ("arin", path))


# ── validate_handle / builders ───────────────────────────────────────────────

@pytest.mark.parametrize("ok", ["EXAMPLE-1", "POC1-ARIN", "NET-192-0-2-0-1", "NET6-2001-DB8-1", "AS64500", "A", "a" * 64])
def test_validate_handle_accepts(ok):
    assert rf.validate_handle(ok) == ok


@pytest.mark.parametrize("bad", ["", "-X", "X-", "a/b", "a.b", "a;b", "a%2fb", "a b", "ａ", "a" * 65, ".."])
def test_validate_handle_rejects(bad):
    with pytest.raises(ValueError):
        rf.validate_handle(bad)


@pytest.mark.parametrize("builder", [
    rf.arin_poc, rf.arin_poc_orgs, rf.arin_org_nets, rf.arin_org_asns, rf.arin_net, rf.arin_net_children,
])
def test_builders_reject_a_bad_handle(builder):
    assert builder("EXAMPLE-1")
    for bad in ("a/b", "..", "", "a b"):
        with pytest.raises(ValueError):
            builder(bad)


def test_builder_shapes():
    assert rf.arin_poc("H1") == "poc/H1"
    assert rf.arin_poc_orgs("H1") == "poc/H1/orgs"
    assert rf.arin_org_nets("H1") == "org/H1/nets"
    assert rf.arin_org_asns("H1") == "org/H1/asns"
    assert rf.arin_net("H1") == "net/H1"
    assert rf.arin_net_children("H1") == "net/H1/children"


def test_domain_builder_normalises_and_rejects():
    assert rf.arin_pocs_by_domain("Example.COM") == "pocs;domain=example.com"
    for bad in ("a/b.com", "example..com", ""):
        with pytest.raises(ValueError):
            rf.arin_pocs_by_domain(bad)


def test_every_builder_output_passes_get_validation(db, transport):
    paths = [
        rf.arin_pocs_by_domain("fabrikam.com"), rf.arin_poc("POC1-ARIN"), rf.arin_poc_orgs("POC1-ARIN"),
        rf.arin_org_nets("EXAMPLE-1"), rf.arin_org_asns("EXAMPLE-1"), rf.arin_net("NET-192-0-2-0-1"),
        rf.arin_net_children("NET-192-0-2-0-1"),
    ]
    for p in paths:
        assert rf._ARIN_PATH_RE.fullmatch(p), p


# ── get: refusals ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("path", [
    "poc/../x", "poc/H?x=1", "net/H/children/x", "pocs;domain=a/b", "poc/H/", "poc/H/orgs/", "", "/poc/H",
    "pocs;domain=example", "poc/H#frag",
])
def test_get_refuses_a_hand_made_path(db, transport, path):
    b = rf.Budget()
    with pytest.raises(ValueError):
        rf.get(db, "arin", path, b)
    assert transport.calls == []
    assert b.used == 0


def test_get_refuses_an_unknown_rir(db, transport):
    with pytest.raises(ValueError):
        rf.get(db, "ripe", "poc/H1", rf.Budget())
    assert transport.calls == []


# ── get: cache behaviour ─────────────────────────────────────────────────────

def test_fresh_hit_makes_no_call(db, transport):
    path = _path()
    now = datetime.now(timezone.utc)
    db.add(RirLookupCache(rir="arin", path=path, status_code=200, body={"cached": 1}, fetched_at=now - timedelta(days=1)))
    db.flush()
    b = rf.Budget()
    assert rf.get(db, "arin", path, b, now=now) == {"cached": 1}
    assert b.cache_hits == 1 and b.used == 0
    assert transport.calls == []


def test_stale_row_is_refetched_and_updated(db, transport):
    path = _path()
    now = datetime.now(timezone.utc)
    old = now - rf.CACHE_TTL - timedelta(seconds=1)
    db.add(RirLookupCache(rir="arin", path=path, status_code=200, body={"old": 1}, fetched_at=old))
    db.flush()
    transport.responses.append(FakeResponse(200, {"new": 2}))
    b = rf.Budget()
    assert rf.get(db, "arin", path, b, now=now) == {"new": 2}
    assert len(transport.calls) == 1 and b.used == 1 and b.cache_hits == 0
    row = _row(db, path)
    assert row.body == {"new": 2} and row.fetched_at == now


def test_request_shape(db, transport):
    path = _path()
    rf.get(db, "arin", path, rf.Budget())
    (url, kw), = transport.calls
    assert url == rf.BASE_URLS["arin"] + path
    assert kw["follow_redirects"] is False
    assert kw["headers"] == {"Accept": "application/json"}


def test_a_200_is_cached_and_the_second_get_is_a_hit(db, transport):
    path = _path()
    b = rf.Budget()
    transport.responses.append(FakeResponse(200, {"a": 1}))
    assert rf.get(db, "arin", path, b) == {"a": 1}
    assert rf.get(db, "arin", path, b) == {"a": 1}
    assert len(transport.calls) == 1 and b.cache_hits == 1


def test_a_404_is_cached_with_null_body(db, transport):
    path = _path()
    b = rf.Budget()
    transport.responses.append(FakeResponse(404))
    assert rf.get(db, "arin", path, b) is None
    row = _row(db, path)
    assert row.status_code == 404
    assert db.execute(text("SELECT body IS NULL FROM rir_lookup_cache WHERE path = :p"), {"p": path}).scalar() is True
    assert rf.get(db, "arin", path, b) is None
    assert len(transport.calls) == 1 and b.cache_hits == 1


@pytest.mark.parametrize("response", [
    FakeResponse(500),
    FakeResponse(200, [1, 2]),
    FakeResponse(200, raw="not json"),
    RuntimeError("boom"),
])
def test_errors_raise_and_cache_nothing(db, transport, response):
    path = _path()
    transport.responses.append(response)
    with pytest.raises(rf.RirFetchError):
        rf.get(db, "arin", path, rf.Budget())
    assert len(transport.calls) == 1  # the path was reached
    assert _row(db, path) is None


def test_budget_exhaustion_blocks_the_second_miss_only(db, transport):
    p1, p2, p3 = _path(), _path(), _path()
    b = rf.Budget(limit=1)
    rf.get(db, "arin", p1, b)
    assert b.used == 1
    with pytest.raises(rf.BudgetExhausted):
        rf.get(db, "arin", p2, b)
    assert len(transport.calls) == 1
    assert b.used == 1
    # a cache hit still works with the budget spent
    assert rf.get(db, "arin", p1, b) == {"ok": True}
    assert b.cache_hits == 1 and len(transport.calls) == 1
    assert p3  # unused path, keeps the three distinct for cleanup


def test_budget_exhausted_is_a_rir_fetch_error():
    assert issubclass(rf.BudgetExhausted, rf.RirFetchError)


# ── schema CHECKs ────────────────────────────────────────────────────────────

def _insert(db, **over):
    values = dict(rir="arin", path=_path(), status_code=200, body={"a": 1})
    values.update(over)
    db.execute(RirLookupCache.__table__.insert().values(**values))
    db.flush()


@pytest.mark.parametrize("over, constraint", [
    (dict(rir="lacnic"), "ck_rir_lookup_cache_rir"),
    (dict(status_code=500, body=None), "ck_rir_lookup_cache_status"),
    (dict(status_code=200, body=None), "ck_rir_lookup_cache_body_iff_200"),
    (dict(status_code=404, body={"a": 1}), "ck_rir_lookup_cache_body_iff_200"),
    (dict(path="   "), "ck_rir_lookup_cache_path_nonblank"),
])
def test_checks_reject(db, over, constraint):
    from sqlalchemy import null
    if over.get("body", 1) is None:
        over = {**over, "body": null()}
    with pytest.raises(IntegrityError) as exc:
        _insert(db, **over)
    db.rollback()
    assert exc.value.orig.diag.constraint_name == constraint


def test_checks_accept_the_good_shapes(db):
    from sqlalchemy import null
    _insert(db)
    _insert(db, status_code=404, body=null())
    assert db.execute(select(RirLookupCache).where(RirLookupCache.path.like("%rirf-%"))).scalars().all()


# ── prefix-first ARIN builders (planning#278 S3c3b1) ─────────────────────────

@pytest.mark.parametrize("prefix, tail", [
    ("192.0.2.0/24", "192.0.2.0/24"),
    ("198.51.100.72/29", "198.51.100.72/29"),
    ("2001:db8::/32", "2001:db8::/32"),
    ("2001:db8:278:1::/64", "2001:db8:278:1::/64"),
])
def test_arin_cidr_builders_exact(prefix, tail):
    assert rf.arin_cidr_less(prefix) == f"cidr/{tail}/less"
    assert rf.arin_cidr_more(prefix) == f"cidr/{tail}/more"


@pytest.mark.parametrize("bad", [
    "192.0.2.1/24",  # host bits
    "192.0.2.0",  # no length
    "192.0.2.00/24",  # leading zero
    "2001:DB8::/32",  # upper case
    "2001:0db8::/32",  # expanded
    "2001:db8::1/32",  # host bits
    "192.0.2.0/24/less", "192.0.2.0/24?x=1", "192.0.2.0/24/../x", "../192.0.2.0/24", " 192.0.2.0/24",
    "", None, 5, b"192.0.2.0/24", ("192.0.2.0/24",),
])
def test_arin_cidr_builders_reject(bad):
    with pytest.raises(ValueError):
        rf.arin_cidr_less(bad)
    with pytest.raises(ValueError):
        rf.arin_cidr_more(bad)


@pytest.mark.parametrize("bad", [
    "cidr/192.0.2.1/24/less",
    "cidr/999.0.0.0/8/less",
    "cidr/2001:DB8::/32/less",
    "cidr/:::/32/less",
    "cidr/192.0.2.0/24/less/",
    "cidr/192.0.2.0/024/less",
    "cidr/192.0.2.0/33/less",
    "cidr/192.0.2.0/24/children",
    "cidr/192.0.2.0/24",
    "cidr/192.0.2.0/24/more?x=1",
    "cidr/2001:db8::/129/more",
])
def test_get_refuses_hand_built_cidr_paths_without_transport(db, transport, bad):
    b = rf.Budget()
    with pytest.raises(ValueError):
        rf.get(db, "arin", bad, b)
    assert transport.calls == [] and b.used == 0


@pytest.mark.parametrize("path", ["cidr/192.0.2.0/24/less", "cidr/192.0.2.0/24/more", "cidr/2001:db8::/32/less"])
def test_get_cidr_good_path_reaches_transport(db, transport, path):
    b = rf.Budget()
    assert rf.get(db, "arin", path, b) == {"ok": True}
    assert len(transport.calls) == 1
    assert transport.calls[0][0] == "https://whois.arin.net/rest/" + path
    assert transport.calls[0][1]["params"] is None


def test_cache_key_helper():
    assert rf.cache_key("net/H1", None) == "net/H1"
    assert rf.cache_key("search.json", (("b", "2"), ("a", "1 x"))) == "search.json?a=1+x&b=2"


def test_ripe_key():
    assert rf.ripe_key("192.0.2.0/24") == ("192.0.2.0 - 192.0.2.255", "inetnum")
    assert rf.ripe_key("198.51.100.72/29") == ("198.51.100.72 - 198.51.100.79", "inetnum")
    assert rf.ripe_key("2001:db8::/32") == ("2001:db8::/32", "inet6num")
    for bad in ("192.0.2.1/24", "2001:DB8::/32", None, "192.0.2.0"):
        with pytest.raises(ValueError):
            rf.ripe_key(bad)
