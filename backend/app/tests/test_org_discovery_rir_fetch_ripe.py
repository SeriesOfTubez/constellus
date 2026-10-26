"""RIPE queries through the fixed-URL fetcher (planning#278 S3b2 slice A).

The transport (`rir_fetch.connector_get`) is replaced with a recording fake;
nothing leaves the process. Synthetic handles, domains and documentation
address space only.

Run with:  scripts/test.sh app/tests/test_org_discovery_rir_fetch_ripe.py
"""

import json
from datetime import datetime, timezone

import pytest

from app.core.database import SessionLocal
from app.models.rir_lookup_cache import RirLookupCache
from app.services.org_discovery import rir_fetch as rf

ORG = "ORG-EXA1-TEST"
FLAGS = (("flags", "no-referenced"), ("flags", "no-irt"))
RANGE = "192.0.2.0 - 192.0.2.255"
V6 = "2001:db8::/32"


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = {"ok": True} if payload is None else payload

    def json(self):
        return json.loads(json.dumps(self._payload))


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
    try:
        yield session
    finally:
        session.rollback()
        # only this file's RIPE lookups write rir='ripe' rows
        session.query(RirLookupCache).filter(RirLookupCache.rir == "ripe").delete(synchronize_session=False)
        session.commit()
        session.close()


def _rows(db, rir="ripe") -> int:
    db.expire_all()
    return db.query(RirLookupCache).filter(RirLookupCache.rir == rir).count()


def _inverse(attrs=("org",), types=("inetnum",)):
    return rf.ripe_inverse(ORG, attrs, types)


# ── builders ─────────────────────────────────────────────────────────────────

def test_fulltext_builder_exact():
    path, params = rf.ripe_fulltext_by_domain("Example.COM", 1)
    assert path == "fulltextsearch/select"
    assert params == (
        ("q", '(e-mail:"example.com") OR (abuse-mailbox:"example.com")'),
        ("rows", "100"),
        ("start", "100"),
    )


@pytest.mark.parametrize("page, start", [(0, "0"), (1, "100"), (2, "200")])
def test_fulltext_builder_pages(page, start):
    assert dict(rf.ripe_fulltext_by_domain("fabrikam.com", page)[1])["start"] == start


@pytest.mark.parametrize("domain, page", [("a/b.com", 0), ("example..com", 0), ("", 0), ("example.com", 3), ("example.com", -1)])
def test_fulltext_builder_rejects(domain, page):
    with pytest.raises(ValueError):
        rf.ripe_fulltext_by_domain(domain, page)


def test_inverse_builder_exact():
    path, params = rf.ripe_inverse(ORG, ("org", "admin-c"), ("inetnum", "aut-num"))
    assert path == "search.json"
    assert params == (
        ("query-string", ORG),
        ("inverse-attribute", "org"),
        ("inverse-attribute", "admin-c"),
        ("type-filter", "inetnum"),
        ("type-filter", "aut-num"),
        ("flags", "no-referenced"),
        ("flags", "no-irt"),
    )


@pytest.mark.parametrize("handle, attrs, types", [
    ("EX1 -i org", ("org",), ("inetnum",)),
    ("a/b", ("org",), ("inetnum",)),
    (ORG, ("mnt-by",), ("inetnum",)),
    (ORG, ("org",), ("person",)),
    (ORG, ("org",), ()),
    (ORG, (), ("inetnum",)),
])
def test_inverse_builder_rejects(handle, attrs, types):
    with pytest.raises(ValueError):
        rf.ripe_inverse(handle, attrs, types)


def test_one_more_builder_exact():
    path, params = rf.ripe_one_more(RANGE, "inetnum")
    assert path == "search.json"
    assert params == (
        ("query-string", RANGE),
        ("type-filter", "inetnum"),
        ("flags", "one-more"),
        ("flags", "no-referenced"),
        ("flags", "no-irt"),
    )
    assert dict(rf.ripe_one_more(V6, "inet6num")[1])["query-string"] == V6


@pytest.mark.parametrize("key, typ", [
    (V6, "inetnum"), (RANGE, "inet6num"), (RANGE, "aut-num"), (ORG, "inetnum"), ("192.0.2.0/24", "inetnum"),
])
def test_one_more_builder_rejects(key, typ):
    with pytest.raises(ValueError):
        rf.ripe_one_more(key, typ)


def test_every_builder_output_passes_get_validation():
    for path, params in (
        rf.ripe_fulltext_by_domain("fabrikam.com", 0), _inverse(), rf.ripe_one_more(RANGE, "inetnum"),
        rf.ripe_one_more(V6, "inet6num"),
    ):
        rf._validate_ripe(path, params)
        assert rf._RIPE_PATH_RE.fullmatch(path)


# ── get: request shape and cache ─────────────────────────────────────────────

def test_get_request_shape_and_cache_key(db, transport):
    query = rf.ripe_inverse(ORG, ("org", "admin-c"), ("inetnum", "aut-num"))
    path, params = query
    b = rf.Budget()
    assert rf.ripe_get(db, query, b) == {"ok": True}
    (url, kw), = transport.calls
    assert url == rf.BASE_URLS["ripe"] + "search.json"
    assert kw["params"] == {
        "flags": ["no-irt", "no-referenced"],
        "inverse-attribute": ["admin-c", "org"],
        "query-string": [ORG],
        "type-filter": ["aut-num", "inetnum"],
    }
    assert kw["follow_redirects"] is False
    assert kw["headers"] == {"Accept": "application/json"}
    assert b.used == 1
    expected = (
        "search.json?flags=no-irt&flags=no-referenced&inverse-attribute=admin-c&inverse-attribute=org"
        "&query-string=ORG-EXA1-TEST&type-filter=aut-num&type-filter=inetnum"
    )
    db.expire_all()
    row = db.get(RirLookupCache, ("ripe", expected))
    assert row is not None and row.status_code == 200 and row.body == {"ok": True}
    assert _rows(db) == 1


def test_second_identical_call_is_a_hit(db, transport):
    query = rf.ripe_fulltext_by_domain("fabrikam.com", 0)
    b = rf.Budget()
    transport.responses.append(FakeResponse(200, {"n": 1}))
    assert rf.ripe_get(db, query, b) == {"n": 1}
    assert len(transport.calls) == 1 and b.cache_hits == 0
    assert rf.ripe_get(db, query, b) == {"n": 1}
    assert len(transport.calls) == 1 and b.cache_hits == 1 and b.used == 1
    assert _rows(db) == 1


def test_same_pairs_in_another_order_hit_the_same_row(db, transport):
    path, params = _inverse(("org", "admin-c"), ("inetnum", "aut-num"))
    b = rf.Budget()
    rf.get(db, "ripe", path, b, params=params)
    assert len(transport.calls) == 1
    rf.get(db, "ripe", path, b, params=tuple(reversed(params)))
    assert len(transport.calls) == 1 and b.cache_hits == 1
    assert _rows(db) == 1


def test_different_params_are_a_different_row(db, transport):
    b = rf.Budget()
    rf.ripe_get(db, _inverse(("org",)), b)
    rf.ripe_get(db, _inverse(("admin-c",)), b)
    assert len(transport.calls) == 2 and b.cache_hits == 0
    assert _rows(db) == 2


def test_arin_and_ripe_rows_do_not_collide(db, transport):
    b = rf.Budget()
    rf.get(db, "arin", "poc/H1", b)
    rf.ripe_get(db, _inverse(), b)
    assert len(transport.calls) == 2
    assert transport.calls[0][1]["params"] is None  # ARIN sends no params
    db.query(RirLookupCache).filter(RirLookupCache.rir == "arin", RirLookupCache.path == "poc/H1").delete()
    db.flush()


def test_404_is_cached_as_none(db, transport):
    query = _inverse()
    b = rf.Budget()
    transport.responses.append(FakeResponse(404))
    assert rf.ripe_get(db, query, b) is None
    assert len(transport.calls) == 1
    assert rf.ripe_get(db, query, b) is None
    assert len(transport.calls) == 1 and b.cache_hits == 1
    assert _rows(db) == 1


def test_500_raises_and_caches_nothing(db, transport):
    transport.responses.append(FakeResponse(500))
    with pytest.raises(rf.RirFetchError):
        rf.ripe_get(db, _inverse(), rf.Budget())
    assert len(transport.calls) == 1  # the path was reached
    assert _rows(db) == 0


def test_stale_ripe_row_is_refetched(db, transport):
    query = _inverse()
    now = datetime.now(timezone.utc)
    rf.ripe_get(db, query, rf.Budget(), now=now - rf.CACHE_TTL - rf.timedelta(seconds=1))
    transport.responses.append(FakeResponse(200, {"new": 1}))
    assert rf.ripe_get(db, query, rf.Budget(), now=now) == {"new": 1}
    assert len(transport.calls) == 2
    assert _rows(db) == 1


# ── get: rejections ──────────────────────────────────────────────────────────

def _q(*pairs):
    return tuple(pairs)


def _search(qs=ORG, types=("inetnum",), inverse=("org",), flags=("no-referenced", "no-irt")):
    return (
        (("query-string", qs),)
        + tuple(("type-filter", t) for t in types)
        + tuple(("inverse-attribute", a) for a in inverse)
        + tuple(("flags", f) for f in flags)
    )


def _fulltext(q='(e-mail:"example.com") OR (abuse-mailbox:"example.com")', rows="100", start="0"):
    return (("q", q), ("rows", rows), ("start", start))


# (id, rir, path, params)
VALID = [
    ("inverse", "ripe", "search.json", _search()),
    ("one-more-v4", "ripe", "search.json", _search(RANGE, ("inetnum",), (), ("one-more", "no-referenced", "no-irt"))),
    ("one-more-v6", "ripe", "search.json", _search(V6, ("inet6num",), (), ("one-more", "no-referenced", "no-irt"))),
    ("fulltext", "ripe", "fulltextsearch/select", _fulltext()),
    ("fulltext-last-page", "ripe", "fulltextsearch/select", _fulltext(start="200")),
    ("inverse-all-types", "ripe", "search.json",
     _search(types=("inetnum", "inet6num", "aut-num", "organisation"), inverse=("org", "admin-c", "tech-c", "abuse-c"))),
]

ONE_MORE = ("one-more", "no-referenced", "no-irt")

REJECTED = [
    ("unknown-key", "ripe", "search.json", _search() + (("source", "RIPE"),)),
    ("flag-all-more", "ripe", "search.json", _search(flags=("no-referenced", "no-irt", "all-more"))),
    ("flag-brief", "ripe", "search.json", _search(flags=("no-referenced", "no-irt", "brief"))),
    ("missing-no-irt", "ripe", "search.json", _search(flags=("no-referenced",))),
    ("missing-no-referenced", "ripe", "search.json", _search(flags=("no-irt",))),
    ("one-more-with-handle", "ripe", "search.json", _search(ORG, ("inetnum",), (), ONE_MORE)),
    ("one-more-plus-inverse", "ripe", "search.json", _search(RANGE, ("inetnum",), ("org",), ONE_MORE)),
    ("one-more-two-types", "ripe", "search.json", _search(RANGE, ("inetnum", "inet6num"), (), ONE_MORE)),
    ("one-more-aut-num", "ripe", "search.json", _search(RANGE, ("aut-num",), (), ONE_MORE)),
    ("one-more-v6-with-inetnum", "ripe", "search.json", _search(V6, ("inetnum",), (), ONE_MORE)),
    ("inverse-with-ip", "ripe", "search.json", _search(RANGE)),
    ("type-person", "ripe", "search.json", _search(types=("person",))),
    ("type-role", "ripe", "search.json", _search(types=("role",))),
    ("type-mntner", "ripe", "search.json", _search(types=("mntner",))),
    ("no-type-filter", "ripe", "search.json", _search(types=())),
    ("inverse-mnt-by", "ripe", "search.json", _search(inverse=("mnt-by",))),
    ("space-injection", "ripe", "search.json", _search("EX1-TEST -i org")),
    ("two-query-strings", "ripe", "search.json", _search() + (("query-string", "EX2-TEST"),)),
    ("no-inverse-no-one-more", "ripe", "search.json", _search(inverse=())),
    ("range-extra-spaces", "ripe", "search.json", _search("192.0.2.0  -  192.0.2.255", ("inetnum",), (), ONE_MORE)),
    ("range-leading-zero", "ripe", "search.json", _search("192.0.2.00 - 192.0.2.255", ("inetnum",), (), ONE_MORE)),
    ("range-reversed", "ripe", "search.json", _search("192.0.2.255 - 192.0.2.0", ("inetnum",), (), ONE_MORE)),
    ("cidr-for-inetnum", "ripe", "search.json", _search("192.0.2.0/24", ("inetnum",), (), ONE_MORE)),
    ("single-address-inetnum", "ripe", "search.json", _search("192.0.2.1", ("inetnum",), (), ONE_MORE)),
    ("v6-non-strict", "ripe", "search.json", _search("2001:db8::1/32", ("inet6num",), (), ONE_MORE)),
    ("v6-non-canonical", "ripe", "search.json", _search("2001:0db8::/32", ("inet6num",), (), ONE_MORE)),
    ("fulltext-two-domains", "ripe", "fulltextsearch/select",
     _fulltext('(e-mail:"example.com") OR (abuse-mailbox:"fabrikam.com")')),
    ("fulltext-extra-clause", "ripe", "fulltextsearch/select",
     _fulltext('(e-mail:"example.com") OR (abuse-mailbox:"example.com") OR *:*')),
    ("fulltext-noncanonical-domain", "ripe", "fulltextsearch/select",
     _fulltext('(e-mail:"www.example.com") OR (abuse-mailbox:"www.example.com")')),
    ("fulltext-rows-1000", "ripe", "fulltextsearch/select", _fulltext(rows="1000")),
    ("fulltext-start-300", "ripe", "fulltextsearch/select", _fulltext(start="300")),
    ("fulltext-start-50", "ripe", "fulltextsearch/select", _fulltext(start="50")),
    ("fulltext-extra-key", "ripe", "fulltextsearch/select", _fulltext() + (("wt", "json"),)),
    ("fulltext-missing-key", "ripe", "fulltextsearch/select", _fulltext()[:2]),
    ("duplicate-pair", "ripe", "search.json", _search() + (("inverse-attribute", "org"),)),
    ("ripe-params-none", "ripe", "search.json", None),
    ("ripe-params-empty", "ripe", "search.json", ()),
    ("arin-with-params", "arin", "poc/H1", (("a", "b"),)),
    ("ripe-path-wrong-shape", "ripe", "ripe/inetnum/x", _search()),
    ("ripe-arin-path", "ripe", "poc/H1", _search()),
    ("ripe-path-with-query", "ripe", "search.json?x=1", _search()),
    ("ripe-path-trailing-slash", "ripe", "search.json/", _search()),
    ("fulltext-params-on-search-path", "ripe", "search.json", _fulltext()),
    ("search-params-on-fulltext-path", "ripe", "fulltextsearch/select", _search()),
]


@pytest.mark.parametrize("case", [pytest.param(c[1:], id=c[0]) for c in VALID])
def test_valid_shapes_are_accepted(db, transport, case):
    rir, path, params = case
    b = rf.Budget()
    assert rf.get(db, rir, path, b, params=params) == {"ok": True}
    assert len(transport.calls) == 1 and b.used == 1
    assert _rows(db) == 1


@pytest.mark.parametrize("case", [pytest.param(c[1:], id=c[0]) for c in REJECTED])
def test_rejected_shapes_make_no_call_and_cache_nothing(db, transport, case):
    rir, path, params = case
    b = rf.Budget()
    before = (_rows(db, "ripe"), _rows(db, "arin"))
    with pytest.raises(ValueError):
        rf.get(db, rir, path, b, params=params)
    assert transport.calls == []
    assert b.used == 0 and b.cache_hits == 0
    assert (_rows(db, "ripe"), _rows(db, "arin")) == before


def test_arin_accepts_none_and_empty_params(db, transport):
    b = rf.Budget()
    rf.get(db, "arin", "poc/H1", b, params=None)
    rf.get(db, "arin", "poc/H2", b, params=())
    assert len(transport.calls) == 2
    assert all(kw["params"] is None for _, kw in transport.calls)
    db.query(RirLookupCache).filter(RirLookupCache.rir == "arin", RirLookupCache.path.in_(["poc/H1", "poc/H2"])).delete(
        synchronize_session=False
    )
    db.flush()


def test_validation_precedes_the_cache_read(db, transport):
    path, params = _inverse()
    rf.get(db, "ripe", path, rf.Budget(), params=params)
    bad = params + (("flags", "brief"),)
    b = rf.Budget()
    with pytest.raises(ValueError):
        rf.get(db, "ripe", path, b, params=bad)
    assert b.cache_hits == 0 and len(transport.calls) == 1
