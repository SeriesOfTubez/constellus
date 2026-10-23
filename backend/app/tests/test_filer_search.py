"""SEC full-text search by domain (planning#277 S1a): the URL builder, the host
allowlist, the response parser and the filer lookup.

The fixture bodies are in the SHAPE a live EFTS response has (observed
2026-10-23 with one request for a reserved example domain: `hits.hits[]` with
`_index`, `_id`, `_score` and a `_source` carrying `ciks[]`, `display_names[]`,
`file_date`, `form`, `adsh`, ...), with every value synthetic. Transport spies
sit on `sec_edgar._transport` (the httpx layer), never on `search_by_domain`,
so a wrapper that skipped the request would fail them.

Run with:  scripts/test.sh app/tests/test_filer_search.py
"""

import json
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from sqlalchemy import func, select

from app.core.config import settings
from app.models.evidence import EvidenceFetch
from app.models.scope_candidate import ScopeCandidate, ScopeSignal
from app.models.user import UserRole
from app.services import sec_edgar
from app.services.org_discovery import candidates as cd
from app.services.org_discovery import filer_search
from app.tests._org_world import World, client
from app.tests.test_registrant_link import submissions_json

UA = "Constellus test suite test@example.invalid"


@pytest.fixture
def w():
    world = World()
    try:
        yield world
    finally:
        world.close()


# ── synthetic EFTS bodies in the real shape ─────────────────────────────────


def _source(cik: str, *, name: str, form="10-K", file_date="2024-02-15", adsh="9900000001-24-000001", **over) -> dict:
    return {
        "ciks": [cik], "period_ending": "2023-12-31", "file_num": ["001-90001"],
        "display_names": [f"{name}  (EXMP)  (CIK {cik})"], "xsl": None, "sequence": 1, "root_forms": ["10-K"],
        "file_date": file_date, "biz_states": [], "sics": ["7372"], "form": form, "adsh": adsh,
        "film_num": ["24000001"], "biz_locations": ["Example City, ZZ"], "file_type": "10-K",
        "file_description": None, "inc_states": ["DE"], "items": [], **over,
    }


def _body(sources: list[dict]) -> bytes:
    hits = [
        {"_index": "edgar_file", "_id": f"{s.get('adsh', 'x')}:doc{i}.htm", "_score": 7.5, "_source": s}
        for i, s in enumerate(sources)
    ]
    return json.dumps({
        "took": 12, "timed_out": False, "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
        "hits": {"total": {"value": len(hits), "relation": "eq"}, "max_score": 7.5, "hits": hits},
        "query": {"from": 0, "size": 100},
    }).encode()


class _Sec:
    """A recording MockTransport: EFTS body, per-CIK submissions, or a status."""

    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.efts = _body([])
        self.efts_status = 200
        self.submissions: dict[str, dict] = {}
        self.missing: set[str] = set()

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = urlsplit(str(request.url))
        if url.netloc == "efts.sec.gov":
            return httpx.Response(self.efts_status, content=self.efts, headers={"content-type": "application/json"})
        if url.netloc == "data.sec.gov" and url.path.startswith("/submissions/CIK"):
            cik = url.path.rsplit("/", 1)[-1][3:13]
            if cik in self.missing:
                return httpx.Response(404)
            if cik in self.submissions:
                return httpx.Response(200, json=self.submissions[cik])
        raise AssertionError(f"unexpected request {request.url}")

    def hosts_and_paths(self) -> list[tuple[str, str]]:
        return [(r.url.host, r.url.path) for r in self.requests]


@pytest.fixture
def sec(monkeypatch):
    s = _Sec()
    monkeypatch.setattr(sec_edgar, "_transport", httpx.MockTransport(s.handler))
    monkeypatch.setattr(sec_edgar, "_sleep", lambda _s: None)
    monkeypatch.setattr(sec_edgar, "_last_request_at", None)
    monkeypatch.setattr(settings, "sec_user_agent", UA)
    return s


# ── the URL builder never splices ───────────────────────────────────────────


def test_the_built_url_parses_back_to_exactly_q_and_forms():
    url = sec_edgar.full_text_search_url("sub.example-co.com")
    parts = urlsplit(url)
    assert (parts.scheme, parts.netloc, parts.path, parts.fragment) == ("https", "efts.sec.gov", "/LATEST/search-index", "")
    assert parse_qs(parts.query, strict_parsing=True) == {"q": ['"sub.example-co.com"'], "forms": ["10-K"]}
    assert '"' not in parts.query  # percent-encoded, not spliced
    sec_edgar._check_allowlisted(url)  # and the guard admits what the builder builds


@pytest.mark.parametrize("bad", [
    "", "Example.COM", "a b.com", 'x.com"&forms=8-K', "x.com&q=other", "http://x.com", "x.com/path", "x.com#frag",
    "192.0.2.1", "nodot", "-x.com", "x..com", "x.com:443", 123, None,
])
def test_the_builder_refuses_anything_that_is_not_a_canonical_domain(bad):
    with pytest.raises(ValueError):
        sec_edgar.full_text_search_url(bad)


# ── the host allowlist ──────────────────────────────────────────────────────

_GOOD_Q = "q=%22example.com%22&forms=10-K"


@pytest.mark.parametrize("url", [
    f"https://efts.sec.gov/LATEST/search-index?{_GOOD_Q}",
])
def test_the_allowlist_admits_only_the_exact_full_text_shape(url):
    sec_edgar._check_allowlisted(url)


@pytest.mark.parametrize("url", [
    f"https://efts.sec.gov/LATEST/search?{_GOOD_Q}",                                   # another path
    f"https://efts.sec.gov/LATEST/search-index/extra?{_GOOD_Q}",
    f"https://efts.sec.gov/LATEST/search-index?{_GOOD_Q}&from=100",                    # an extra parameter
    f"https://efts.sec.gov/LATEST/search-index?{_GOOD_Q}&dateRange=all",
    "https://efts.sec.gov/LATEST/search-index?q=%22example.com%22",                    # forms missing
    "https://efts.sec.gov/LATEST/search-index?forms=10-K",                             # q missing
    "https://efts.sec.gov/LATEST/search-index?q=%22example.com%22&forms=8-K",          # another form
    "https://efts.sec.gov/LATEST/search-index?q=%22example.com%22&forms=10-K&forms=8-K",
    "https://efts.sec.gov/LATEST/search-index?q=%22example.com%22&q=%22other.com%22&forms=10-K",
    "https://efts.sec.gov/LATEST/search-index?q=example.com&forms=10-K",               # not quoted
    "https://efts.sec.gov/LATEST/search-index?q=%22not+a+domain%22&forms=10-K",
    "https://efts.sec.gov/LATEST/search-index?q=%22%22&forms=10-K",
    f"https://efts.sec.gov/LATEST/search-index?{_GOOD_Q}#frag",
    f"http://efts.sec.gov/LATEST/search-index?{_GOOD_Q}",                              # not https
    f"https://efts.sec.gov:8443/LATEST/search-index?{_GOOD_Q}",
    f"https://efts.sec.gov.evil.example/LATEST/search-index?{_GOOD_Q}",
    "https://efts.sec.gov/",
    "https://efts.sec.gov/LATEST/search-index",
])
def test_the_allowlist_refuses_every_other_efts_url(url):
    with pytest.raises(ValueError):
        sec_edgar._check_allowlisted(url)


def test_the_other_hosts_keep_their_own_rules():
    with pytest.raises(ValueError):
        sec_edgar._check_allowlisted("https://www.sec.gov/LATEST/search-index?q=%22example.com%22&forms=10-K")
    sec_edgar._check_allowlisted("https://data.sec.gov/submissions/CIK0000000001.json")


@pytest.mark.parametrize("body,ok", [
    (b'{"hits": {"hits": []}}', True),
    (b'{"hits": {"hits": [{"_source": {}}]}, "took": 1}', True),
    (b'{"hits": {"hits": {}}}', False),
    (b'{"hits": []}', False),
    (b"[]", False),
    (b"503 Service Unavailable", False),
    (b"\xff\xfe", False),
])
def test_the_json_validator_checks_shape_only(body, ok):
    assert sec_edgar._validate_full_text_json(body) is ok


def test_search_full_text_makes_one_allowlisted_request_with_the_sec_headers(sec):
    sec.efts = _body([_source("0000000101", name="Example Alpha")])
    content, _ct, _at, url = sec_edgar.search_full_text("example.com")
    assert json.loads(content)["hits"]["total"]["value"] == 1
    assert [(r.url.host, r.url.path) for r in sec.requests] == [("efts.sec.gov", "/LATEST/search-index")]
    assert parse_qs(sec.requests[0].url.query.decode()) == {"q": ['"example.com"'], "forms": ["10-K"]}
    assert sec.requests[0].headers["user-agent"] == UA
    assert url.startswith("https://efts.sec.gov/LATEST/search-index?")


def test_an_sec_failure_is_retried_then_raised(sec):
    sec.efts_status = 503
    with pytest.raises(sec_edgar.SecFetchError):
        sec_edgar.search_full_text("example.com")
    assert len(sec.requests) == sec_edgar._MAX_ATTEMPTS  # the retry loop was REACHED


# ── the parser and the lookup ───────────────────────────────────────────────


def _filer_world(sec, w):
    """Three filers: Alpha (2 matching 10-Ks), Beta (1), Gamma (co-registrant with Beta)."""
    sec.efts = _body([
        _source("0000000101", name="Example Alpha Holdings", file_date="2023-02-10", adsh="9900000101-23-000001"),
        _source("0000000101", name="Example Alpha Holdings", file_date="2024-02-15", adsh="9900000101-24-000001"),
        _source("0000000102", name="Example Beta Corp", file_date="2022-03-01", adsh="9900000102-22-000001",
                ciks=["0000000102", "0000000103"],
                display_names=["Example Beta Corp  (CIK 0000000102)", "Example Gamma Ltd  (CIK 0000000103)"]),
    ])
    for cik in ("0000000101", "0000000102", "0000000103"):
        sec.submissions[cik] = submissions_json(cik)


def test_filers_are_grouped_by_cik_newest_match_first(sec, w):
    _filer_world(sec, w)
    hits = filer_search.search_by_domain(w.db, "WWW.Example.com")  # normalised first
    assert [h.cik for h in hits] == ["0000000101", "0000000102", "0000000103"]
    alpha, beta, gamma = hits
    assert [(f.form, f.file_date, f.accession) for f in alpha.matched_filings] == [
        ("10-K", "2024-02-15", "9900000101-24-000001"), ("10-K", "2023-02-10", "9900000101-23-000001"),
    ]
    assert alpha.display_name == "Example Alpha Holdings  (EXMP)"
    assert (beta.display_name, gamma.display_name) == ("Example Beta Corp", "Example Gamma Ltd")
    assert alpha.edgar_url == "https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK=0000000101"
    assert filer_search.describe_match(alpha, "example.com")[0] == 'a 10-K filed 2024-02-15 contains "example.com"'
    # the request was for the NORMALISED domain
    assert parse_qs(sec.requests[0].url.query.decode())["q"] == ['"example.com"']


def test_stats_come_from_the_submissions_json(sec, w):
    _filer_world(sec, w)
    alpha = filer_search.search_by_domain(w.db, "example.com")[0]
    s = alpha.stats
    # 3 recent filings + the paged file's filingCount of 9
    assert (s.total_filings, s.first_filing, s.last_filing, s.latest_10k, s.partial) == (
        12, "1999-01-04", "2012-03-01", "2012-03-01", True,
    )


def test_at_most_ten_filers_and_three_filings_each(sec, w):
    sources = [
        _source(f"{i:010d}", name=f"Example Filer {i}", file_date=f"2020-01-{i:02d}", adsh=f"{i:010d}-20-000001")
        for i in range(1, 13)
    ] + [
        _source("0000000001", name="Example Filer 1", file_date=f"2021-0{k}-01", adsh=f"0000000001-21-00000{k}")
        for k in range(1, 6)
    ]
    sec.efts = _body(sources)
    for i in range(1, 13):
        sec.submissions[f"{i:010d}"] = submissions_json(f"{i:010d}")
    hits = filer_search.search_by_domain(w.db, "example.com")
    assert len(hits) == filer_search.MAX_FILERS == 10
    assert hits[0].cik == "0000000001"                       # its 2021 matches are the newest
    assert [f.file_date for f in hits[0].matched_filings] == ["2021-05-01", "2021-04-01", "2021-03-01"]
    assert [h.cik for h in hits[1:4]] == ["0000000012", "0000000011", "0000000010"]
    # the 10-CIK cap means 10 submissions fetches, no more
    assert sum(1 for r in sec.requests if r.url.host == "data.sec.gov") == 10


def test_malformed_hits_are_skipped(sec, w):
    good = _source("0000000101", name="Example Alpha", adsh="9900000101-24-000001")
    sec.efts = _body([
        good,
        _source("not-a-cik", name="Bad Cik", adsh="9900000102-24-000001", ciks=["not-a-cik"]),
        _source("0000000103", name="Bad Accession", adsh="../../etc/passwd"),
        _source("0000000104", name="Bad Date", file_date="2024-13-45", adsh="9900000104-24-000001"),
        _source("0000000105", name="Bad Date 2", file_date="yesterday", adsh="9900000105-24-000001"),
        _source("12345678901", name="Too Long", adsh="9900000106-24-000001", ciks=["12345678901"]),
        {"not": "a source"},
    ])
    sec.submissions["0000000101"] = submissions_json("0000000101")
    hits = filer_search.search_by_domain(w.db, "example.com")
    assert [h.cik for h in hits] == ["0000000101"]


def test_an_unpadded_cik_is_padded(sec, w):
    sec.efts = _body([_source("101", name="Example Alpha", ciks=["101"])])
    sec.submissions["0000000101"] = submissions_json("0000000101")
    assert [h.cik for h in filer_search.search_by_domain(w.db, "example.com")] == ["0000000101"]


def test_one_unreachable_filer_does_not_fail_the_search(sec, w, caplog, monkeypatch):
    _filer_world(sec, w)
    sec.missing.update({"0000000102", "0000000103"})            # SEC answers 404 for these two
    with caplog.at_level("WARNING"):
        hits = filer_search.search_by_domain(w.db, "example.com")
    by = {h.cik: h for h in hits}
    assert by["0000000101"].stats is not None                       # the others still got theirs
    assert by["0000000102"].stats is None and by["0000000103"].stats is None
    assert [h.cik for h in hits] == ["0000000101", "0000000102", "0000000103"]
    assert any("no filing stats" in r.message for r in caplog.records)
    # ...and a 5xx on one filer (retries exhausted) is soft too
    sec.missing.clear()
    sec.submissions["0000000102"] = submissions_json("0000000102")
    sec.submissions["0000000103"] = submissions_json("0000000103")
    orig = sec.handler

    def flaky(request):
        if request.url.path.endswith("CIK0000000102.json"):
            sec.requests.append(request)
            return httpx.Response(503)
        return orig(request)

    monkeypatch.setattr(sec_edgar, "_transport", httpx.MockTransport(flaky))
    assert {h.cik: h.stats is None for h in filer_search.search_by_domain(w.db, "example.com")} == {
        "0000000101": False, "0000000102": True, "0000000103": False,
    }


def test_the_lookup_writes_nothing_and_requests_only_the_two_known_surfaces(sec, w):
    _filer_world(sec, w)
    tables = (EvidenceFetch, ScopeCandidate, ScopeSignal)
    before = {t.__tablename__: w.db.execute(select(func.count()).select_from(t)).scalar_one() for t in tables}
    hits = filer_search.search_by_domain(w.db, "example.com")
    assert len(hits) == 3  # the path was reached
    w.db.rollback()
    after = {t.__tablename__: w.db.execute(select(func.count()).select_from(t)).scalar_one() for t in tables}
    assert after == before
    # nothing taken from the response was ever fetched
    assert {hp for hp in sec.hosts_and_paths()} == {
        ("efts.sec.gov", "/LATEST/search-index"),
        ("data.sec.gov", "/submissions/CIK0000000101.json"),
        ("data.sec.gov", "/submissions/CIK0000000102.json"),
        ("data.sec.gov", "/submissions/CIK0000000103.json"),
    }


def test_a_response_url_is_never_followed(sec, w):
    """A hostile body: every string field is a URL. Nothing may be requested for them."""
    sec.efts = _body([_source(
        "0000000101", name="https://evil.example/steal", file_description="https://evil.example/a",
        xsl="https://evil.example/b", biz_locations=["https://evil.example/c"],
    )])
    sec.submissions["0000000101"] = submissions_json("0000000101")
    hits = filer_search.search_by_domain(w.db, "example.com")
    assert [h.cik for h in hits] == ["0000000101"]
    assert all(host in ("efts.sec.gov", "data.sec.gov") for host, _ in sec.hosts_and_paths())
    assert hits[0].edgar_url.startswith("https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK=0000000101")


def test_a_non_domain_is_refused_before_any_request(sec, w):
    for bad in ("not a domain", "192.0.2.1", ""):
        with pytest.raises(cd.CandidateInvalid):
            filer_search.search_by_domain(w.db, bad)
    assert sec.requests == []


def test_an_existing_entity_with_the_cik_is_reported(sec, w):
    _filer_world(sec, w)
    existing = w.entity(cik="0000000102")
    hits = {h.cik: h for h in filer_search.search_by_domain(w.db, "example.com")}
    assert hits["0000000102"].entity_id == existing.id and hits["0000000101"].entity_id is None


# ── the route ───────────────────────────────────────────────────────────────


def test_the_route_needs_organizations_create(sec, w):
    _filer_world(sec, w)
    url = "/api/organizations/filer-search?domain=example.com"
    assert client.get(url, headers=w.headers(role=UserRole.INTEGRATION_ADMIN.value)).status_code == 403
    assert client.get(url, headers=w.headers(role=UserRole.VIEWER.value)).status_code == 403
    assert sec.requests == []                                    # refused before any request
    r = client.get(url, headers=w.headers())
    assert r.status_code == 200, r.text
    first = r.json()[0]
    assert first["cik"] == "0000000101" and first["display_name"].startswith("Example Alpha")
    assert first["why"][0] == 'a 10-K filed 2024-02-15 contains "example.com"'
    assert first["stats"]["total_filings"] == 12 and first["edgar_url"].endswith("CIK=0000000101")
    assert len(first["matched_filings"]) == 2


def test_the_route_maps_errors(sec, w, monkeypatch):
    h = w.headers()
    assert client.get("/api/organizations/filer-search?domain=not%20a%20domain", headers=h).status_code == 400
    assert client.get("/api/organizations/filer-search", headers=h).status_code == 422
    sec.efts_status = 503
    r = client.get("/api/organizations/filer-search?domain=example.com", headers=h)
    assert r.status_code == 502 and "SecFetchError" in r.json()["detail"]
    assert "example.com" not in r.json()["detail"]               # the typed domain never echoes back
    monkeypatch.setattr(settings, "sec_user_agent", None)
    assert client.get("/api/organizations/filer-search?domain=example.com", headers=h).status_code == 409
