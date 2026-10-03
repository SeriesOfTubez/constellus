"""Link a CIK-less acquired company to its SEC registrant (planning#236 S1).

`app.services.sec_edgar`'s company search (URL, allowlist, parser),
`app.services.registrant_link` (gate, link, follow-up read, unlink) and the
API in `app.api.entities`. SEC is never contacted: every request goes
through an `httpx.MockTransport`, and every company and CIK is invented
(`make_cik`'s 99-prefixed CIKs cannot belong to a real filer).

Run with:  scripts/test.ps1 app/tests/test_registrant_link.py
"""

import json
import uuid
from datetime import date, datetime, timezone
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError

from app.core.auth import create_access_token
from app.core.config import settings
from app.core.database import SessionLocal
from app.main import app
from app.models.audit import AuditLog
from app.models.candidate_domain import CandidateDomain
from app.models.entity_filing_event import EntityFilingEvent
from app.models.entity_filing_section import EntityFilingSection
from app.models.entity_ingest_run import EntityIngestRun
from app.models.entity_relation import EntityRelation
from app.models.entity_subsidiary_listing import EntitySubsidiaryListing
from app.models.observer import Observer
from app.models.org_entity import OrgEntity
from app.models.user import User, UserRole
from app.services import acquisition_reader, edgar_ingest, entity_graph, llm_connector, sec_edgar
from app.services import registrant_link as rl
from app.tests._edgar import make_cik
from app.tests._entity_graph import cleanup_evidence, cleanup_observer, make_evidence, make_observer

client = TestClient(app)

UA = "Constellus test suite test@example.invalid"


def _hex() -> str:
    return uuid.uuid4().hex[:10]


# ── synthetic SEC responses (the real wire shapes) ──────────────────────────


def submissions_json(cik10: str, *, name: str = "EXAMPLE TARGET CORP", files: bool = True) -> dict:
    """The submissions JSON shape SEC sends: `cik` UNPADDED as a string,
    former-name dates as ISO datetimes, filing dates as plain dates, and
    paged files carrying `filingFrom`/`filingTo`."""
    return {
        "cik": str(int(cik10)),
        "name": name,
        "sic": "7372",
        "sicDescription": "SERVICES-PREPACKAGED SOFTWARE",
        "stateOfIncorporation": "DE",
        "formerNames": [
            {"name": "EXAMPLE TARGET INC", "from": "2001-02-03T00:00:00.000Z", "to": "2008-04-05T00:00:00.000Z"},
        ],
        "filings": {
            "recent": {
                "accessionNumber": ["9900000001-12-000001", "9900000001-11-000001", "9900000001-10-000001"],
                "filingDate": ["2012-03-01", "2011-03-01", "2010-05-01"],
                "form": ["10-K", "10-K", "8-K"],
                "items": ["", "", "2.01"],
            },
            "files": (
                [{"name": f"CIK{cik10}-submissions-001.json", "filingCount": 9,
                  "filingFrom": "1999-01-04", "filingTo": "2009-12-30"}]
                if files else []
            ),
        },
    }


def search_list_html(ciks: list[str]) -> str:
    rows = "".join(
        f'<tr><td valign="top" scope="row"><a href="/cgi-bin/browse-edgar?action=getcompany&amp;CIK={c}'
        f'&amp;owner=include&amp;count=40&amp;hidefilings=0">{c}</a></td>'
        f'<td scope="row">EXAMPLE CO {i}<br /><acronym title="Standard Industrial Code">SIC</acronym>: '
        f'<a href="/cgi-bin/browse-edgar?action=getcompany&amp;SIC=7372&amp;owner=include&amp;count=40">7372</a>'
        f' - SERVICES</td><td valign="top" scope="row"><a href="/cgi-bin/browse-edgar?action=getcompany'
        f'&amp;State=DE&amp;owner=include&amp;count=40">DE</a></td></tr>'
        for i, c in enumerate(ciks)
    )
    return (
        '<html><head><title>EDGAR Search Results</title></head><body>'
        '<table class="tableFile2" summary="Results"><tr><th>CIK</th><th>Company</th><th>State</th></tr>'
        f"{rows}</table></body></html>"
    )


def search_company_html(cik10: str) -> str:
    return (
        '<html><body><div class="companyInfo"><span class="companyName">EXAMPLE TARGET CORP '
        '<acronym title="Central Index Key">CIK</acronym>#: <a href="/cgi-bin/browse-edgar?action=getcompany'
        f'&amp;CIK={cik10}&amp;owner=include&amp;count=40">{cik10} (see all company filings)</a></span></div>'
        "</body></html>"
    )


SEARCH_NONE_HTML = "<html><body><h1>EDGAR Search Results</h1><p>No matching companies.</p></body></html>"


class _Sec:
    """A MockTransport keyed by path: the submissions JSON per CIK, and one
    canned search page. Records every request."""

    def __init__(self):
        self.submissions: dict[str, dict] = {}
        self.search_pages: list[str] = []
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path == "/cgi-bin/browse-edgar":
            body = self.search_pages.pop(0) if len(self.search_pages) > 1 else self.search_pages[0]
            return httpx.Response(200, text=body, headers={"content-type": "text/html"})
        if path.startswith("/submissions/CIK"):
            cik10 = path[len("/submissions/CIK"):-len(".json")]
            if cik10 in self.submissions:
                return httpx.Response(200, content=json.dumps(self.submissions[cik10]).encode(),
                                      headers={"content-type": "application/json"})
            return httpx.Response(404)
        return httpx.Response(500)


@pytest.fixture
def sec(monkeypatch):
    s = _Sec()
    monkeypatch.setattr(sec_edgar, "_transport", httpx.MockTransport(s.handler))
    monkeypatch.setattr(sec_edgar, "_sleep", lambda _s: None)
    monkeypatch.setattr(sec_edgar, "_last_request_at", None)
    monkeypatch.setattr(settings, "sec_user_agent", UA)
    return s


# ── the world: an acquirer, a CIK-less acquired company, the deal edge ──────


class _World:
    def __init__(self):
        self.db = SessionLocal()
        self.entities: list[uuid.UUID] = []
        self.evidence: list[uuid.UUID] = []
        self.users: list[uuid.UUID] = []
        self.ciks: list[str] = []
        self.observer = make_observer(self.db)

    def user(self, role: str = UserRole.ADMIN.value) -> User:
        u = User(id=uuid.uuid4(), email=f"rl236-{_hex()}@example.invalid", full_name="rl236 test",
                 role=role, is_active=True)
        self.db.add(u)
        self.db.commit()
        self.users.append(u.id)
        return u

    def headers(self, role: str = UserRole.ADMIN.value) -> dict:
        u = self.user(role)
        return {"Authorization": f"Bearer {create_access_token(str(u.id), role)}"}

    def entity(self, cik: str | None = None, name: str | None = None) -> OrgEntity:
        e = OrgEntity(id=uuid.uuid4(), legal_name=name or f"Example Target {_hex()}, Inc.", cik=cik)
        self.db.add(e)
        self.db.commit()
        self.entities.append(e.id)
        return e

    def cik(self) -> str:
        c = make_cik(self.db)
        self.ciks.append(c)
        return c

    def ev(self):
        f = make_evidence(self.db, content=f"rl236 {_hex()}".encode(), source_url=f"https://example.test/{_hex()}")
        self.evidence.append(f.id)
        return f

    def relation(self, subject, obj, relation, *, observer=None, confirm_by_person=False, event_date=None):
        rel = entity_graph.assert_relation(
            self.db, subject_id=subject.id, object_id=obj.id, relation=relation,
            observer_id=(observer or self.observer).id, evidence_id=self.ev().id, quote="rl236",
            event_date=event_date, event_date_precision="day" if event_date else "unknown",
        )
        if confirm_by_person:
            rel = entity_graph.decide(self.db, relation_id=rel.id, status="confirmed", user=self.user())
        return rel

    def deal(self, *, confirmed: bool = True):
        """(acquirer, acquired): `acquirer acquired acquired`, confirmed by
        a person unless told otherwise."""
        acquirer = self.entity(cik=self.cik(), name=f"Example Acquirer {_hex()}")
        acquired = self.entity()
        self.relation(acquirer, acquired, "acquired", confirm_by_person=confirmed, event_date=date(2015, 6, 1))
        return acquirer, acquired

    def section(self, entity):
        footnote = self.db.query(Observer).filter(Observer.name == "edgar_10k_footnote").one()
        text = "Note 3. Business Combinations\nWe acquired Example Widgets LLC in 2014."
        s = EntityFilingSection(
            id=uuid.uuid4(), entity_id=entity.id, observer_id=footnote.id, evidence_id=self.ev().id,
            accession_number=f"99000002{uuid.uuid4().int % 100:02d}-24-{uuid.uuid4().int % 10**6:06d}",
            form="10-K", filing_date=date(2014, 3, 1), report_date=None,
            section=acquisition_reader.SECTION, extraction="test", heading="Note 3. Business Combinations",
            heading_match_count=1, start_line=0, end_line=2, text=text,
        )
        self.db.add(s)
        self.db.commit()
        return s

    def close(self):
        db = self.db
        db.rollback()
        ids = set(self.entities)
        rels = db.query(EntityRelation).filter(
            EntityRelation.subject_id.in_(ids) | EntityRelation.object_id.in_(ids)
        ).all()
        others = {r.subject_id for r in rels} | {r.object_id for r in rels}
        all_ids = ids | others
        db.query(EntityRelation).filter(EntityRelation.id.in_([r.id for r in rels])).delete(synchronize_session=False)
        db.query(CandidateDomain).filter(CandidateDomain.entity_id.in_(all_ids)).delete(synchronize_session=False)
        db.query(EntityFilingSection).filter(EntityFilingSection.entity_id.in_(all_ids)).delete(synchronize_session=False)
        db.query(EntityFilingEvent).filter(EntityFilingEvent.entity_id.in_(all_ids)).delete(synchronize_session=False)
        db.query(EntitySubsidiaryListing).filter(
            EntitySubsidiaryListing.filer_entity_id.in_(all_ids)
        ).delete(synchronize_session=False)
        db.query(EntityIngestRun).filter(EntityIngestRun.cik.in_(self.ciks)).delete(synchronize_session=False)
        db.commit()
        db.query(OrgEntity).filter(OrgEntity.id.in_(all_ids)).delete(synchronize_session=False)
        db.commit()
        for fid in self.evidence:
            cleanup_evidence(db, fid)
        cleanup_observer(db, self.observer.id)
        db.query(AuditLog).filter(AuditLog.user_id.in_(self.users)).delete(synchronize_session=False)
        db.query(User).filter(User.id.in_(self.users)).delete(synchronize_session=False)
        db.commit()
        db.close()


@pytest.fixture
def w():
    world = _World()
    yield world
    world.close()


# ── 1. sec_edgar: the search URL and the allowlist ──────────────────────────


def test_search_url_encodes_the_query_and_passes_the_allowlist():
    url = sec_edgar.company_search_url("  Example & Sons/Co #1 ", contains=True)
    parts = urlsplit(url)
    assert (parts.scheme, parts.netloc, parts.path) == ("https", "www.sec.gov", "/cgi-bin/browse-edgar")
    params = parse_qs(parts.query)
    assert params["company"] == ["Example & Sons/Co #1"]  # trimmed, and never split by & or #
    assert params["action"] == ["getcompany"] and params["match"] == ["contains"]
    assert not parts.fragment
    sec_edgar._check_allowlisted(url)  # does not raise
    assert "match" not in parse_qs(urlsplit(sec_edgar.company_search_url("Example")).query)


@pytest.mark.parametrize("query", ["", "   ", "x" * 101, "Example\nHoldings", "Example\x00", 7])
def test_search_url_refuses_bad_queries(query):
    with pytest.raises(ValueError):
        sec_edgar.company_search_url(query)


@pytest.mark.parametrize("url", [
    "https://www.sec.gov/cgi-bin/browse-edgar?action=getcurrent&company=x",
    "https://www.sec.gov/cgi-bin/browse-edgar?company=x",
    "https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany",
    "https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&action=getcompany&company=x",
    "https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&company=x&company=y",
    "https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&company=x&output=atom",
    "https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&company=x#frag",
    "https://www.sec.gov/cgi-bin/browse-edgar/../srch-edgar?action=getcompany&company=x",
    "https://www.sec.gov/cgi-bin/srch-edgar?action=getcompany&company=x",
    "http://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&company=x",
    "https://efts.sec.gov/cgi-bin/browse-edgar?action=getcompany&company=x",
])
def test_allowlist_admits_only_the_company_search(url):
    with pytest.raises(ValueError):
        sec_edgar._check_allowlisted(url)


def test_allowlist_still_admits_the_archive_tree():
    sec_edgar._check_allowlisted("https://www.sec.gov/Archives/edgar/data/1/000000000124000001/x.htm")


# ── 2. sec_edgar: parsing the search page ───────────────────────────────────


def test_parse_list_page_returns_ciks_in_order_and_skips_other_links():
    a, b = "9911111111", "9922222222"
    html = search_list_html([a, b, a])
    assert sec_edgar.parse_company_search(html.encode()) == [a, b]


def test_parse_single_company_page():
    assert sec_edgar.parse_company_search(search_company_html("9933333333").encode()) == ["9933333333"]


def test_parse_no_match_page_is_empty():
    assert sec_edgar.parse_company_search(SEARCH_NONE_HTML.encode()) == []


def test_parse_ignores_a_link_whose_text_and_href_disagree():
    html = search_list_html(["9911111111"]).replace("CIK=9911111111", "CIK=9944444444")
    with pytest.raises(sec_edgar.SecSearchUnparsed):
        sec_edgar.parse_company_search(html.encode())


def test_parse_a_results_page_with_no_cik_fails_loudly():
    """A layout change must not read as "no registrant by that name"."""
    html = '<html><table class="tableFile2"><tr><td>something new</td></tr></table></html>'
    with pytest.raises(sec_edgar.SecSearchUnparsed):
        sec_edgar.parse_company_search(html.encode())


def test_search_retries_an_error_page_then_parses(sec):
    sec.search_pages = ["<html>Undeclared Automated Tool</html>", search_list_html(["9955555555"])]
    assert sec_edgar.search_companies("Example") == ["9955555555"]
    assert len(sec.requests) == 2
    sent = sec.requests[-1]
    assert sent.url.path == "/cgi-bin/browse-edgar"
    assert sent.headers["User-Agent"] == UA


# ── 3. registrant facts (the reviewer's hint) ───────────────────────────────


def test_summarise_the_real_wire_shape():
    f = rl.summarise_submissions(submissions_json("9966666666"))
    assert f.cik == "9966666666" and f.name == "EXAMPLE TARGET CORP"
    assert (f.state_of_incorporation, f.sic) == ("DE", "7372")
    assert f.former_names == [{"name": "EXAMPLE TARGET INC", "from": "2001-02-03", "to": "2008-04-05"}]
    assert (f.first_filing, f.last_filing) == ("1999-01-04", "2012-03-01")
    assert (f.annual_reports, f.first_annual_report, f.last_annual_report) == (2, "2011-03-01", "2012-03-01")
    assert f.annual_reports_partial is True
    assert rl.summarise_submissions(submissions_json("9966666666", files=False)).annual_reports_partial is False


def test_summarise_tolerates_malformed_fields():
    data = submissions_json("9966666666")
    data.update(sic=7, stateOfIncorporation=None, formerNames=[{"name": None}, "x"], cik=None)
    data["filings"]["recent"]["filingDate"] = ["not a date", None, "2010-05-01"]
    data["filings"]["files"] = [{"filingFrom": 5}, "x"]
    f = rl.summarise_submissions(data)
    assert (f.sic, f.state_of_incorporation, f.former_names, f.cik) == (None, None, [], "")
    assert (f.first_filing, f.last_filing, f.annual_reports) == ("2010-05-01", "2010-05-01", 0)


def test_suggested_query_drops_the_legal_suffix():
    assert rl.suggested_query("Example Widgets, Inc.") == "Example Widgets"
    assert rl.suggested_query("Example Widgets") == "Example Widgets"


# ── 4. the gate ─────────────────────────────────────────────────────────────


def test_context_eligible_only_with_a_confirmed_deal_and_no_cik(w):
    _acquirer, acquired = w.deal()
    ctx = rl.context(w.db, acquired.id)
    assert ctx.eligible and ctx.reason is None and not ctx.linked
    assert [d.event_date for d in ctx.deals] == ["2015-06-01"]

    _a2, proposed_only = w.deal(confirmed=False)
    ctx = rl.context(w.db, proposed_only.id)
    assert not ctx.eligible and "confirmed" in ctx.reason and ctx.deals == []

    filer = w.entity(cik=w.cik())
    assert rl.context(w.db, filer.id).reason == "this company already has a CIK"


def test_a_confirmed_subsidiary_edge_is_not_a_deal(w):
    """Only `acquired` reaches the link: an EX-21 child is not an
    acquisition the person confirmed."""
    parent = w.entity(cik=w.cik())
    child = w.entity()
    w.relation(child, parent, "subsidiary_of", confirm_by_person=True)
    assert not rl.context(w.db, child.id).eligible


def test_search_refuses_an_ineligible_company_before_contacting_sec(w, sec):
    _a, acquired = w.deal(confirmed=False)
    with pytest.raises(rl.LinkConflict):
        rl.search(w.db, entity_id=acquired.id, query="Example")
    assert sec.requests == []


def test_search_returns_facts_and_flags_a_taken_cik(w, sec):
    _a, acquired = w.deal()
    free, taken, gone = w.cik(), w.cik(), w.cik()
    holder = w.entity(cik=taken)
    sec.search_pages = [search_list_html([free, taken, gone])]
    sec.submissions = {free: submissions_json(free), taken: submissions_json(taken, name="OTHER CO")}
    out = rl.search(w.db, entity_id=acquired.id, query="Example")
    assert [f.cik for f in out] == [free, taken]  # the 404 one is dropped
    assert out[0].taken_by_id is None
    assert (out[1].taken_by_id, out[1].taken_by_name) == (holder.id, holder.legal_name)


def test_search_caps_the_candidates(w, sec, monkeypatch):
    monkeypatch.setattr(rl, "MAX_CANDIDATES", 2)
    _a, acquired = w.deal()
    ciks = [w.cik() for _ in range(3)]
    sec.search_pages = [search_list_html(ciks)]
    sec.submissions = {c: submissions_json(c) for c in ciks}
    assert len(rl.search(w.db, entity_id=acquired.id, query="Example")) == 2
    assert sum(r.url.path.startswith("/submissions/") for r in sec.requests) == 2


# ── 5. the link ─────────────────────────────────────────────────────────────


def test_link_sets_the_cik_on_the_existing_entity_and_queues_the_ingest(w, sec):
    _a, acquired = w.deal()
    cik = w.cik()
    sec.submissions = {cik: submissions_json(cik)}
    admin = w.user()
    before = w.db.query(OrgEntity).count()
    entity, run, facts = rl.link(w.db, entity_id=acquired.id, cik=cik, user=admin)
    assert entity.id == acquired.id and entity.cik == cik
    assert entity.registrant_linked_by_id == admin.id and entity.registrant_linked_at is not None
    assert (run.cik, run.kind, run.status) == (cik, "edgar_ingest", "queued")
    assert facts.name == "EXAMPLE TARGET CORP"
    assert w.db.query(OrgEntity).count() == before  # no new entity
    assert rl.context(w.db, acquired.id).linked


def test_link_refuses_a_cik_already_on_another_entity_and_names_it(w, sec):
    _a, acquired = w.deal()
    cik = w.cik()
    holder = w.entity(cik=cik)
    sec.submissions = {cik: submissions_json(cik)}
    with pytest.raises(rl.CikTaken) as exc:
        rl.link(w.db, entity_id=acquired.id, cik=cik, user=w.user())
    assert (exc.value.entity_id, exc.value.legal_name) == (holder.id, holder.legal_name)
    w.db.refresh(acquired)
    assert acquired.cik is None


def test_link_refuses_without_a_confirmed_deal_and_sends_nothing(w, sec):
    _a, acquired = w.deal(confirmed=False)
    cik = w.cik()
    sec.submissions = {cik: submissions_json(cik)}
    with pytest.raises(rl.LinkConflict):
        rl.link(w.db, entity_id=acquired.id, cik=cik, user=w.user())
    assert sec.requests == []
    w.db.refresh(acquired)
    assert acquired.cik is None


def test_link_refuses_an_unknown_registrant(w, sec):
    _a, acquired = w.deal()
    with pytest.raises(rl.LinkInvalid):
        rl.link(w.db, entity_id=acquired.id, cik=w.cik(), user=w.user())
    assert len(sec.requests) == 1  # it did ask SEC
    with pytest.raises(rl.LinkInvalid):
        rl.link(w.db, entity_id=acquired.id, cik="12ab", user=w.user())


def test_link_refuses_while_an_ingest_of_that_cik_is_active(w, sec):
    _a, acquired = w.deal()
    cik = w.cik()
    sec.submissions = {cik: submissions_json(cik)}
    w.db.add(EntityIngestRun(cik=cik, kind="edgar_ingest", status="running", started_at=datetime.now(timezone.utc)))
    w.db.commit()
    with pytest.raises(rl.LinkConflict, match="already queued or running"):
        rl.link(w.db, entity_id=acquired.id, cik=cik, user=w.user())
    w.db.refresh(acquired)
    assert acquired.cik is None and acquired.registrant_linked_at is None


def test_a_link_record_without_a_cik_is_refused_by_the_check(w):
    e = w.entity()
    e.registrant_linked_at = datetime.now(timezone.utc)
    with pytest.raises(IntegrityError):
        w.db.commit()
    w.db.rollback()


# ── 6. the follow-up read ───────────────────────────────────────────────────


def _linked(w, sec):
    acquirer, acquired = w.deal()
    cik = w.cik()
    sec.submissions = {cik: submissions_json(cik)}
    entity, run, _f = rl.link(w.db, entity_id=acquired.id, cik=cik, user=w.user())
    run.status, run.result = "succeeded", {}
    run.started_at = run.finished_at = datetime.now(timezone.utc)
    w.db.commit()
    return acquirer, entity


def test_followup_skips_without_a_section(w, sec, monkeypatch):
    monkeypatch.setattr(llm_connector, "is_configured", lambda db: True)
    _a, e = _linked(w, sec)
    run, reason = rl.followup_read(w.db, entity_id=e.id, cik10=e.cik, user_id=None)
    assert run is None and "Business Combinations" in reason


def test_followup_skips_when_the_llm_is_not_configured(w, sec, monkeypatch):
    monkeypatch.setattr(llm_connector, "is_configured", lambda db: False)
    _a, e = _linked(w, sec)
    w.section(e)
    run, reason = rl.followup_read(w.db, entity_id=e.id, cik10=e.cik, user_id=None)
    assert run is None and "OpenRouter" in reason


def test_followup_queues_the_read_on_the_linked_entity(w, sec, monkeypatch):
    monkeypatch.setattr(llm_connector, "is_configured", lambda db: True)
    _a, e = _linked(w, sec)
    w.section(e)
    run, reason = rl.followup_read(w.db, entity_id=e.id, cik10=e.cik, user_id=None)
    assert reason is None and (run.kind, run.cik, run.status) == ("acquisition_read", e.cik, "queued")


def test_followup_skips_after_an_unlink(w, sec, monkeypatch):
    monkeypatch.setattr(llm_connector, "is_configured", lambda db: True)
    _a, e = _linked(w, sec)
    w.section(e)
    cik = e.cik
    rl.unlink(w.db, entity_id=e.id, user=w.user())
    run, reason = rl.followup_read(w.db, entity_id=e.id, cik10=cik, user_id=None)
    assert run is None and "removed" in reason


# ── 7. unlink ───────────────────────────────────────────────────────────────


def _produce(w, e, acquirer):
    """What a link's runs leave on `e`, one of each kind."""
    former_obs = w.db.query(Observer).filter(Observer.name == "edgar_former_names").one()
    website = w.db.query(Observer).filter(Observer.name == "edgar_10k_website").one()
    former = w.entity(name=f"Example Former {_hex()}")
    rows = SimpleNamespace(
        former=w.relation(e, former, "formerly_named", observer=former_obs),  # source-confirmed
        acquired=w.relation(e, w.entity(), "acquired"),
        subsidiary=w.relation(w.entity(), e, "subsidiary_of"),
        already_rejected=w.relation(e, w.entity(), "acquired"),
        own_parent=w.relation(e, acquirer, "subsidiary_of"),  # E as CHILD: not the link's
    )
    entity_graph.decide(w.db, relation_id=rows.already_rejected.id, status="rejected", user=w.user())
    dom = f"rl236-{_hex()}.com"
    ev = w.ev()
    from app.services import candidate_domains as cd
    cd.propose_from_filing(w.db, entity_id=e.id, domain=dom, observer=website, evidence_id=ev.id,
                           quote=f"Our website is www.{dom}.", filing_date=date(2012, 3, 1))
    rows.candidate = w.db.query(CandidateDomain).filter_by(entity_id=e.id, domain=dom).one()
    manual = f"rl236-{_hex()}.com"
    rows.manual = CandidateDomain(id=uuid.uuid4(), entity_id=e.id, domain=manual, source="person",
                                  evidence_id=w.ev().id, quote=f"see {manual}")
    w.db.add(rows.manual)
    events_obs = w.db.query(Observer).filter(Observer.name == "edgar_8k_items").one()
    ex21_obs = w.db.query(Observer).filter(Observer.name == "edgar_ex21").one()
    w.db.add(EntityFilingEvent(id=uuid.uuid4(), entity_id=e.id, observer_id=events_obs.id, evidence_id=w.ev().id,
                               form="8-K", accession_number="9900000001-10-000001",
                               filing_date=date(2010, 5, 1), items="2.01"))
    w.db.add(EntitySubsidiaryListing(id=uuid.uuid4(), filer_entity_id=e.id, observer_id=ex21_obs.id,
                                     evidence_id=w.ev().id, accession_number="9900000001-12-000001",
                                     exhibit_type="EX-21", filing_date=date(2012, 3, 1), row_index=0,
                                     name="Example Sub LLC", cells=["Example Sub LLC"]))
    w.db.commit()
    w.section(e)
    return rows


def _status(w, row):
    w.db.expire_all()
    return w.db.get(type(row), row.id).status


def test_unlink_undoes_what_the_link_produced_and_nothing_else(w, sec):
    acquirer, e = _linked(w, sec)
    rows = _produce(w, e, acquirer)
    assert _status(w, rows.former) == "confirmed"  # precondition: source-confirmed
    rejector = w.db.query(EntityRelation).get(rows.already_rejected.id).decided_by_id
    unlinker = w.user()

    entity, summary = rl.unlink(w.db, entity_id=e.id, user=unlinker)

    assert entity.cik is None and entity.registrant_linked_at is None and entity.registrant_linked_by_id is None
    assert summary["relations_rejected"] == 3 and summary["candidates_rejected"] == 1
    assert (summary["filing_events"], summary["filing_sections"], summary["subsidiary_listings"]) == (1, 1, 1)
    for r in (rows.former, rows.acquired, rows.subsidiary):
        got = w.db.get(EntityRelation, r.id)
        assert (got.status, got.decision_kind, got.decided_by_id) == ("rejected", "person", unlinker.id)
    assert w.db.get(EntityRelation, rows.already_rejected.id).decided_by_id == rejector
    assert _status(w, rows.own_parent) == "proposed"
    deal = w.db.query(EntityRelation).filter_by(subject_id=acquirer.id, object_id=e.id, relation="acquired").one()
    assert deal.status == "confirmed"
    assert _status(w, rows.candidate) == "rejected"
    assert _status(w, rows.manual) == "proposed"
    assert w.db.query(EntityFilingSection).filter_by(entity_id=e.id).count() == 0
    # Linkable again, to the right registrant this time.
    assert rl.context(w.db, e.id).eligible


def test_unlink_refuses_once_a_person_confirmed_its_output(w, sec):
    acquirer, e = _linked(w, sec)
    rows = _produce(w, e, acquirer)
    entity_graph.decide(w.db, relation_id=rows.acquired.id, status="confirmed", user=w.user())
    with pytest.raises(rl.LinkConflict, match="1 confirmed"):
        rl.unlink(w.db, entity_id=e.id, user=w.user())
    w.db.expire_all()
    assert w.db.get(OrgEntity, e.id).cik is not None
    assert _status(w, rows.subsidiary) == "proposed"
    assert w.db.query(EntityFilingSection).filter_by(entity_id=e.id).count() == 1


def test_unlink_refuses_once_a_domain_was_accepted(w, sec):
    acquirer, e = _linked(w, sec)
    _produce(w, e, acquirer)
    website = w.db.query(Observer).filter(Observer.name == "edgar_10k_website").one()
    dom = f"rl236-{_hex()}.com"
    w.db.add(CandidateDomain(id=uuid.uuid4(), entity_id=e.id, domain=dom, source="edgar_10k_website",
                             observer_id=website.id, evidence_id=w.ev().id, quote=f"www.{dom}",
                             status="accepted", accepted_into="estate", decided_at=datetime.now(timezone.utc)))
    w.db.commit()
    with pytest.raises(rl.LinkConflict, match="1 accepted"):
        rl.unlink(w.db, entity_id=e.id, user=w.user())
    w.db.expire_all()
    assert w.db.get(OrgEntity, e.id).cik is not None


def test_unlink_refuses_while_a_run_is_active(w, sec):
    _a, e = _linked(w, sec)
    w.db.add(EntityIngestRun(cik=e.cik, kind="acquisition_read", status="queued"))
    w.db.commit()
    with pytest.raises(rl.LinkConflict, match="queued or running"):
        rl.unlink(w.db, entity_id=e.id, user=w.user())


def test_unlink_refuses_a_directly_mapped_filer(w):
    """Its CIK is its identity, not a decision: nothing to undo."""
    filer = w.entity(cik=w.cik())
    w.section(filer)
    with pytest.raises(rl.LinkConflict, match="not set by a registrant link"):
        rl.unlink(w.db, entity_id=filer.id, user=w.user())
    w.db.expire_all()
    assert w.db.get(OrgEntity, filer.id).cik is not None
    assert w.db.query(EntityFilingSection).filter_by(entity_id=filer.id).count() == 1


# ── 8. the API ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize("role", [UserRole.VIEWER.value, UserRole.INTEGRATION_ADMIN.value])
def test_writes_and_sec_lookups_are_admin_only(w, sec, role):
    _a, acquired = w.deal()
    h = w.headers(role)
    base = f"/api/entities/{acquired.id}"
    assert client.get(f"{base}/registrant-candidates?q=Example", headers=h).status_code == 403
    assert client.post(f"{base}/registrant-link", json={"cik": "1"}, headers=h).status_code == 403
    assert client.delete(f"{base}/registrant-link", headers=h).status_code == 403
    assert client.get(f"{base}/registrant-link", headers=h).status_code == 200  # a read
    assert sec.requests == []


def test_api_candidates_needs_exactly_one_of_q_or_cik(w, sec):
    _a, acquired = w.deal()
    h = w.headers()
    base = f"/api/entities/{acquired.id}/registrant-candidates"
    assert client.get(base, headers=h).status_code == 422
    assert client.get(f"{base}?q=x&cik=1", headers=h).status_code == 422
    cik = w.cik()
    sec.submissions = {cik: submissions_json(cik)}
    r = client.get(f"{base}?cik={cik}", headers=h)
    assert r.status_code == 200 and [c["cik"] for c in r.json()] == [cik]


def test_api_taken_cik_names_the_holder(w, sec):
    _a, acquired = w.deal()
    cik = w.cik()
    holder = w.entity(cik=cik)
    sec.submissions = {cik: submissions_json(cik)}
    r = client.post(f"/api/entities/{acquired.id}/registrant-link", json={"cik": cik}, headers=w.headers())
    assert r.status_code == 409
    assert r.json()["detail"]["entity_id"] == str(holder.id)


def test_api_link_runs_the_ingest_then_the_read_on_the_linked_entity(w, sec, monkeypatch):
    """The background chain, run synchronously by TestClient. The ingest
    and the read are stubbed: their own suites cover what they do."""
    _a, acquired = w.deal()
    cik = w.cik()
    sec.submissions = {cik: submissions_json(cik)}
    calls: list[tuple] = []

    def fake_ingest(db, c):
        calls.append(("ingest", c))
        w.section(db.query(OrgEntity).filter(OrgEntity.cik == c).one())
        return edgar_ingest.IngestResult(entity_id=acquired.id, denied=[])

    def fake_read(db, *, entity_id, run_id):
        calls.append(("read", entity_id))
        return SimpleNamespace(as_dict=lambda: {"proposed": 0})

    monkeypatch.setattr(edgar_ingest, "ingest_cik", fake_ingest)
    monkeypatch.setattr(acquisition_reader, "read_acquisitions", fake_read)
    monkeypatch.setattr(llm_connector, "is_configured", lambda db: True)

    h = w.headers()
    r = client.post(f"/api/entities/{acquired.id}/registrant-link", json={"cik": cik}, headers=h)
    assert r.status_code == 202, r.text
    assert r.json()["entity"]["cik"] == cik and r.json()["entity"]["registrant_linked_at"]
    assert calls == [("ingest", cik), ("read", acquired.id)]

    w.db.expire_all()
    ingest_run = w.db.query(EntityIngestRun).filter_by(cik=cik, kind="edgar_ingest").one()
    read_run = w.db.query(EntityIngestRun).filter_by(cik=cik, kind="acquisition_read").one()
    assert ingest_run.status == "succeeded" and read_run.status == "succeeded"
    assert ingest_run.result["acquisition_read"] == {"status": "queued", "run_id": str(read_run.id)}

    # Another filer's newer ingest: the filter must leave it out.
    w.db.add(EntityIngestRun(cik=w.cik(), kind="edgar_ingest", status="queued"))
    w.db.commit()
    listed = client.get(f"/api/entities/edgar-ingest/runs?cik={cik}&limit=5", headers=h).json()
    assert [r["id"] for r in listed] == [str(ingest_run.id)]
    assert listed[0]["entity_id"] == str(acquired.id)
    assert client.get("/api/entities/edgar-ingest/runs?cik=12ab", headers=h).status_code == 422

    rows = w.db.query(AuditLog).filter(AuditLog.user_id.in_(w.users)).all()
    changes = [a.detail["changes"] for a in rows if "registrant" in ((a.detail or {}).get("changes") or {})]
    assert len(changes) == 1
    assert changes[0]["registrant"]["name"] == "EXAMPLE TARGET CORP"
    assert changes[0]["registrant_link"] == {"from": None, "to": cik}


def test_api_link_records_why_the_read_did_not_run(w, sec, monkeypatch):
    _a, acquired = w.deal()
    cik = w.cik()
    sec.submissions = {cik: submissions_json(cik)}
    read_called = []
    monkeypatch.setattr(edgar_ingest, "ingest_cik",
                        lambda db, c: edgar_ingest.IngestResult(entity_id=acquired.id, denied=[]))
    monkeypatch.setattr(acquisition_reader, "read_acquisitions", lambda *a, **k: read_called.append(1))
    r = client.post(f"/api/entities/{acquired.id}/registrant-link", json={"cik": cik}, headers=w.headers())
    assert r.status_code == 202
    w.db.expire_all()
    ingest_run = w.db.query(EntityIngestRun).filter_by(cik=cik, kind="edgar_ingest").one()
    assert ingest_run.status == "succeeded"  # the chain was reached
    assert ingest_run.result["acquisition_read"]["status"] == "skipped"
    assert "Business Combinations" in ingest_run.result["acquisition_read"]["reason"]
    assert read_called == []


def test_api_link_after_a_failed_ingest_skips_the_read(w, sec, monkeypatch):
    _a, acquired = w.deal()
    cik = w.cik()
    sec.submissions = {cik: submissions_json(cik)}

    def boom(db, c):
        raise sec_edgar.SecFetchError("synthetic")

    monkeypatch.setattr(edgar_ingest, "ingest_cik", boom)
    r = client.post(f"/api/entities/{acquired.id}/registrant-link", json={"cik": cik}, headers=w.headers())
    assert r.status_code == 202
    w.db.expire_all()
    run = w.db.query(EntityIngestRun).filter_by(cik=cik, kind="edgar_ingest").one()
    assert run.status == "failed"
    assert run.result["acquisition_read"]["reason"] == "the ingest did not succeed"
    assert w.db.query(EntityIngestRun).filter_by(cik=cik, kind="acquisition_read").count() == 0


def test_api_unlink(w, sec):
    acquirer, e = _linked(w, sec)
    _produce(w, e, acquirer)
    r = client.delete(f"/api/entities/{e.id}/registrant-link", headers=w.headers())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["entity"]["cik"] is None and body["relations_rejected"] == 3
    assert client.delete(f"/api/entities/{e.id}/registrant-link", headers=w.headers()).status_code == 409
