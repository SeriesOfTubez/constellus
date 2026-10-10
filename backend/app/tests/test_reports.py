"""Coverage for planning#230 slice 1: grounded executive-summary reports
(`app.services.report_facts`, `app.services.reports`, `/api/reports`,
migration 0073, the `read_scope.engagement_visible` hook).

Recorded fixtures only: every LLM response is scripted on
`llm_connector._transport` and the assertions read what the TRANSPORT
received, never a wrapper. Synthetic rows only (RFC 5737 addresses,
example.com names), every row deleted by id afterwards.

Run with:  backend/scripts/test.ps1 app/tests/test_reports.py
"""

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import distinct, func, select

from app.core.database import SessionLocal
from app.main import app
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.engagement import Engagement
from app.models.finding_canonical import FindingCanonical
from app.models.llm_call import LlmCall
from app.models.report import Report
from app.models.target import Target
from app.models.target_asset_link import TargetAssetLink
from app.models.user import User, UserRole
from app.services import query_compiler, read_scope, report_facts, reports
from app.services.query_schema import validate
from app.tests.test_edgar_ingest_api import _cleanup_user, _make_user
from app.tests.test_finding_writeup import NARRATE_PRIMARY, _World, llm, permissive  # noqa: F401  (fixtures)
from app.tests.test_llm_connector import _ok_response

client = TestClient(app)

OPEN = ("open", "acknowledged")


def _viewer() -> User:
    return User(id=uuid.uuid4(), email="rpt-viewer@example.invalid", full_name="rpt",
                role=UserRole.VIEWER.value, is_active=True)


# ── fixtures ────────────────────────────────────────────────────────────────

class _RWorld(_World):
    """`_World` plus report/ledger cleanup (ledger rows pin engagements)."""

    def set_finding(self, finding_id, **fields) -> None:
        db = SessionLocal()
        try:
            db.query(FindingCanonical).filter(FindingCanonical.id == finding_id).update(
                fields, synchronize_session=False)
            db.commit()
        finally:
            db.close()

    def close(self):
        db = SessionLocal()
        try:
            if self.engagement_ids:
                db.query(LlmCall).filter(LlmCall.engagement_id.in_(self.engagement_ids)).delete(
                    synchronize_session=False)
                db.query(Report).filter(Report.engagement_id.in_(self.engagement_ids)).delete(
                    synchronize_session=False)
            db.commit()
        finally:
            db.close()
        super().close()


@pytest.fixture
def world():
    w = _RWorld()
    yield w
    w.close()


class Scenario:
    """Engagement E (the subject), F (another), and:

    E assets:  a1 claimed (two E targets), a2 proven, a5 claimed (also in F), a7 not_ours, a8 unknown
    elsewhere: a3 in F only, a4 unlinked, a6 linked to a target without an engagement
    E findings (all first seen at `as_of`, unless noted):
      f_crit  critical open, risk 91, on a1
      f_high  high open, kev + exploit, risk 80, on a2
      f_med   medium open, risk 50, on a5 (also in F)
      f_low   low acknowledged, risk 10, on a7, first seen as_of-29d
      f_res   critical resolved 5d before as_of, first seen as_of-31d, on a1
    Outside E: critical open findings on a3 and a4."""


def build_scenario(world: _RWorld, as_of: datetime, posture: str = "pre_close") -> Scenario:
    s = Scenario()
    s.E, s.F = world.engagement(posture), world.engagement(posture)
    t_e1 = world.target(engagement_id=s.E)
    t_e2 = world.target(engagement_id=s.E)
    t_f = world.target(engagement_id=s.F)
    t_null = world.target(engagement_id=None)
    s.a1 = world.asset(estate="claimed_ours")
    s.a2 = world.asset(estate="proven_ours")
    s.a5 = world.asset(estate="claimed_ours")
    s.a7 = world.asset(estate="not_ours")
    s.a8 = world.asset(estate=None)
    s.a3 = world.asset()
    s.a4 = world.asset()
    s.a6 = world.asset()
    db = SessionLocal()
    try:
        link = lambda t, a: db.add(TargetAssetLink(  # noqa: E731
            target_id=t, asset_canonical_id=a, first_linked_at=as_of, last_observed_at=as_of))
        for t, a in ((t_e1, s.a1), (t_e2, s.a1), (t_e1, s.a2), (t_e1, s.a5), (t_f, s.a5), (t_e1, s.a7),
                     (t_e2, s.a8), (t_f, s.a3), (t_null, s.a6)):
            link(t, a)
        db.commit()
    finally:
        db.close()
    s.f_crit = world.finding(s.a1, severity="critical", title="Crit finding on a1")
    s.f_high = world.finding(s.a2, severity="high", title="High finding on a2", kev=True)
    s.f_med = world.finding(s.a5, severity="medium", title="Medium finding on a5")
    s.f_low = world.finding(s.a7, severity="low", title="Low finding on a7", state="acknowledged")
    s.f_res = world.finding(s.a1, severity="critical", title="Resolved finding on a1", state="resolved")
    s.f_out1 = world.finding(s.a3, severity="critical", title="Out of scope A")
    s.f_out2 = world.finding(s.a4, severity="critical", title="Out of scope B")
    day = timedelta(days=1)
    world.set_finding(s.f_crit, risk_score=91, first_seen_at=as_of)
    world.set_finding(s.f_high, risk_score=80, has_exploit=True, first_seen_at=as_of)
    world.set_finding(s.f_med, risk_score=50, first_seen_at=as_of)
    world.set_finding(s.f_low, risk_score=10, first_seen_at=as_of - 29 * day)
    world.set_finding(s.f_res, risk_score=95, first_seen_at=as_of - 31 * day, resolved_at=as_of - 5 * day)
    s.as_of = as_of
    return s


def _facts(s: Scenario, as_of=None) -> dict:
    db = SessionLocal()
    try:
        e = db.get(Engagement, s.E)
        return report_facts.build_facts(db, e, _viewer(), as_of or s.as_of)
    finally:
        db.close()


# ── 1. facts ────────────────────────────────────────────────────────────────

def _oracle(db, eid) -> dict[str, int]:
    """The same numbers by plain ORM SQL, not the query language."""
    in_e = select(TargetAssetLink.asset_canonical_id).join(Target, Target.id == TargetAssetLink.target_id).where(
        Target.engagement_id == eid)

    def assets(*conds) -> int:
        return db.execute(
            select(func.count(distinct(AssetCanonical.id)))
            .select_from(AssetCanonical).outerjoin(AssetState, AssetState.asset_canonical_id == AssetCanonical.id)
            .where(AssetCanonical.id.in_(in_e), *conds)
        ).scalar_one()

    def findings(*conds) -> int:
        return db.execute(
            select(func.count(distinct(FindingCanonical.id))).where(
                FindingCanonical.asset_canonical_id.in_(in_e), *conds)
        ).scalar_one()

    return {"_assets": assets, "_findings": findings}


def test_every_metric_equals_an_independent_sql_count(world):
    as_of = datetime.now(timezone.utc)
    s = build_scenario(world, as_of)
    facts = _facts(s)
    since = as_of - timedelta(days=30)
    estate = func.coalesce(AssetState.estate, "unknown")
    db = SessionLocal()
    try:
        o = _oracle(db, s.E)
        A, F = o["_assets"], o["_findings"]
        F_ = FindingCanonical
        open_ = F_.state.in_(OPEN)
        expected = {
            "assets_total": A(estate != "not_ours"),
            "assets_proven_ours": A(estate == "proven_ours"),
            "assets_claimed_ours": A(estate == "claimed_ours"),
            "assets_not_ours": A(estate == "not_ours"),
            "assets_unknown": A(estate == "unknown"),
            "assets_new_30d": A(estate != "not_ours", AssetCanonical.first_seen_at >= since),
            "findings_open": F(open_),
            "findings_open_critical": F(open_, F_.severity == "critical"),
            "findings_open_high": F(open_, F_.severity == "high"),
            "findings_open_medium": F(open_, F_.severity == "medium"),
            "findings_open_low": F(open_, F_.severity == "low"),
            "findings_open_kev": F(open_, F_.kev.is_(True)),
            "findings_open_exploit": F(open_, F_.has_exploit.is_(True)),
            "findings_new_30d": F(F_.first_seen_at >= since),
            "findings_resolved_30d": F(F_.resolved_at >= since),
        }
    finally:
        db.close()
    assert set(facts["metrics"]) == set(expected)
    assert {k: m["count"] for k, m in facts["metrics"].items()} == expected
    assert facts["metric_order"] == list(expected)  # the display order, kept outside JSONB key order
    assert {k for k, m in facts["metrics"].items() if "window_days" in m} == {
        "assets_new_30d", "findings_new_30d", "findings_resolved_30d"}
    assert {m["window_days"] for m in facts["metrics"].values() if "window_days" in m} == {30}
    # Hand-checked against the scenario, so the oracle itself is not the only witness.
    assert expected == {
        "assets_total": 4, "assets_proven_ours": 1, "assets_claimed_ours": 2, "assets_not_ours": 1,
        "assets_unknown": 1, "assets_new_30d": 4, "findings_open": 4, "findings_open_critical": 1,
        "findings_open_high": 1, "findings_open_medium": 1, "findings_open_low": 1,
        "findings_open_kev": 1, "findings_open_exploit": 1, "findings_new_30d": 4,
        "findings_resolved_30d": 1,
    }
    assert all(m["capped"] is False and m["label"] for m in facts["metrics"].values())


def test_each_metric_carries_a_query_that_reproduces_its_count(world):
    s = build_scenario(world, datetime.now(timezone.utc))
    facts = _facts(s)
    db = SessionLocal()
    try:
        for key, m in facts["metrics"].items():
            res = query_compiler.count_query(db, validate(m["query"]), _viewer())
            assert res["count"] == m["count"], key
            assert any(p.get("field") == "asset.engagement_id" and p["value"] == str(s.E)
                       for p in m["query"]["where"]["all"]), key
    finally:
        db.close()
    assert "name" not in facts["engagement"]
    assert facts["engagement"] == {"id": str(s.E), "posture": "pre_close"}


def test_top_findings_are_the_open_ones_in_the_engagement_by_risk(world):
    s = build_scenario(world, datetime.now(timezone.utc))
    facts = _facts(s)
    top = facts["top_findings"]
    assert [f["id"] for f in top] == [str(s.f_crit), str(s.f_high), str(s.f_med), str(s.f_low)]
    assert top[0] == {
        "id": str(s.f_crit), "title": "Crit finding on a1", "severity": "critical", "risk_score": 91,
        "risk_band": "imminent_compromise", "kev": False, "cve_id": "CVE-2099-0001",
        "asset_id": str(s.a1), "asset_value": top[0]["asset_value"],
    }
    assert facts["top_findings_query"]["limit"] == report_facts.TOP_FINDINGS
    assert facts["top_findings_query"]["sort"] == [{"field": "finding.risk_score", "dir": "desc"}]


def test_capped_flag_passes_through(world, monkeypatch):
    s = build_scenario(world, datetime.now(timezone.utc))
    monkeypatch.setattr(query_compiler, "COUNT_CAP", 1)
    m = _facts(s)["metrics"]
    assert m["assets_total"]["capped"] is True and m["assets_total"]["count"] == 1
    assert m["assets_proven_ours"]["capped"] is False  # exactly one: not "more than one"


def test_time_windows_are_pinned_to_as_of_not_now(world):
    now = datetime.now(timezone.utc)
    as_of = now - timedelta(days=10)
    s = build_scenario(world, as_of)
    m = _facts(s)["metrics"]
    # f_low was first seen as_of-29d (in the window); f_res as_of-31d (out of it).
    # Measured from now() the first would be 39d old, so a now()-based window would miss it.
    assert m["findings_new_30d"]["count"] == 4
    new = m["findings_new_30d"]["query"]["where"]["all"][1]
    assert new["value"] == (as_of - timedelta(days=30)).isoformat() and new["op"] == "gte"
    assert m["findings_resolved_30d"]["count"] == 1


def test_a_finding_first_seen_31_days_before_as_of_is_outside_the_window(world):
    as_of = datetime.now(timezone.utc)
    s = build_scenario(world, as_of)
    m = _facts(s)["metrics"]
    assert m["findings_new_30d"]["count"] == 4  # the five E findings minus f_res (31d)
    world.set_finding(s.f_res, first_seen_at=as_of - timedelta(days=29))
    assert _facts(s)["metrics"]["findings_new_30d"]["count"] == 5


# ── 2. shape ────────────────────────────────────────────────────────────────

SHAPE_FACTS = {
    "as_of": "2026-10-10T00:00:00+00:00",
    "engagement": {"id": "00000000-0000-0000-0000-000000000001", "posture": "pre_close"},
    "metrics": {
        "findings_open": {"label": "Open findings", "count": 12, "capped": False},
        "findings_open_critical": {"label": "Open critical findings", "count": 3, "capped": False},
        "findings_open_high": {"label": "Open high findings", "count": 4, "capped": False},
        "assets_total": {"label": "Assets", "count": 500, "capped": False},
        "findings_new_30d": {"label": "Findings first seen in the last 30 days", "count": 0,
                             "capped": False, "window_days": 30},
    },
    "top_findings": [
        {"id": "f0", "title": "First finding", "risk_score": 91},
        {"id": "f1", "title": "Second finding", "risk_score": 80},
    ],
}


def _st(text, *sources, section="posture") -> reports.Statement:
    return reports.Statement(section=section, text=text,
                             sources=[reports.Source(path=p, value=v) for p, v in sources])


def _shape(*statements):
    return reports.shape(reports.ReportOut(statements=list(statements)), SHAPE_FACTS)


OPEN_SRC = ("metrics.findings_open.count", "12")


def test_shape_keeps_a_grounded_statement():
    kept, returned, dropped, reasons = _shape(_st("There are 12 open findings.", OPEN_SRC))
    assert (returned, dropped, reasons) == (1, 0, {})
    assert kept[0]["text"] == "There are 12 open findings." and kept[0]["section"] == "posture"
    assert kept[0]["citations"] == [{"path": "metrics.findings_open.count", "value": "12",
                                     "kind": "metric", "ref": "findings_open"}]


def test_citing_a_windowed_metric_grounds_its_window_and_only_its_window():
    new_src = ("metrics.findings_new_30d.count", "0")
    kept, _, dropped, _ = _shape(_st("No findings were first seen in the last 30 days.", new_src))
    assert len(kept) == 1 and dropped == 0
    # the window grounds only through a windowed metric's own citation:
    kept, _, dropped, reasons = _shape(_st("There are 12 open findings from the last 30 days.", OPEN_SRC))
    assert (len(kept), reasons) == (0, {"number_not_in_sources": 1})
    # and only the window: another number beside it still drops
    kept, _, _, reasons = _shape(_st("No findings were first seen in the last 31 days.", new_src))
    assert (len(kept), reasons) == (0, {"number_not_in_sources": 1})


@pytest.mark.parametrize("statement,reason", [
    (_st("There are 12 open findings.", ("metrics.nope.count", "12")), "path_not_found"),
    (_st("There are 13 open findings.", ("metrics.findings_open.count", "13")), "value_not_at_path"),
    (_st("There are 12 open findings.", ("metrics.findings_open", "12")), "path_not_scalar"),
    (_st("There are 12 open findings.", ("metrics..count", "12")), "path_invalid"),
    # 3 is in the facts (critical count) but is not among the CITED values:
    (_st("There are 3 open critical findings.", OPEN_SRC), "number_not_in_sources"),
    (_st("A quarter, 25% of findings, are critical.", OPEN_SRC), "number_not_in_sources"),
    (_st("About 25 percent are critical.", OPEN_SRC), "number_not_in_sources"),
    # even when the percentage's digits happen to be a cited value:
    (_st("That is 12% of findings.", OPEN_SRC), "number_not_in_sources"),
    # a sum has no source path:
    (_st("7 findings are critical or high.", ("metrics.findings_open_critical.count", "3"),
         ("metrics.findings_open_high.count", "4")), "number_not_in_sources"),
    # a number spelled out bypasses the digit check, so it is refused outright:
    (_st("There are twelve open findings.", OPEN_SRC), "number_word"),
    (_st("Half of the 12 open findings are critical.", OPEN_SRC), "number_word"),
    (_st("Dozens of findings are open.", OPEN_SRC), "number_word"),
    (_st("There are findings."), "sources_count"),
    (_st("There are 12 open findings.", *([OPEN_SRC] * 5)), "sources_count"),
    (_st("<b></b>", OPEN_SRC), "text_length"),
    (_st("x" * 401, OPEN_SRC), "text_length"),
])
def test_shape_drops_and_counts_by_reason(statement, reason):
    good = _st("There are 12 open findings.", OPEN_SRC)
    kept, returned, dropped, reasons = _shape(good, statement)
    assert len(kept) == 1 and kept[0]["text"] == good.text  # the good one survived: the drop is per statement
    assert (returned, dropped, reasons) == (2, 1, {reason: 1})


def test_a_sum_that_is_cited_to_a_summing_value_is_still_only_what_is_cited():
    # The two counts together with their own sum is the line the check holds.
    kept, *_ = _shape(_st("There are 3 critical and 4 high findings.",
                          ("metrics.findings_open_critical.count", "3"), ("metrics.findings_open_high.count", "4")))
    assert len(kept) == 1


def test_over_cap_statements_are_dropped_and_counted():
    many = [_st(f"Statement {i} has no numbers.".replace(str(i), "x"), OPEN_SRC) for i in range(reports.MAX_STATEMENTS + 3)]
    kept, returned, dropped, reasons = _shape(*many)
    assert len(kept) == reports.MAX_STATEMENTS
    assert (returned, dropped, reasons) == (reports.MAX_STATEMENTS + 3, 3, {"over_cap": 3})


def test_citation_kind_and_ref_are_derived_from_the_path_not_the_model():
    kept, *_ = _shape(_st(
        "Second finding is high risk in a pre_close engagement with 12 open findings.",
        ("top_findings[1].title", "Second finding"), ("engagement.posture", "pre_close"),
        ("metrics.findings_open.count", "12"), ("top_findings[0].risk_score", "91"),
    ))
    cites = kept[0]["citations"]
    assert [(c["kind"], c["ref"]) for c in cites] == [
        ("finding", "f1"), ("fact", None), ("metric", "findings_open"), ("finding", "f0")]
    assert cites[3]["value"] == "91"


def test_markdown_in_model_text_is_flattened_to_plain_text():
    kept, *_ = _shape(_st("See [this link](http://evil.example) and `code` <b>bold</b> ![img](x) for 12 findings.",
                          OPEN_SRC))
    assert kept[0]["text"] == "See this link and code bold img for 12 findings."


# ── 3-4. generate end to end ────────────────────────────────────────────────

def _data_of(request) -> dict:
    content = json.loads(request.content)["messages"][-1]["content"]
    block = content.split("<data>\n", 1)[1].rsplit("\n</data>", 1)[0]
    return json.loads(block)


def _scripted(statements_for):
    """Transport handler: reads the facts out of the request it received and
    answers with statements built from them."""
    def handler(request):
        facts = _data_of(request)
        return _ok_response(model=NARRATE_PRIMARY, cost=0.0042, content=json.dumps(
            {"statements": statements_for(facts)}))
    return handler


def _good_statements(facts):
    return [
        {"section": "posture", "text": f"There are {facts['metrics']['findings_open']['count']} open findings.",
         "sources": [{"path": "metrics.findings_open.count",
                      "value": str(facts["metrics"]["findings_open"]["count"])}]},
        {"section": "priorities", "text": "The top finding is titled as shown.",
         "sources": [{"path": "top_findings[0].title", "value": facts["top_findings"][0]["title"]}]},
        {"section": "gaps", "text": "This report covers 99 assets.",  # 99 is cited nowhere
         "sources": [{"path": "metrics.assets_total.count", "value": str(facts["metrics"]["assets_total"]["count"])}]},
        {"section": "exposure", "text": "Nothing here.",
         "sources": [{"path": "metrics.nothing.count", "value": "1"}]},
    ]


@pytest.fixture
def writer():
    headers, uid = _make_user(UserRole.REPORT_ADMIN.value)
    yield headers, uid
    _cleanup_user(uid)


def _post(headers, engagement_id):
    return client.post("/api/reports", json={"engagement_id": str(engagement_id)}, headers=headers)


def _row(report_id) -> Report:
    db = SessionLocal()
    try:
        r = db.get(Report, uuid.UUID(report_id))
        db.expunge(r)
        return r
    finally:
        db.close()


def test_generate_end_to_end_with_the_transport_spied(world, llm, writer, permissive):
    headers, _ = writer
    s = build_scenario(world, datetime.now(timezone.utc), "integrated")
    t = llm(_scripted(_good_statements))

    r = _post(headers, s.E)
    assert r.status_code == 202, r.text
    row = _row(r.json()["id"])

    # Exactly one model call, carrying the facts as an untrusted data block.
    assert len(t.requests) == 1
    body = t.bodies()[0]
    assert body["model"] == NARRATE_PRIMARY
    user_msg = body["messages"][-1]["content"]
    assert "<data>" in user_msg and '"findings_open"' in user_msg
    assert "untrusted" in body["messages"][0]["content"]
    db = SessionLocal()
    try:
        name = db.get(Engagement, s.E).name
    finally:
        db.close()
    assert name not in json.dumps(body)  # the model never sees the engagement name

    assert row.status == "done" and row.prompt_version == reports.PROMPT_VERSION
    assert row.model == NARRATE_PRIMARY and row.facts["metrics"]["findings_open"]["count"] == 4
    assert (row.statements_returned, row.statements_dropped) == (4, 2)
    assert row.drop_reasons == {"number_not_in_sources": 1, "path_not_found": 1}
    assert [x["section"] for x in row.payload["statements"]] == ["posture", "priorities"]
    assert row.payload["statements"][1]["citations"][0]["ref"] == str(s.f_crit)

    # The ledger: non-empty, labelled report:<id>, scoped to the engagement.
    assert row.ledger_ids
    db = SessionLocal()
    try:
        calls = db.query(LlmCall).filter(LlmCall.task == f"report:{row.id}").all()
        assert [c.id for c in calls] == row.ledger_ids
        assert {c.engagement_id for c in calls} == {s.E}
    finally:
        db.close()

    got = client.get(f"/api/reports/{row.id}", headers=headers).json()
    assert got["cost_usd"] == pytest.approx(0.0042) and got["payload"]["statements"]
    # f_med (a top finding) is on a5, which is also linked to a target of F: forced strict.
    assert got["forced_strict"] is True and got["drop_reasons"] == row.drop_reasons


def test_forced_strict_only_when_a_top_finding_asset_spans_engagements(world, llm, writer, permissive):
    headers, _ = writer
    t = llm(_scripted(_good_statements))

    # Engagement G: one asset linked only to G's target.
    g = world.engagement("integrated")
    a_solo = world.asset()
    world.target(engagement_id=g, link_asset=a_solo)
    world.finding(a_solo, title="Solo finding")
    r1 = _post(headers, g)
    assert r1.status_code == 202, r1.text
    solo = _row(r1.json()["id"])
    assert solo.status == "done" and solo.facts["top_findings"], "no top finding: the check below would be vacuous"
    assert solo.forced_strict is False

    # Engagement H: its only asset is also linked to a target of another engagement.
    h = world.engagement("integrated")
    a_shared = world.asset()
    world.target(engagement_id=h, link_asset=a_shared)
    world.target(engagement_id=g, link_asset=a_shared)
    world.finding(a_shared, title="Shared finding")
    r2 = _post(headers, h)
    shared = _row(r2.json()["id"])
    assert shared.status == "done" and shared.facts["top_findings"][0]["asset_id"] == str(a_shared)
    assert shared.forced_strict is True

    # And one linked to a target with no engagement at all.
    k = world.engagement("integrated")
    a_null = world.asset()
    world.target(engagement_id=k, link_asset=a_null)
    world.target(engagement_id=None, link_asset=a_null)
    world.finding(a_null, title="Null-engagement finding")
    assert _row(_post(headers, k).json()["id"]).forced_strict is True

    assert len(t.requests) == 3
    # The effective data policy on the ledger shows the flag reached the connector.
    db = SessionLocal()
    try:
        policy = {c.engagement_id: c.data_policy for c in db.query(LlmCall).filter(
            LlmCall.task.in_([f"report:{solo.id}", f"report:{shared.id}"])).all()}
    finally:
        db.close()
    assert policy[shared.engagement_id] == "strict"
    assert policy[solo.engagement_id] != "strict"


def test_llm_failure_marks_failed_but_keeps_the_facts(world, llm, writer):
    headers, _ = writer
    s = build_scenario(world, datetime.now(timezone.utc))
    t = llm(lambda request: _ok_response(model=NARRATE_PRIMARY, content="not json"))
    r = _post(headers, s.E)
    assert r.status_code == 202
    assert t.requests  # the ladder really ran
    row = _row(r.json()["id"])
    assert row.status == "failed" and row.error == "no model returned a usable report"
    assert row.payload is None and row.finished_at is not None
    assert row.facts["metrics"]["findings_open"]["count"] == 4  # the numbers stand
    assert row.ledger_ids


def test_zero_surviving_statements_is_still_done(world, llm, writer):
    headers, _ = writer
    s = build_scenario(world, datetime.now(timezone.utc))
    llm(_scripted(lambda facts: [{"section": "posture", "text": "Made up 77.",
                                  "sources": [{"path": "metrics.findings_open.count", "value": "4"}]}]))
    row = _row(_post(headers, s.E).json()["id"])
    assert row.status == "done" and row.payload == {"statements": []}
    assert (row.statements_returned, row.statements_dropped) == (1, 1)


# ── 5. API ──────────────────────────────────────────────────────────────────

@pytest.fixture
def viewer():
    headers, uid = _make_user(UserRole.VIEWER.value)
    yield headers
    _cleanup_user(uid)


@pytest.fixture
def admin():
    headers, uid = _make_user(UserRole.ADMIN.value)
    yield headers
    _cleanup_user(uid)


def _insert(engagement_id, *, status="done", created_at=None, facts=None, payload=None, dropped=0) -> uuid.UUID:
    db = SessionLocal()
    try:
        r = Report(engagement_id=engagement_id, kind="exec_summary", status=status,
                   as_of=datetime.now(timezone.utc), facts=facts, payload=payload, statements_dropped=dropped,
                   **({"created_at": created_at} if created_at else {}))
        db.add(r)
        db.commit()
        return r.id
    finally:
        db.close()


def test_viewer_cannot_create_or_delete_and_no_call_is_made(world, llm, viewer):
    e = world.engagement("pre_close")
    rid = _insert(e)
    t = llm(_scripted(_good_statements))
    assert client.post("/api/reports", json={"engagement_id": str(e)}, headers=viewer).status_code == 403
    assert client.delete(f"/api/reports/{rid}", headers=viewer).status_code == 403
    assert t.requests == []
    assert client.get(f"/api/reports/{rid}", headers=viewer).status_code == 200  # reading is allowed
    assert [x["id"] for x in client.get(f"/api/reports?engagement_id={e}", headers=viewer).json()] == [str(rid)]


def test_report_admin_and_admin_can_create_and_delete(world, llm, writer, admin):
    s = build_scenario(world, datetime.now(timezone.utc))
    llm(_scripted(_good_statements))
    ra_headers, _ = writer
    first = _post(ra_headers, s.E)
    assert first.status_code == 202
    second = _post(admin, s.E)
    assert second.status_code == 202  # the first is finished, so not "running"
    for headers, rid in ((ra_headers, first.json()["id"]), (admin, second.json()["id"])):
        assert client.delete(f"/api/reports/{rid}", headers=headers).status_code == 204
        assert client.get(f"/api/reports/{rid}", headers=headers).status_code == 404


def test_409_when_one_is_running_and_no_call_is_made(world, llm, writer):
    headers, _ = writer
    e = world.engagement("pre_close")
    _insert(e, status="running")
    t = llm(_scripted(_good_statements))
    r = _post(headers, e)
    assert r.status_code == 409 and "already" in r.json()["detail"]
    assert t.requests == []


def test_429_at_the_daily_cap(world, llm, writer, monkeypatch):
    headers, _ = writer
    s = build_scenario(world, datetime.now(timezone.utc))
    t = llm(_scripted(_good_statements))
    db = SessionLocal()
    try:
        today = db.execute(select(func.count()).select_from(Report).where(
            Report.created_at >= datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        )).scalar_one()
    finally:
        db.close()
    monkeypatch.setattr(reports, "DAILY_CAP", today + 1)
    assert _post(headers, s.E).status_code == 202      # the count path is reached and passes
    r = _post(headers, s.E)                            # ... and now it does not
    assert r.status_code == 429 and "limit" in r.json()["detail"]
    assert len(t.requests) == 1


def test_404_for_an_unknown_engagement(llm, writer):
    headers, _ = writer
    t = llm(_scripted(_good_statements))
    assert _post(headers, uuid.uuid4()).status_code == 404
    assert client.get(f"/api/reports?engagement_id={uuid.uuid4()}", headers=headers).status_code == 404
    assert client.get(f"/api/reports/{uuid.uuid4()}", headers=headers).status_code == 404
    assert t.requests == []


def test_503_when_the_connector_is_not_configured(world, writer):
    headers, _ = writer
    e = world.engagement("pre_close")
    from app.tests.test_llm_connector import _configure_openrouter, _restore_openrouter
    db = SessionLocal()
    try:
        snap = _configure_openrouter(db, enabled=False)
    finally:
        db.close()
    try:
        assert _post(headers, e).status_code == 503
    finally:
        _restore_openrouter(snap)


def test_markdown_endpoint_is_an_attachment_named_by_id_only(world, writer):
    headers, _ = writer
    s = build_scenario(world, datetime.now(timezone.utc))
    facts = _facts(s)
    done = _insert(s.E, facts=facts, payload={"statements": []})
    queued = _insert(world.engagement("pre_close"), status="queued")
    r = client.get(f"/api/reports/{done}/markdown", headers=headers)
    assert r.status_code == 200
    assert r.headers["content-type"] == "text/markdown; charset=utf-8"
    assert r.headers["content-disposition"] == f'attachment; filename="report-{done}.md"'
    db = SessionLocal()
    try:
        name = db.get(Engagement, s.E).name
    finally:
        db.close()
    assert name not in r.headers["content-disposition"]
    assert r.text.startswith("# Executive summary") and "Open findings" in r.text
    assert client.get(f"/api/reports/{queued}/markdown", headers=headers).status_code == 409


# ── 6. markdown rendering ───────────────────────────────────────────────────

def _render_fixture(capped=False) -> str:
    evil = "[x](http://evil.example) ![i](x) <script>alert(1)</script> `code` | pipe"
    facts = {
        "as_of": "2026-10-10T00:00:00+00:00", "engagement": {"id": "e", "posture": "pre_close"},
        "metrics": {"findings_open": {"label": "Open findings", "count": 10000 if capped else 12, "capped": capped}},
        "top_findings": [{"id": "f0", "title": evil, "severity": "critical", "risk_score": 91,
                          "asset_value": "www.example.com"}],
    }
    payload = {"statements": [{
        "section": "posture", "text": evil,
        "citations": [{"path": "metrics.findings_open.count", "value": "12", "kind": "metric", "ref": "findings_open"},
                      {"path": "top_findings[0].title", "value": evil, "kind": "finding", "ref": "f0"},
                      {"path": "engagement.posture", "value": "pre_close", "kind": "fact", "ref": None}],
    }]}
    r = Report(id=uuid.uuid4(), engagement_id=uuid.uuid4(), kind="exec_summary", status="done",
               as_of=datetime(2026, 10, 10, tzinfo=timezone.utc), facts=facts, payload=payload,
               statements_returned=3, statements_dropped=2)
    return reports.render_markdown(r, f"Eng {evil}")


def test_render_markdown_escapes_model_text_data_strings_and_the_name():
    md = _render_fixture()
    assert "](" not in md              # no link or image can form
    assert "![" not in md
    assert "<script>" not in md and "<" not in md.replace("\\<", "")
    assert "`" not in md.replace("\\`", "")
    assert "\\[x\\]\\(http://evil.example\\)" in md
    assert md.startswith("# Executive summary — Eng \\[x\\]")
    # footnotes and the structure around the text
    assert "\\[1\\] metric: Open findings = 12" in md
    assert "\\[2\\] finding: " in md and "(/findings/f0)" in md
    assert "\\[3\\] fact: engagement\\.posture".replace("\\.", ".") in md
    assert "2 statements were dropped because they could not be tied to the data." in md
    assert "Posture" in md and "Highest-risk open findings" in md


def test_render_markdown_shows_a_capped_count_as_10000_plus():
    md = _render_fixture(capped=True)
    assert "| Open findings | 10,000\\+ |".replace("\\+", "+") in md
    assert "metric: Open findings = 10,000+" in md


def test_render_markdown_follows_metric_order_and_says_1_statement():
    facts = {
        "as_of": "2026-10-10T00:00:00+00:00", "engagement": {"id": "e", "posture": "integrated"},
        "metrics": {"b_metric": {"label": "Second", "count": 2, "capped": False},
                    "a_metric": {"label": "First", "count": 1, "capped": False}},
        "metric_order": ["a_metric", "b_metric"],
        "top_findings": [],
    }
    r = Report(id=uuid.uuid4(), engagement_id=uuid.uuid4(), kind="exec_summary", status="done",
               as_of=datetime(2026, 10, 10, tzinfo=timezone.utc), facts=facts, payload={"statements": []},
               statements_returned=1, statements_dropped=1)
    md = reports.render_markdown(r, "Eng")
    assert md.index("| First | 1 |") < md.index("| Second | 2 |")
    assert "1 statement was dropped because it could not be tied to the data." in md


def test_render_markdown_is_deterministic():
    a, b = _render_fixture(), _render_fixture()
    # report ids differ between the two fixtures but are not rendered
    assert a == b


# ── 7. purge ────────────────────────────────────────────────────────────────

def test_purge_deletes_only_rows_older_than_retention(world):
    e = world.engagement("pre_close")
    now = datetime.now(timezone.utc)
    old = _insert(e, created_at=now - timedelta(days=reports.RETENTION_DAYS + 1))
    new = _insert(e, created_at=now - timedelta(days=reports.RETENTION_DAYS - 1))
    db = SessionLocal()
    try:
        deleted = reports.purge_reports(db)
        assert deleted >= 1
        assert db.get(Report, old) is None
        assert db.get(Report, new) is not None
        assert reports.purge_reports(db) == 0  # idempotent: nothing else is old
    finally:
        db.close()


# ── 8. the read_scope hook ──────────────────────────────────────────────────

def test_endpoints_call_engagement_visible(world, writer, monkeypatch):
    headers, _ = writer
    e = world.engagement("pre_close")
    rid = _insert(e, facts={"as_of": "x", "metrics": {}, "top_findings": []}, payload={"statements": []})
    urls = [f"/api/reports?engagement_id={e}", f"/api/reports/{rid}", f"/api/reports/{rid}/markdown"]
    for u in urls:                                    # reached: all three answer while visible
        assert client.get(u, headers=headers).status_code == 200, u
    seen = []
    monkeypatch.setattr(read_scope, "engagement_visible", lambda user, eid: seen.append(eid) or False)
    for u in urls:
        assert client.get(u, headers=headers).status_code == 404, u
    assert client.delete(f"/api/reports/{rid}", headers=headers).status_code == 404
    assert len(seen) == 4 and set(seen) == {e}


def test_engagement_visible_grants_everything_today():
    assert read_scope.engagement_visible(_viewer(), uuid.uuid4()) is True


# ── recorded live answer ────────────────────────────────────────────────────

_RECORDED = Path(__file__).parent / "fixtures" / "report_recorded_2026-10-10.json"


def _recorded() -> dict:
    return json.loads(_RECORDED.read_text(encoding="utf-8"))


def test_recorded_live_answer_shapes_as_it_did_live():
    rec = _recorded()
    kept, returned, dropped, reasons = reports.shape(reports.ReportOut.model_validate(rec["answer"]), rec["facts"])
    assert {"returned": returned, "kept": len(kept), "dropped": dropped, "reasons": reasons} == rec["expected"]
    assert returned > 0 and len(kept) > 0  # the replay reached the grounding checks with real output


@pytest.mark.parametrize("metric,count", [("assets_total", 259), ("findings_open", 5)])
def test_recorded_answer_drops_a_statement_whose_source_changed(metric, count):
    rec = _recorded()
    before, *_ = reports.shape(reports.ReportOut.model_validate(rec["answer"]), rec["facts"])
    cites = [s for s in before if any(c["path"] == f"metrics.{metric}.count" for c in s["citations"])]
    assert cites  # the precondition: a kept statement cites this metric
    rec["facts"]["metrics"][metric]["count"] = count
    after, _, _, reasons = reports.shape(reports.ReportOut.model_validate(rec["answer"]), rec["facts"])
    assert len(after) == len(before) - len(cites)
    assert reasons == {"value_not_at_path": len(cites)}
