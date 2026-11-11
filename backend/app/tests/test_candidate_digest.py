"""Coverage for planning#319: the organization discovery digest
(`app.services.candidate_digest`, `notification_scope`, migration
0099, the dispatcher's kind filter, the rule/digest API).

Synthetic values only (`.example.com`, `Example Holdings ...`). The connector
is spied at its `send` (the transport double from `test_alert_events`). A test
that asserts something did NOT happen also asserts the path was reached (a
sibling eligible candidate IS listed, or the finding rule DID get a dispatch).

Run:  backend/scripts/test.sh app/tests/test_candidate_digest.py
"""

import json
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError

from app.main import app
from app.models.alert_event import AlertDispatch
from app.models.digest import Digest, DigestCandidate
from app.models.engagement import Engagement
from app.models.llm_call import LlmCall
from app.models.notification_rule import NotificationRule
from app.models.scope_candidate import ScopeCandidate, ScopeSignal
from app.models.user import UserRole
from app.services import candidate_digest, digest, notification_dispatcher
from app.services import llm_connector as llmc
from app.services import notification_scope
from app.services.org_discovery import candidates as org_candidates
from app.services.org_discovery.tiers import SIGNALS
from app.services.score_history import Promotion
from app.tests._org_world import World
from app.tests.test_alert_events import _Conn, _use_connectors
from app.tests.test_digests import _asset, _dispatch, _digests, _finding, _rule, denv  # noqa: F401
from app.tests.test_digests import _data_block, _narrative_response, llm
from app.tests.test_edgar_ingest_api import _cleanup_user, _make_user

client = TestClient(app)


# ── helpers ──────────────────────────────────────────────────────────────────

@pytest.fixture
def oenv(denv):  # noqa: F811
    """`denv` (session, suffix, T1/T2, digest hour, cleanup) plus an org world."""
    w = World()
    denv.w = w
    try:
        yield denv
    finally:
        # Digests and rules first (the claims cascade with the candidates).
        denv.db.rollback()
        like = f"%{denv.suffix}%"
        # The AI ledger rows go too: `denv` finds them through the digests deleted here.
        ids = [r[0] for r in denv.db.query(Digest.id).filter(Digest.rule_name.like(like)).all()]
        if ids:
            denv.db.query(LlmCall).filter(LlmCall.task.in_([f"{digest.TASK_PREFIX}:{i}" for i in ids])).delete(
                synchronize_session=False)
        denv.db.query(Digest).filter(Digest.rule_name.like(like)).delete(synchronize_session=False)
        denv.db.query(NotificationRule).filter(NotificationRule.name.like(like)).delete(synchronize_session=False)
        denv.db.commit()
        w.close()


def _org_rule(e, name="org", *, recipients=("alerts@example.com",), enabled=True):
    rule = NotificationRule(
        id=uuid.uuid4(), name=f"{name}-{e.suffix}", enabled=enabled, severity_threshold="high",
        categories=[], recipients=list(recipients), mode="digest", kind="org_discovery",
    )
    e.db.add(rule)
    e.db.commit()
    return rule


def _posture(e, eng, posture):
    """Set an engagement's posture directly, keeping the authorisation CHECK happy."""
    widened = posture in ("day_0", "integrated")
    e.db.query(Engagement).filter(Engagement.id == eng.id).update({
        "posture": posture,
        "authorised_at": datetime.now(timezone.utc) if widened else None,
        "authorisation_reference": "org319 ref" if widened else None,
        "authorised_by_id": None,
    })
    e.db.commit()


def _decide(e, cand, status, **cols):
    """Move a candidate to `claimed` / `rejected`, satisfying the decision CHECKs
    (a stored affiliate and an engagement destination exist only when claimed)."""
    vals = {"status": status, "decided_at": datetime.now(timezone.utc)}
    if status == "rejected":
        vals["rejected_strong_types"] = []
        vals["rejection_reason"] = "org319 test"
    else:
        vals["accepted_into"] = "estate"
        vals["affiliated_entity_id"] = cand.root_entity_id
    vals.update(cols)
    e.db.query(ScopeCandidate).filter(ScopeCandidate.id == cand.id).update(vals)
    e.db.commit()


def _live_deal(e, posture="day_0"):
    ent, eng = e.w.deal()
    _posture(e, eng, posture)
    return ent, eng


def _set_created(e, cand, when):
    e.db.query(ScopeCandidate).filter(ScopeCandidate.id == cand.id).update({"created_at": when})
    e.db.commit()


def _claim(e, rule, now=None):
    return digest.claim(e.db, rule.id, now or e.t1)


def _listed(body):
    return {c["value"] for o in body["organizations"] for c in o["candidates"]}


def _claim_rows(e, rule):
    e.db.expire_all()
    return {r.candidate_id for r in e.db.query(DigestCandidate).filter(DigestCandidate.rule_id == rule.id)}


def _send_texts(conn, e):
    return [m["text"] for m in conn.sent if e.suffix in m["subject"]]


# ── 1. the predicate ─────────────────────────────────────────────────────────

def test_eligible_roots(oenv):
    e, w = oenv, oenv.w
    ours = w.ours()
    day0, _ = _live_deal(e, "day_0")
    integ, _ = _live_deal(e, "integrated")
    cands = [w.candidate(r) for r in (ours, day0, integ)]
    assert notification_scope.eligible_candidate_ids(e.db, [c.id for c in cands]) == {c.id for c in cands}
    assert notification_scope.eligible_candidate_ids(e.db, []) == set()


def _x_pre_close(e):
    ent, _eng = e.w.deal()  # a live deal engagement in pre_close
    return e.w.candidate(ent)


def _x_abandoned(e):
    ent, eng = e.w.deal()
    _posture(e, eng, "abandoned")
    return e.w.candidate(ent)


def _x_integrated_and_abandoned(e):
    ent, eng = _live_deal(e, "integrated")
    e.w.engagement("abandoned", subject=ent)
    return e.w.candidate(ent)


def _x_no_engagement(e):
    ent = e.w.entity()
    e.db.query(type(ent)).filter(type(ent).id == ent.id).update({"relationship": "ma_target"})
    e.db.commit()
    return e.w.candidate(ent)


def _x_ours_also_pre_close_subject(e):
    ours = e.w.ours()
    e.w.engagement("pre_close", subject=ours)
    return e.w.candidate(ours)


def _x_stored_affiliate_pre_close(e):
    ours = e.w.ours()
    aff = e.w.child_of(ours)
    cand = e.w.candidate(ours)
    e.w.engagement("pre_close", subject=aff)
    _decide(e, cand, "claimed", affiliated_entity_id=aff.id)  # a stored affiliate exists only when claimed
    return cand


def _x_default_affiliate_pre_close(e):
    ours = e.w.ours()
    aff = e.w.child_of(ours)
    cand = e.w.candidate(ours, via=aff)
    e.w.engagement("pre_close", subject=aff)  # after the candidate: a deal child leaves the root's tree
    # signal via_entity_id, no stored affiliate
    assert cand.affiliated_entity_id is None
    return cand


def _x_pre_close_root_via_child(e):
    """Only the ROOT is a deal subject; the affiliate (a child) is not, so the
    root check alone must exclude it."""
    ent, _eng = e.w.deal()
    child = e.w.child_of(ent)
    return e.w.candidate(ent, via=child)


def _x_own_engagement_pre_close(e):
    ours = e.w.ours()
    eng = e.w.engagement("pre_close")
    cand = e.w.candidate(ours)
    _decide(e, cand, "claimed", accepted_into="engagement", engagement_id=eng.id)
    return cand


_EXCLUDED = {
    "ma_target_pre_close": _x_pre_close,
    "ma_target_abandoned": _x_abandoned,
    "integrated_plus_abandoned": _x_integrated_and_abandoned,
    "ma_target_no_engagement": _x_no_engagement,
    "ours_also_pre_close_subject": _x_ours_also_pre_close_subject,
    "stored_affiliate_pre_close": _x_stored_affiliate_pre_close,
    "default_affiliate_pre_close": _x_default_affiliate_pre_close,
    "own_engagement_pre_close": _x_own_engagement_pre_close,
    "pre_close_root_via_child": _x_pre_close_root_via_child,
}


@pytest.mark.parametrize("case", sorted(_EXCLUDED))
def test_excluded_candidates(oenv, case):
    e = oenv
    good = e.w.candidate(e.w.ours())
    bad = _EXCLUDED[case](e)
    got = notification_scope.eligible_candidate_ids(e.db, [good.id, bad.id])
    assert good.id in got, "precondition: the eligible sibling is returned"
    assert bad.id not in got


# ── 2. the finding entrypoints never load an org rule ────────────────────────

def _dispatches_for(e, rule):
    e.db.expire_all()
    return e.db.query(AlertDispatch).filter(AlertDispatch.rule_id == rule.id).all()


def test_dispatch_skips_org_discovery_rules(oenv, monkeypatch):
    e = oenv
    _use_connectors(monkeypatch, [("c1", _Conn("ok"))])
    frule = _rule(e, "frule", "digest")
    orule = _org_rule(e)
    f = _finding(e, _asset(e, 10), "fp-hi", severity="high", cve_id="CVE-2024-90101")

    notification_dispatcher._dispatch(e.db, [f.id])

    assert len(_dispatches_for(e, frule)) == 1, "precondition: the finding rule was dispatched"
    assert _dispatches_for(e, orule) == []


def test_dispatch_promotions_skips_org_discovery_rules(oenv, monkeypatch):
    e = oenv
    _use_connectors(monkeypatch, [("c1", _Conn("ok"))])
    frule = _rule(e, "frule", "digest")
    orule = _org_rule(e)
    f = _finding(e, _asset(e, 10), "fp-hi", severity="high", cve_id="CVE-2024-90101")

    promo = Promotion(
        finding_canonical_id=f.id, asset_canonical_id=f.asset_canonical_id, previous_band="medium",
        new_band="high", previous_score=50, new_score=80, velocity_started=False,
    )
    notification_dispatcher._dispatch_promotions(e.db, [promo])

    assert len(_dispatches_for(e, frule)) == 1, "precondition: the finding rule was dispatched"
    assert _dispatches_for(e, orule) == []


# ── 3. the claim ─────────────────────────────────────────────────────────────

def test_claim_lists_grouped_ordered_and_writes_claim_rows(oenv):
    e, w = oenv, oenv.w
    rule = _org_rule(e)
    org_a = w.entity(legal_name=f"Example Alpha {e.suffix}")
    org_b = w.entity(legal_name=f"Example Bravo {e.suffix}")
    w.ours(org_a)
    w.ours(org_b)
    cb = w.candidate(org_b, value=f"b1-{e.suffix}.example.com")
    ca2 = w.candidate(org_a, value=f"a2-{e.suffix}.example.com")
    ca1 = w.candidate(org_a, value=f"a1-{e.suffix}.example.com")
    digest.app_settings.set_value(e.db, digest.BASE_URL_KEY, "https://app.example.com")

    dg = _claim(e, rule)

    body = dg.body
    assert dg.kind == "org_discovery" and dg.outcome == "pending" and dg.narrative_status is None
    mine = [o for o in body["organizations"] if o["id"] in (str(org_a.id), str(org_b.id))]
    assert [o["name"] for o in mine] == [org_a.legal_name, org_b.legal_name]
    assert [c["value"] for c in mine[0]["candidates"]] == [ca1.value, ca2.value]
    assert mine[0]["candidate_count"] == 2 and mine[1]["candidate_count"] == 1
    assert mine[0]["url"] == f"https://app.example.com/organizations/{org_a.id}?tab=domains&seg=candidates"
    assert mine[0]["candidates"][0]["kind"] == "domain"
    assert body["totals"]["candidates"] >= 3 and body["totals"]["organizations"] >= 2
    assert dg.event_count == body["totals"]["candidates"] and dg.finding_count == 0
    assert _claim_rows(e, rule) >= {ca1.id, ca2.id, cb.id}
    assert len(_claim_rows(e, rule)) == body["totals"]["candidates"]
    assert body["rule"]["id"] == str(rule.id)


def test_second_claim_does_not_relist_and_grace_window_applies(oenv):
    e, w = oenv, oenv.w
    rule = _org_rule(e)
    ours = w.ours()
    first = w.candidate(ours)
    dg1 = _claim(e, rule)
    assert first.value in _listed(dg1.body), "precondition: the first claim listed it"

    late = w.candidate(ours)   # committed after the cut-off, stamped before it
    old = w.candidate(ours)    # older than the grace window
    _set_created(e, late, e.t1 - timedelta(minutes=30))
    _set_created(e, old, e.t1 - timedelta(hours=2))

    dg2 = _claim(e, rule, e.t2)

    assert dg2 is not None and dg2.period_start == dg1.period_end
    listed = _listed(dg2.body)
    assert late.value in listed, "inside floor - GRACE and unclaimed: picked up"
    assert first.value not in listed, "already claimed: not relisted"
    assert old.value not in listed, "older than floor - GRACE: not claimed"
    assert old.id not in _claim_rows(e, rule)


def test_claimed_and_rejected_candidates_are_not_listed_or_claimed(oenv):
    e, w = oenv, oenv.w
    rule = _org_rule(e)
    ours = w.ours()
    open_c, rejected, claimed = w.candidate(ours), w.candidate(ours), w.candidate(ours)
    _decide(e, rejected, "rejected")
    _decide(e, claimed, "claimed")

    dg = _claim(e, rule)

    assert open_c.value in _listed(dg.body), "precondition: the open sibling is listed"
    assert rejected.value not in _listed(dg.body) and claimed.value not in _listed(dg.body)
    assert _claim_rows(e, rule) == {open_c.id}


def test_excluded_org_is_not_named_counted_or_claimed(oenv):
    e, w = oenv, oenv.w
    rule = _org_rule(e)
    ours = w.ours()
    good = w.candidate(ours)
    deal, _eng = w.deal()  # pre_close
    hidden = w.candidate(deal)

    dg = _claim(e, rule)

    assert good.value in _listed(dg.body), "precondition: the eligible org is listed"
    assert deal.legal_name not in str(dg.body) and hidden.value not in str(dg.body)
    assert str(deal.id) not in str(dg.body)
    assert dg.body["totals"]["candidates"] == 1 and dg.body["totals"]["organizations"] == 1
    assert hidden.id not in _claim_rows(e, rule) and good.id in _claim_rows(e, rule)


def test_empty_period_is_recorded_and_sends_nothing(oenv, monkeypatch):
    e = oenv
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    rule = _org_rule(e)

    digest.run_due(e.t1)

    (dg,) = _digests(e, rule)
    assert dg.outcome == "empty" and dg.kind == "org_discovery" and dg.event_count == 0
    assert dg.sent_at is None and dg.body["organizations"] == []
    assert _send_texts(conn, e) == [] and [m for m in conn.sent if e.suffix in m["subject"]] == []


def test_two_org_rules_each_list_the_same_candidate_once(oenv):
    e, w = oenv, oenv.w
    r1, r2 = _org_rule(e, "one"), _org_rule(e, "two")
    cand = w.candidate(w.ours())

    d1, d2 = _claim(e, r1), _claim(e, r2)

    assert cand.value in _listed(d1.body) and cand.value in _listed(d2.body)
    assert cand.id in _claim_rows(e, r1) and cand.id in _claim_rows(e, r2)
    e.db.expire_all()
    for r in (r1, r2):
        assert e.db.query(DigestCandidate).filter(
            DigestCandidate.rule_id == r.id, DigestCandidate.candidate_id == cand.id).count() == 1


def test_list_cap_keeps_the_count_exact(oenv, monkeypatch):
    e, w = oenv, oenv.w
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    rule = _org_rule(e)
    org = w.entity(legal_name=f"Example Capped {e.suffix}")
    w.ours(org)
    for i in range(52):
        w.candidate(org, value=f"c{i:02d}-{e.suffix}.example.com")

    dg = _claim(e, rule)
    mine = next(o for o in dg.body["organizations"] if o["id"] == str(org.id))
    assert candidate_digest.LIST_CAP == 50
    assert len(mine["candidates"]) == 50 and mine["candidate_count"] == 52
    assert len(_claim_rows(e, rule)) == 52

    digest.send(e.db, dg)

    (text,) = _send_texts(conn, e) or [None]
    assert text is not None, "precondition: the send was reached"
    assert "52 new candidates" in text and "and 2 more" in text


# ── 4. the send re-filters ───────────────────────────────────────────────────

def test_send_refilters_when_the_only_org_goes_back_to_pre_close(oenv, monkeypatch):
    e, w = oenv, oenv.w
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    rule = _org_rule(e)
    deal, eng = _live_deal(e, "day_0")
    w.candidate(deal)
    dg = _claim(e, rule)
    assert dg.outcome == "pending" and dg.body["totals"]["candidates"] == 1, "precondition: a pending digest"

    _posture(e, eng, "pre_close")
    digest.send(e.db, dg)

    e.db.expire_all()
    row = e.db.get(Digest, dg.id)
    assert conn.sent == []
    assert row.outcome == "empty" and row.deliveries == [] and row.sent_at is None
    assert deal.legal_name in str(row.body), "the stored body is untouched"


def test_send_refilters_but_still_sends_the_remaining_org(oenv, monkeypatch):
    e, w = oenv, oenv.w
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    rule = _org_rule(e)
    ours = w.entity(legal_name=f"Example Ours {e.suffix}")
    w.ours(ours)
    deal, eng = _live_deal(e, "day_0")
    keep = w.candidate(ours)
    hide = w.candidate(deal)
    dg = _claim(e, rule)
    assert {keep.value, hide.value} <= _listed(dg.body), "precondition: both were listed at claim"

    _posture(e, eng, "pre_close")
    digest.send(e.db, dg)

    assert len(conn.sent) == 1
    text = conn.sent[0]["text"]
    assert ours.legal_name in text and keep.value in text
    assert deal.legal_name not in text and hide.value not in text
    assert "1 new organization discovery candidate to review" in conn.sent[0]["subject"]
    e.db.expire_all()
    assert e.db.get(Digest, dg.id).outcome == "sent"


# ── 5. retry_stale ───────────────────────────────────────────────────────────

def test_retry_stale_resends_an_org_digest_through_the_filter(oenv, monkeypatch):
    e, w = oenv, oenv.w
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    rule = _org_rule(e)
    ours = w.entity(legal_name=f"Example Ours {e.suffix}")
    w.ours(ours)
    deal, eng = _live_deal(e, "day_0")
    keep, hide = w.candidate(ours), w.candidate(deal)
    dg = _claim(e, rule)  # left pending: a crash between claim and send
    assert dg.outcome == "pending" and hide.value in _listed(dg.body)
    _posture(e, eng, "abandoned")

    digest.retry_stale(e.db, datetime.now(timezone.utc) + timedelta(hours=1))

    mine = [m for m in conn.sent if e.suffix in m["subject"]]
    assert len(mine) == 1, "precondition: the stale digest was resent"
    assert keep.value in mine[0]["text"]
    assert hide.value not in mine[0]["text"] and deal.legal_name not in mine[0]["text"]


# ── 6. run_due narrates an org digest but never embeds cluster write-ups ────

def test_run_due_narrates_an_org_digest_without_cluster_embedding(oenv, monkeypatch):
    e, w = oenv, oenv.w
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    orule = _org_rule(e)
    frule = _rule(e, "frule", "digest")
    cand = w.candidate(w.ours())
    f = _finding(e, _asset(e, 10), "fp-hi", severity="high", cve_id="CVE-2024-90101")
    _dispatch(e, frule, [(f, "high", None)])

    narrated, embedded, llm_calls = [], [], []
    real_narrate, real_embed = digest.narrate, digest._embed_cluster_writeups

    def _narrate(db, dg):
        narrated.append(dg.kind)
        return real_narrate(db, dg)

    def _embed(db, dg):
        embedded.append(dg.kind)
        return real_embed(db, dg)

    def _configured(db):
        llm_calls.append("is_configured")
        return False

    monkeypatch.setattr(digest, "narrate", _narrate)
    monkeypatch.setattr(digest, "_embed_cluster_writeups", _embed)
    monkeypatch.setattr(llmc, "is_configured", _configured)

    digest.run_due(e.t1)

    (odg,) = _digests(e, orule)
    (fdg,) = _digests(e, frule)
    assert odg.outcome == "sent" and fdg.outcome == "sent", "precondition: both digests went through run_due"
    org_msgs = [m for m in conn.sent if e.suffix in m["subject"] and "org" in m["subject"].lower()]
    assert cand.value in org_msgs[0]["text"]
    assert sorted(narrated) == ["finding", "org_discovery"] and embedded == ["finding"]
    assert llm_calls == ["is_configured", "is_configured"], "the LLM path was reached for both digests"
    assert odg.narrative_status == "skipped" and odg.narrative_reason == "AI is not configured"
    assert odg.narrative is None and odg.model is None
    assert "AI summary unavailable: AI is not configured" in org_msgs[0]["text"]


# ── 7. the API ───────────────────────────────────────────────────────────────

@pytest.fixture
def admin():
    headers, uid = _make_user(UserRole.ADMIN.value)
    try:
        yield headers
    finally:
        _cleanup_user(uid)


def _post_rule(h, e, **kw):
    body = {"name": f"api-{e.suffix}-{uuid.uuid4().hex[:4]}", "recipients": ["a@example.com"], **kw}
    return client.post("/api/notifications/rules", headers=h, json=body)


def test_api_create_org_rule_defaults_to_digest(oenv, admin):
    r = _post_rule(admin, oenv, kind="Org_Discovery")
    assert r.status_code == 201, r.text
    assert r.json()["kind"] == "org_discovery" and r.json()["mode"] == "digest"
    r = _post_rule(admin, oenv, kind="org_discovery", mode="digest")
    assert r.status_code == 201 and r.json()["mode"] == "digest"
    f = _post_rule(admin, oenv)
    assert f.status_code == 201 and f.json()["kind"] == "finding" and f.json()["mode"] == "immediate"


def test_api_org_rule_shape_is_validated(oenv, admin):
    ok = _post_rule(admin, oenv, kind="org_discovery")
    assert ok.status_code == 201, "precondition: the same rule without the bad field is accepted"
    for mode in ("immediate", "both"):
        r = _post_rule(admin, oenv, kind="org_discovery", mode=mode)
        assert r.status_code == 422 and "daily digest only" in r.text
    r = _post_rule(admin, oenv, kind="org_discovery", categories=["x"])
    assert r.status_code == 422 and "has no categories" in r.text
    assert _post_rule(admin, oenv, kind="nonsense").status_code == 422


def test_api_patch_rules(oenv, admin):
    h = admin
    org = _post_rule(h, oenv, kind="org_discovery").json()["id"]
    fin = _post_rule(h, oenv).json()["id"]
    url = "/api/notifications/rules/"

    r = client.patch(url + org, headers=h, json={"kind": "finding"})
    assert r.status_code == 422 and "can't be changed" in r.json()["detail"]
    assert client.patch(url + fin, headers=h, json={"kind": "org_discovery"}).status_code == 422
    assert client.patch(url + org, headers=h, json={"kind": "org_discovery", "name": f"n-{oenv.suffix}"}).status_code == 200
    for mode in ("both", "immediate"):
        r = client.patch(url + org, headers=h, json={"mode": mode})
        assert r.status_code == 422 and "daily digest only" in r.json()["detail"]
    r = client.patch(url + org, headers=h, json={"categories": ["x"]})
    assert r.status_code == 422 and "no categories" in r.json()["detail"]
    r = client.patch(url + org, headers=h, json={"mode": "digest", "categories": []})
    assert r.status_code == 200 and r.json()["kind"] == "org_discovery"
    # finding rules are unchanged
    r = client.patch(url + fin, headers=h, json={"mode": "both", "categories": ["x"]})
    assert r.status_code == 200 and r.json()["mode"] == "both" and r.json()["categories"] == ["x"]


def test_api_digest_reads_refilter_and_never_write_back(oenv, admin):
    e, w = oenv, oenv.w
    rule = _org_rule(e)
    ours = w.entity(legal_name=f"Example Ours {e.suffix}")
    w.ours(ours)
    deal, eng = _live_deal(e, "day_0")
    keep, hide = w.candidate(ours), w.candidate(deal)
    dg = _claim(e, rule)
    url = f"/api/notifications/digests/{dg.id}"

    before = client.get(url, headers=admin).json()
    assert before["kind"] == "org_discovery" and before["event_count"] == 2
    assert {o["name"] for o in before["body"]["organizations"]} == {ours.legal_name, deal.legal_name}

    _posture(e, eng, "pre_close")

    after = client.get(url, headers=admin).json()
    assert [o["name"] for o in after["body"]["organizations"]] == [ours.legal_name]
    assert after["body"]["totals"] == {"candidates": 1, "organizations": 1}
    assert after["event_count"] == 1
    assert deal.legal_name not in str(after) and hide.value not in str(after)
    assert keep.value in str(after)

    listed = client.get("/api/notifications/digests?limit=100", headers=admin).json()
    (mine,) = [d for d in listed if d["id"] == str(dg.id)]
    assert mine["event_count"] == 1 and mine["kind"] == "org_discovery"

    e.db.expire_all()
    stored = e.db.get(Digest, dg.id)
    assert stored.event_count == 2 and deal.legal_name in str(stored.body)
    assert stored.body["totals"]["candidates"] == 2


# ── 8. the DB CHECK ──────────────────────────────────────────────────────────

def test_db_check_refuses_an_org_rule_that_is_not_digest_only(oenv):
    e = oenv
    for kw in ({"mode": "immediate"}, {"mode": "both"}, {"categories": ["x"]}):
        args = {"mode": "digest", "categories": [], **kw}
        e.db.add(NotificationRule(
            id=uuid.uuid4(), name=f"bad-{e.suffix}", recipients=["a@example.com"], kind="org_discovery", **args,
        ))
        with pytest.raises(IntegrityError):
            e.db.commit()
        e.db.rollback()
    ok = _org_rule(e)
    assert e.db.get(NotificationRule, ok.id).kind == "org_discovery", "precondition: a valid org rule inserts"


# ── 9. render ────────────────────────────────────────────────────────────────

def _body(values, count=None):
    return {
        "kind": "org_discovery", "rule": {"id": str(uuid.uuid4()), "name": "Rule <i>x</i>"},
        "period": {"start": "2026-01-01T00:00:00+00:00", "end": "2026-01-02T00:00:00+00:00"},
        "totals": {"candidates": count or len(values), "organizations": 1},
        "organizations": [{
            "id": str(uuid.uuid4()), "name": "Example <b>Org</b>", "candidate_count": count or len(values),
            "url": "https://app.example.com/organizations/x?tab=domains&seg=candidates",
            "candidates": [{"id": str(uuid.uuid4()), "kind": k, "value": v} for k, v in values],
        }],
    }


def test_render_escapes_html_and_pluralises():
    subject1, text1, html1 = candidate_digest.render(
        _body([("domain", "<b>evil</b>.example.com")]), "https://app.example.com")
    assert subject1.startswith("Constellus: 1 new organization discovery candidate to review (")
    assert "&lt;b&gt;evil&lt;/b&gt;.example.com" in html1 and "<b>evil</b>" not in html1
    assert "Example <b>Org</b>" not in html1 and "Example &lt;b&gt;Org&lt;/b&gt;" in html1
    assert "Review them in Constellus" in text1 and "Review them in Constellus" in html1
    assert "AI summary unavailable: not generated" in text1 and "AI summary unavailable: not generated" in html1

    subject2, text2, _ = candidate_digest.render(
        _body([("domain", "a.example.com"), ("asn", "AS64500"), ("cidr", "192.0.2.0/24")]), "")
    assert "3 new organization discovery candidates to review" in subject2
    assert "[ASN] AS64500" in text2 and "[IP range] 192.0.2.0/24" in text2 and "[domain] a.example.com" in text2


def test_filter_body_leaves_a_finding_body_unchanged(oenv):
    e = oenv
    rule = _rule(e, "frule", "digest")
    dg = Digest(
        rule_id=rule.id, rule_name=rule.name, period_start=e.t1 - timedelta(days=1), period_end=e.t1,
        body={"totals": {"findings": 0}, "groups": []},
    )
    e.db.add(dg)
    e.db.commit()
    assert candidate_digest.filter_body(e.db, dg) == {"totals": {"findings": 0}, "groups": []}


def test_filter_body_keys_on_the_row_kind_not_the_body(oenv):
    """A stored body that lost its `kind` field is still filtered: the row's
    kind decides, so a body cannot opt out of the engagement filter."""
    e = oenv
    rule = _org_rule(e)
    deal, eng = _live_deal(e, "day_0")
    e.w.candidate(deal)
    dg = _claim(e, rule)
    assert dg.body["totals"]["candidates"] == 1, "precondition: the deal was listed"

    dg.body = {k: v for k, v in dg.body.items() if k != "kind"}
    e.db.commit()
    _posture(e, eng, "pre_close")

    out = candidate_digest.filter_body(e.db, dg)
    assert out["organizations"] == [] and out["totals"] == {"candidates": 0, "organizations": 0}


# ── 10. planning#331 slice 1: strength, signals and shared groups in the body ─

def _sig(e, root, value, signal_type, matched=None):
    """Record one more signal for (root, value) through the service (creates the
    candidate when `signal_type` is Strong/Supporting). Returns the candidate."""
    ev = e.w.evidence_row()
    out = org_candidates.record_signal(
        e.db, root_entity_id=root.id, value=value, signal_type=signal_type, anchor_kind="person",
        via_entity_id=root.id, evidence_id=ev.id, quote=f"Our site is {value}.", matched_values=matched,
    )
    e.db.commit()
    return out.candidate


def _item(body, cand):
    return next(c for o in body["organizations"] for c in o["candidates"] if c["id"] == str(cand.id))


def _org_of(body, org):
    return next(o for o in body["organizations"] if o["id"] == str(org.id))


def test_claim_items_carry_strength_and_ordered_signals(oenv):
    e, w = oenv, oenv.w
    rule = _org_rule(e)
    ours = w.ours()
    strong = w.candidate(ours, value=f"s-{e.suffix}.fabrikam.com")  # person_evidence
    _sig(e, ours, strong.value, "registrant_org_match", ["example holdings a"])
    supp = _sig(e, ours, f"p-{e.suffix}.fabrikam.com", "registrant_org_match", ["example holdings a"])
    _sig(e, ours, supp.value, "spf_sender_shared", ["mail.contoso.com"])
    bare = w.candidate(ours, value=f"n-{e.suffix}.fabrikam.com")
    e.db.query(ScopeSignal).filter(ScopeSignal.candidate_id == bare.id).delete(synchronize_session=False)
    e.db.commit()

    dg = _claim(e, rule)

    a, b, c = (_item(dg.body, x) for x in (strong, supp, bare))
    assert a["strength"] == "strong"
    assert [s["type"] for s in a["signals"]] == ["person_evidence", "registrant_org_match"]
    assert a["signals"][0] == {"type": "person_evidence", "label": SIGNALS["person_evidence"].label}
    assert b["strength"] == "supporting"
    assert [s["label"] for s in b["signals"]] == sorted(SIGNALS[t].label for t in ("registrant_org_match", "spf_sender_shared"))
    assert c["strength"] == "context" and c["signals"] == []


def test_strongest_candidate_is_listed_first_and_survives_the_cap(oenv, monkeypatch):
    e, w = oenv, oenv.w
    rule = _org_rule(e)
    org = w.entity(legal_name=f"Example Ordered {e.suffix}")
    w.ours(org)
    weak = _sig(e, org, f"a-{e.suffix}.fabrikam.com", "registrant_org_match", ["x"])
    strong = w.candidate(org, value=f"z-{e.suffix}.fabrikam.com")
    dg = _claim(e, rule)
    mine = _org_of(dg.body, org)
    assert [c["id"] for c in mine["candidates"]] == [str(strong.id), str(weak.id)]
    assert weak.id in _claim_rows(e, rule) and mine["candidate_count"] == 2

    monkeypatch.setattr(candidate_digest, "LIST_CAP", 1)
    rule2 = _org_rule(e, "two")
    dg2 = _claim(e, rule2)
    mine2 = _org_of(dg2.body, org)
    assert [c["id"] for c in mine2["candidates"]] == [str(strong.id)] and mine2["candidate_count"] == 2


def test_shared_groups_per_org_and_cap(oenv, monkeypatch):
    e, w = oenv, oenv.w
    rule = _org_rule(e)
    o1, o2 = w.entity(legal_name=f"Example One {e.suffix}"), w.entity(legal_name=f"Example Two {e.suffix}")
    w.ours(o1)
    w.ours(o2)
    t = "registrant_org_match"
    a = _sig(e, o1, f"a-{e.suffix}.fabrikam.com", t, ["example holdings a", "solo-a"])
    b = _sig(e, o1, f"b-{e.suffix}.fabrikam.com", t, ["example holdings a"])
    # the same value under a different org's candidates must not group across orgs
    _sig(e, o1, f"c-{e.suffix}.fabrikam.com", t, ["cross-org"])
    _sig(e, o2, f"d-{e.suffix}.fabrikam.com", t, ["cross-org"])

    dg = _claim(e, rule)

    g1 = _org_of(dg.body, o1)["shared"]
    assert g1 == [{
        "type": t, "label": SIGNALS[t].label, "value": "example holdings a",
        "candidate_ids": [str(a.id), str(b.id)],
    }]
    assert _org_of(dg.body, o2)["shared"] == []
    assert len(_org_of(dg.body, o1)["candidates"]) == 3, "precondition: the cross-org candidate was listed"

    # a member beyond the cap is not in the group
    monkeypatch.setattr(candidate_digest, "LIST_CAP", 1)
    dg2 = _claim(e, _org_rule(e, "capped"))
    assert [c["id"] for c in _org_of(dg2.body, o1)["candidates"]] == [str(a.id)]
    assert _org_of(dg2.body, o1)["shared"] == []


def test_filter_body_prunes_groups(oenv):
    e, w = oenv, oenv.w
    rule = _org_rule(e)
    deal, eng = _live_deal(e, "day_0")
    t = "registrant_org_match"
    a = _sig(e, deal, f"a-{e.suffix}.fabrikam.com", t, ["example holdings a"])
    b = _sig(e, deal, f"b-{e.suffix}.fabrikam.com", t, ["example holdings a"])
    c = _sig(e, deal, f"c-{e.suffix}.fabrikam.com", t, ["example holdings a"])
    dg = _claim(e, rule)
    org = _org_of(dg.body, deal)
    assert len(org["shared"]) == 1 and len(org["shared"][0]["candidate_ids"]) == 3, "precondition"
    assert candidate_digest.filter_body(e.db, dg) == dg.body, "nothing removed: identical"

    # Make exactly one member ineligible: its own engagement is pre_close.
    pre = w.engagement("pre_close")
    _decide(e, c, "claimed", accepted_into="engagement", engagement_id=pre.id)
    out = _org_of(candidate_digest.filter_body(e.db, dg), deal)
    assert [x["id"] for x in out["candidates"]] == [str(a.id), str(b.id)]
    assert out["shared"][0]["candidate_ids"] == [str(a.id), str(b.id)]

    pre2 = w.engagement("pre_close")
    _decide(e, b, "claimed", accepted_into="engagement", engagement_id=pre2.id)
    out = _org_of(candidate_digest.filter_body(e.db, dg), deal)
    assert [x["id"] for x in out["candidates"]] == [str(a.id)] and out["shared"] == []


def test_filter_body_passes_an_old_shape_body_through(oenv):
    e, w = oenv, oenv.w
    rule = _org_rule(e)
    cand = w.candidate(w.ours())
    dg = _claim(e, rule)
    old = {k: v for k, v in dg.body.items()}
    old["organizations"] = [
        {k: v for k, v in o.items() if k != "shared"} | {
            "candidates": [{"id": c["id"], "kind": c["kind"], "value": c["value"]} for c in o["candidates"]]}
        for o in dg.body["organizations"]
    ]
    dg.body = old
    e.db.commit()
    assert cand.value in _listed(old), "precondition: the candidate is in the old-shape body"
    assert candidate_digest.filter_body(e.db, dg) == old


def _withheld_setup(e, narrative):
    rule = _org_rule(e)
    ours, (deal, eng) = e.w.ours(), _live_deal(e, "day_0")
    keep, hide = e.w.candidate(ours), e.w.candidate(deal)
    dg = _claim(e, rule)
    if narrative:
        dg.narrative = {"summary": "fake summary"}
        dg.narrative_status = "succeeded"
        dg.narrative_reason = None
        e.db.commit()
    return dg, keep, hide, eng


def test_view_org_unchanged_keeps_the_narrative(oenv):
    e = oenv
    dg, keep, hide, _eng = _withheld_setup(e, narrative=True)
    v = digest.view(e.db, dg)
    assert v.body == dg.body and v.narrative == {"summary": "fake summary"} and v.narrative_status == "succeeded"
    assert hide.value in _listed(v.body), "precondition: nothing was removed"


def test_view_org_removal_withholds_the_narrative(oenv):
    e = oenv
    dg, keep, hide, eng = _withheld_setup(e, narrative=True)
    _posture(e, eng, "pre_close")
    v = digest.view(e.db, dg)
    assert keep.value in _listed(v.body) and hide.value not in _listed(v.body), "the candidate was removed"
    assert v.narrative is None and v.narrative_status == "skipped"
    assert v.narrative_reason == digest.ORG_NARRATIVE_WITHHELD


def test_api_org_removal_withholds_the_narrative_fields(oenv, admin):
    # The view is right only if the API passes all of it through (the planning#331
    # walk caught `_apply_view` returning before the narrative fields for org digests).
    e = oenv
    dg, keep, hide, eng = _withheld_setup(e, narrative=False)
    dg.narrative = {"statements": [{"text": "fake summary", "cites": []}], "returned": 1, "dropped": 0}
    dg.narrative_status = "succeeded"
    e.db.commit()
    url = f"/api/notifications/digests/{dg.id}"
    before = client.get(url, headers=admin).json()
    assert before["narrative_status"] == "succeeded" and before["narrative"] is not None

    _posture(e, eng, "pre_close")

    after = client.get(url, headers=admin).json()
    assert keep.value in str(after["body"]) and hide.value not in str(after["body"]), "the candidate was removed"
    assert after["narrative"] is None and after["narrative_status"] == "skipped"
    assert after["narrative_reason"] == digest.ORG_NARRATIVE_WITHHELD
    listed = client.get("/api/notifications/digests?limit=100", headers=admin).json()
    (mine,) = [d for d in listed if d["id"] == str(dg.id)]
    assert mine["narrative_status"] == "skipped" and mine["narrative_reason"] == digest.ORG_NARRATIVE_WITHHELD


def test_view_org_removal_without_a_narrative_does_not_claim_withholding(oenv):
    e = oenv
    dg, keep, hide, eng = _withheld_setup(e, narrative=False)
    assert dg.narrative is None and dg.narrative_status is None and dg.narrative_reason is None
    _posture(e, eng, "pre_close")
    v = digest.view(e.db, dg)
    assert keep.value in _listed(v.body) and hide.value not in _listed(v.body), "the candidate was removed"
    assert v.narrative is None and v.narrative_status == "skipped" and v.narrative_reason is None


def test_render_shows_strength_signals_and_shared_groups():
    body = _body([("domain", "a.fabrikam.com"), ("domain", "b.fabrikam.com")])
    org = body["organizations"][0]
    ids = [c["id"] for c in org["candidates"]]
    org["candidates"][0].update(strength="strong", signals=[{"type": "admin_seed", "label": "Admin seed"},
                                                            {"type": "registrant_org_match", "label": "Registrant org match"}])
    org["candidates"][1].update(strength="lead", signals=[])
    org["shared"] = [{"type": "registrant_org_match", "label": "Registrant org match",
                      "value": "<b>x</b>", "candidate_ids": ids}]

    _, text, html = candidate_digest.render(body, "")

    assert "  [domain] a.fabrikam.com: Strong (Admin seed, Registrant org match)" in text
    assert "  [domain] b.fabrikam.com: Lead\n" in text
    assert "  Shared by several candidates:" in text
    assert "    Registrant org match: <b>x</b> (2 candidates: a.fabrikam.com, b.fabrikam.com)" in text
    assert ": Strong (Admin seed, Registrant org match)</li>" in html and "Shared by several candidates" in html
    assert "&lt;b&gt;x&lt;/b&gt;" in html and "<b>x</b>" not in html


def test_render_escapes_the_strength_note_in_html():
    # Labels are snapshots of SIGNALS today, but the body is stored data: escape it anyway.
    body = _body([("domain", "a.fabrikam.com")])
    body["organizations"][0]["candidates"][0].update(
        strength="strong", signals=[{"type": "admin_seed", "label": "<i>seed</i>"}],
    )
    _, text, html = candidate_digest.render(body, "")
    assert "a.fabrikam.com: Strong (<i>seed</i>)" in text
    assert "Strong (&lt;i&gt;seed&lt;/i&gt;)" in html and "<i>seed</i>" not in html


def test_signal_list_orders_by_tier_before_label():
    # Alphabetical by type would put the context signal first.
    assert SIGNALS["name_similarity"].tier != SIGNALS["person_evidence"].tier
    listed = candidate_digest._signal_list(("name_similarity", "person_evidence"))
    assert [s["type"] for s in listed] == ["person_evidence", "name_similarity"]


def test_render_old_shape_body_has_no_shared_section():
    _, text, html = candidate_digest.render(_body([("domain", "a.fabrikam.com")]), "")
    assert "[domain] a.fabrikam.com" in text and "Strong" not in text
    assert "Shared by" not in text + html


# ── 8. the AI summary (planning#331 slice 2) ─────────────────────────────────

class _HtmlConn(_Conn):
    """`_Conn` that also keeps the html part."""

    def __init__(self, mode="ok"):
        super().__init__(mode)
        self.html: list[str] = []

    def send(self, subject, body_text, recipients, config, body_html=None):
        self.html.append(body_html or "")
        return super().send(subject, body_text, recipients, config, body_html)


_MATCHED = "example holdings alpha"
_AI_LINE = "AI summary (each statement is tied to the candidates below):"


def _org_index(body, org):
    return next(i for i, o in enumerate(body["organizations"]) if o["id"] == str(org.id))


def _cite(path, value):
    return {"source_field": path, "value": str(value)}


def _shared_pair(e):
    """An ours root with a strong candidate `a` and a supporting candidate `b`
    sharing one matched value, claimed into an org digest."""
    ours = e.w.ours()
    a = e.w.candidate(ours, value=f"a-{e.suffix}.example.com")
    b = _sig(e, ours, f"b-{e.suffix}.example.com", "registrant_org_match", [_MATCHED])
    _sig(e, ours, a.value, "registrant_org_match", [_MATCHED])
    rule = _org_rule(e)
    dg = _claim(e, rule)
    assert digest.org_has_something_to_say(dg.body), "precondition: the body has a strong candidate and a group"
    return ours, a, b, rule, dg


def _five_statements(body, ours, a):
    base = f"organizations[{_org_index(body, ours)}]"
    s1 = f"{a.value} carries the strongest signals (strong)."
    s2 = f"2 candidates share {_MATCHED}."
    s3 = "Also seen on other.example.org."
    s4 = f"{a.value} is probably not the organization's."
    s5 = "9999 candidates stand out."
    statements = [
        {"text": s1, "cites": [_cite(f"{base}.candidates[0].value", a.value), _cite(f"{base}.candidates[0].strength", "strong")]},
        # members[0] is a list-of-strings leaf: the path grounder must resolve it, or S2 is dropped.
        {"text": s2, "cites": [
            _cite(f"{base}.shared[0].count", 2), _cite(f"{base}.shared[0].value", _MATCHED),
            _cite(f"{base}.shared[0].members[0]", a.value),
        ]},
        {"text": s3, "cites": [_cite(f"{base}.candidates[0].strength", "strong")]},
        {"text": s4, "cites": [_cite(f"{base}.candidates[0].value", a.value)]},
        {"text": s5, "cites": [_cite("totals.candidates", body["totals"]["candidates"])]},
    ]
    return statements, (s1, s2)


def test_org_narrative_input_hides_ids_and_links_and_names_group_members(oenv):
    e = oenv
    ours, a, b, _rule_, dg = _shared_pair(e)
    body = dg.body
    stored = json.dumps(body, sort_keys=True)
    data = digest.org_narrative_input(body)
    dumped = json.dumps(data)
    for key in ('"id"', '"url"', '"candidate_ids"'):
        assert key not in dumped
    mine = next(o for o in data["organizations"] if o["name"] == ours.legal_name)
    src = _org_of(body, ours)
    assert mine["shared"][0]["members"] == [a.value, b.value]
    assert mine["shared"][0]["count"] == 2
    assert mine["name"] == src["name"] and mine["candidate_count"] == src["candidate_count"]
    assert [(c["kind"], c["value"], c["strength"], c["signals"]) for c in mine["candidates"]] == [
        (c["kind"], c["value"], c["strength"], c["signals"]) for c in src["candidates"]]
    assert data["totals"] == body["totals"] and data["period"] == body["period"]
    assert json.dumps(body, sort_keys=True) == stored, "the stored body is unchanged"
    assert "id" in src["candidates"][0] and "candidate_ids" in src["shared"][0] and "id" in body["rule"]


def _cand(strength):
    return {"kind": "domain", "value": "a.example.com", "strength": strength, "signals": []}


@pytest.mark.parametrize("body, expected", [
    ({"organizations": [{"candidates": [_cand("context")], "shared": []}]}, False),
    ({"organizations": [{"candidates": [_cand("supporting")], "shared": []}]}, False),
    ({"organizations": [{"candidates": [_cand("supporting"), _cand("strong")], "shared": []}]}, True),
    ({"organizations": [{"candidates": [_cand("supporting")], "shared": [{"value": "x", "candidate_ids": ["1", "2"]}]}]}, True),
    ({}, False),
], ids=["context-only", "supporting-only", "one-strong", "shared-group", "empty"])
def test_org_has_something_to_say(body, expected):
    assert digest.org_has_something_to_say(body) is expected


def test_narrate_org_skips_before_the_cap_when_nothing_stands_out(oenv, llm):
    e = oenv
    ours = e.w.ours()
    cand = _sig(e, ours, f"s-{e.suffix}.example.com", "registrant_org_match", [_MATCHED])
    rule = _org_rule(e)
    dg = _claim(e, rule)
    t = llm(lambda request: _narrative_response([]))
    assert llmc.is_configured(e.db) and llmc.models_configured(e.db)
    assert cand.value in _listed(dg.body) and not digest.org_has_something_to_say(dg.body), \
        "precondition: only a supporting candidate, no group"
    before = digest.narrative_count_today(e.db)

    digest.narrate(e.db, dg)

    e.db.expire_all()
    dg = e.db.get(Digest, dg.id)
    assert dg.narrative_status == "skipped" and dg.narrative_reason == digest.ORG_NOTHING_TO_SAY
    assert t.requests == []
    assert digest.narrative_count_today(e.db) == before, "no cap slot was used"


def test_narrate_org_summary_is_grounded_stored_and_rendered(oenv, llm, monkeypatch):
    e = oenv
    conn = _HtmlConn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    ours, a, b, rule, dg = _shared_pair(e)
    statements, (s1, s2) = _five_statements(dg.body, ours, a)
    t = llm(lambda request: _narrative_response(statements))

    digest.narrate(e.db, dg)

    e.db.expire_all()
    dg = e.db.get(Digest, dg.id)
    assert len(t.requests) == 1, "precondition: the model was called"
    assert dg.narrative_status == "succeeded", dg.narrative_reason
    assert [s["text"] for s in dg.narrative["statements"]] == [s1, s2]
    assert dg.narrative["returned"] == 5 and dg.narrative["dropped"] == 3
    assert dg.model and dg.forced_strict is False and dg.ledger_ids
    request = t.requests[0]
    system = json.loads(request.content)["messages"][0]["content"]
    assert system.startswith("You summarise one organization discovery digest")
    block = json.dumps(_data_block(request))
    for key in ("candidate_ids", '"url"', '"id"'):
        assert key not in block

    digest.send(e.db, dg)

    (text,) = _send_texts(conn, e) or [None]
    assert text is not None, "precondition: the digest was sent"
    assert _AI_LINE in text and "  - " + s1 in text and "  - " + s2 in text
    html = next(h for h in conn.html if e.suffix in h)
    assert "<li>" + notification_dispatcher._esc(s1) + "</li>" in html


def test_narrate_org_with_nothing_grounded_says_so(oenv, llm, monkeypatch):
    e = oenv
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    ours, a, _b, _rule_, dg = _shared_pair(e)
    statements, _kept = _five_statements(dg.body, ours, a)
    t = llm(lambda request: _narrative_response(statements[2:]))  # S3, S4, S5 only

    digest.narrate(e.db, dg)

    e.db.expire_all()
    dg = e.db.get(Digest, dg.id)
    assert len(t.requests) == 1, "precondition: the model was called"
    assert dg.narrative_status == "failed"
    assert dg.narrative_reason == "no AI statement could be tied to its records"
    assert dg.narrative["statements"] == [] and dg.narrative["dropped"] == 3

    digest.send(e.db, dg)

    (text,) = _send_texts(conn, e) or [None]
    assert text is not None, "precondition: the digest was sent"
    assert "AI summary unavailable: no AI statement could be tied to its records" in text
    assert _AI_LINE not in text


E1, E2 = SimpleNamespace(id=uuid.uuid4()), SimpleNamespace(id=uuid.uuid4())


@pytest.mark.parametrize("results, expected", [
    ([(None, False), (None, False)], (None, False)),
    ([(E1, False), (E1, False)], (E1.id, False)),
    ([(E1, False), (E2, False)], (None, True)),
    ([(None, False), (E1, False)], (None, True)),
    ([(None, False), (None, True)], (None, True)),
    ([], (None, True)),
], ids=["all-estate", "same-engagement", "two-engagements", "estate-and-engagement", "one-strict", "no-orgs"])
def test_org_scope_for_combines_per_org_scopes(monkeypatch, results, expected):
    by_id = {uuid.uuid4(): r for r in results}
    monkeypatch.setattr(digest.entity_relationship, "ai_scope", lambda db, entity_id: by_id[entity_id])
    body = {"organizations": [{"id": str(i)} for i in by_id]}
    assert digest.org_scope_for(None, body) == expected


def test_narrate_org_under_one_deal_scopes_to_its_engagement(oenv, llm):
    e = oenv
    deal, eng = _live_deal(e, "day_0")
    cand = e.w.candidate(deal, value=f"d-{e.suffix}.example.com")
    rule = _org_rule(e)
    dg = _claim(e, rule)
    oi = _org_index(dg.body, deal)
    statement = {"text": f"{cand.value} carries the strongest signals.",
                 "cites": [_cite(f"organizations[{oi}].candidates[0].value", cand.value)]}
    t = llm(lambda request: _narrative_response([statement]))

    digest.narrate(e.db, dg)

    e.db.expire_all()
    dg = e.db.get(Digest, dg.id)
    assert len(t.requests) == 1, "precondition: the model was called"
    assert dg.narrative_status == "succeeded", dg.narrative_reason
    assert dg.forced_strict is False
    calls = e.db.query(LlmCall).filter(LlmCall.id.in_(dg.ledger_ids)).all()
    assert calls, "precondition: the ledger has rows"
    assert {c.engagement_id for c in calls} == {eng.id}


def test_narrate_org_shares_the_daily_cap(oenv, llm):
    e = oenv
    digest.app_settings.set_value(e.db, digest.NARRATIVE_CAP_KEY, "1")
    e.db.add(Digest(rule_id=None, rule_name=f"earlier-{e.suffix}", period_start=e.t1 - timedelta(days=1),
                    period_end=e.t1, outcome="sent", narrative_status="succeeded"))
    e.db.commit()
    assert digest.narrative_count_today(e.db) >= 1, "precondition: a finding digest already used the slot"
    _ours, _a, _b, _rule_, dg = _shared_pair(e)
    t = llm(lambda request: _narrative_response([]))
    assert digest.org_has_something_to_say(dg.body)

    digest.narrate(e.db, dg)

    e.db.expire_all()
    dg = e.db.get(Digest, dg.id)
    assert dg.narrative_status == "skipped" and dg.narrative_reason == "today's AI digest cap (1) is reached"
    assert t.requests == []


def test_view_withholds_a_real_org_summary_after_a_deal_goes_back_to_pre_close(oenv, llm, monkeypatch):
    e, w = oenv, oenv.w
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    ours = w.ours()
    deal, eng = _live_deal(e, "day_0")
    keep = w.candidate(ours, value=f"keep-{e.suffix}.example.com")
    hide = w.candidate(deal, value=f"hide-{e.suffix}.example.com")
    rule = _org_rule(e)
    dg = _claim(e, rule)
    statements = []
    for org, cand in ((ours, keep), (deal, hide)):
        oi = _org_index(dg.body, org)
        statements.append({
            "text": f"{cand.value} carries a strong signal.",
            "cites": [_cite(f"organizations[{oi}].candidates[0].value", cand.value)],
        })
    t = llm(lambda request: _narrative_response(statements))

    digest.narrate(e.db, dg)

    e.db.expire_all()
    dg = e.db.get(Digest, dg.id)
    assert len(t.requests) == 1 and dg.narrative_status == "succeeded", "precondition: a stored summary"
    assert len(dg.narrative["statements"]) == 2

    _posture(e, eng, "pre_close")
    v = digest.view(e.db, dg)
    assert keep.value in _listed(v.body) and hide.value not in _listed(v.body), "the candidate was removed"
    assert v.narrative is None and v.narrative_status == "skipped"
    assert v.narrative_reason == digest.ORG_NARRATIVE_WITHHELD
    e.db.expire_all()
    stored = e.db.get(Digest, dg.id)
    assert stored.narrative_status == "succeeded" and len(stored.narrative["statements"]) == 2

    digest.send(e.db, dg)

    (text,) = _send_texts(conn, e) or [None]
    assert text is not None, "precondition: the digest was sent"
    assert "AI summary unavailable: it was withheld because candidates were removed from this digest after it was written" in text
    assert hide.value not in text
    assert not any(s["text"] in text for s in statements)
    assert keep.value in text


_DISMISSALS = [
    "is not the organization's", "does not belong to", "doesn't belong", "is unrelated", "can be rejected",
    "can be ignored", "no need to review", "can be skipped", "is probably not", "a coincidence",
    "false positive", "low priority",
]


@pytest.mark.parametrize("phrase", _DISMISSALS)
def test_org_dismissal_phrases_are_dropped(phrase):
    data = {"organizations": [{"candidates": [{"value": "a.example.com", "strength": "strong"}]}]}
    cites = [digest.Cite(source_field="organizations[0].candidates[0].value", value="a.example.com")]

    def run(text):
        out = digest.NarrativeOut(statements=[digest.Statement(text=text, cites=cites)])
        return digest.ground(out, data, forbidden=digest._ORG_DISMISSAL)

    kept, _returned, dropped = run("a.example.com carries the strongest signals of the group")
    assert (len(kept["statements"]), dropped) == (1, 0), "control: the same cites without the phrase are kept"
    narrative, returned, dropped = run(f"a.example.com {phrase} here")
    assert (narrative["statements"], returned, dropped) == ([], 1, 1)
