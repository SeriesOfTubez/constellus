"""planning#330: findings under a restricting engagement never reach rule
recipients (`app.services.notification_scope`), at dispatch and at digest claim.

Synthetic values only (`example` hostnames). Reuses the `denv` fixture from
test_digests.py, which removes everything carrying its suffix.

Run:  backend/scripts/test.sh app/tests/test_notification_scope.py
"""

import copy
import json
import uuid
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone

import pytest

from app.models.alert_event import AlertDispatch, AlertEvent
from app.models.digest import Digest
from app.models.notification_rule import RULE_KIND_ORG_DISCOVERY
from app.models.engagement import Engagement, EngagementPosture
from app.services import digest, notification_dispatcher, notification_scope, score_history
from app.tests.test_alert_events import _Conn, _use_connectors
from app.tests.test_digests import _defer, _dispatch, _finding_ids, _rule, admin, client, denv  # noqa: F401  (fixtures)

RESTRICTING = [EngagementPosture.PRE_CLOSE.value, EngagementPosture.ABANDONED.value]
OPEN = [EngagementPosture.DAY_0.value, EngagementPosture.INTEGRATED.value]


def _set_posture(e, engagement_id, posture):
    row = e.db.get(Engagement, engagement_id)
    row.posture = posture
    if posture in OPEN:
        row.authorised_at = datetime.now(timezone.utc)
        row.authorisation_reference = "test"
    else:
        row.authorised_at = None
        row.authorisation_reference = None
        row.authorised_by_id = None
    e.db.commit()


class _Scope:
    pass


def _world(e, posture):
    """deal target (engagement `posture`) + its asset/finding, and an ours
    target (no engagement) + asset/finding."""
    w = _Scope()
    w.deal_host = f"www.{e.suffix}.deal.example"
    w.ours_host = f"www.{e.suffix}.ours.example"
    # `_World.engagement` writes authorisation fields for every non-pre_close posture,
    # which `abandoned` forbids: create pre_close and set the posture ourselves.
    w.eng = e.world.engagement(EngagementPosture.PRE_CLOSE.value)
    _set_posture(e, w.eng, posture)
    w.deal_target = e.world.target(engagement_id=w.eng, value=f"{e.suffix}.deal.example")
    e.world.target(value=f"{e.suffix}.ours.example")
    w.deal_asset = e.world.asset(asset_type="subdomain", value=w.deal_host)
    w.ours_asset = e.world.asset(asset_type="subdomain", value=w.ours_host)
    w.deal_cve, w.ours_cve = "CVE-2099-1111", "CVE-2099-2222"
    w.deal = e.world.finding(w.deal_asset, cve=w.deal_cve)
    w.ours = e.world.finding(w.ours_asset, cve=w.ours_cve)
    return w


# ── 1-4. the predicate ───────────────────────────────────────────────────────

@pytest.mark.parametrize("posture", RESTRICTING)
def test_restricting_posture_leaves_only_ours(denv, posture):
    w = _world(denv, posture)
    got = notification_scope.eligible_finding_ids(denv.db, [w.deal, w.ours])
    assert got == {w.ours}  # ours stays eligible (case 3): another asset under a deal does not flip it


@pytest.mark.parametrize("posture", OPEN)
def test_open_posture_keeps_both(denv, posture):
    w = _world(denv, posture)
    assert notification_scope.eligible_finding_ids(denv.db, [w.deal, w.ours]) == {w.deal, w.ours}


def test_empty_input_is_empty_set(denv):
    assert notification_scope.eligible_finding_ids(denv.db, []) == set()


def test_strictest_wins_over_a_second_open_target(denv):
    e = denv
    w = _world(e, EngagementPosture.PRE_CLOSE.value)
    open_eng = e.world.engagement(EngagementPosture.PRE_CLOSE.value)
    _set_posture(e, open_eng, EngagementPosture.DAY_0.value)
    e.world.target(engagement_id=open_eng, value=f"deal.example")  # parent domain covers the deal asset too
    assert notification_scope.eligible_finding_ids(e.db, [w.deal, w.ours]) == {w.ours}


def test_target_link_only_leg_is_excluded(denv):
    e = denv
    eng = e.world.engagement(EngagementPosture.PRE_CLOSE.value)
    # The asset value is NOT under the target's domain: only the link covers it.
    asset = e.world.asset(asset_type="subdomain", value=f"www.{e.suffix}.unrelated.example")
    e.world.target(engagement_id=eng, value=f"{e.suffix}.linked.example", link_asset=asset)
    f = e.world.finding(asset)
    assert notification_scope.eligible_finding_ids(e.db, [f]) == set()
    _set_posture(e, eng, EngagementPosture.DAY_0.value)
    assert notification_scope.eligible_finding_ids(e.db, [f]) == {f}


# ── 5-6. dispatcher ──────────────────────────────────────────────────────────

def _dispatches_for(e, rule):
    e.db.expire_all()
    return e.db.query(AlertDispatch).filter(AlertDispatch.rule_id == rule.id).all()


def _event_finding_ids(e, rule):
    return {ev.finding_id for d in _dispatches_for(e, rule)
            for ev in e.db.query(AlertEvent).filter(AlertEvent.dispatch_id == d.id)}


def test_dispatch_sends_only_the_unrestricted_finding(denv, monkeypatch):
    e = denv
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    rule = _rule(e, "rule", "immediate")
    w = _world(e, EngagementPosture.PRE_CLOSE.value)

    notification_dispatcher._dispatch(e.db, [w.deal, w.ours])

    assert len(conn.sent) == 1  # reached: the ours finding produced a send
    assert _event_finding_ids(e, rule) == {w.ours}
    assert w.deal_cve not in conn.sent[0]["text"] and w.ours_cve in conn.sent[0]["text"]


def test_dispatch_only_restricted_finding_records_and_sends_nothing_but_open_control_sends(denv, monkeypatch):
    e = denv
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    rule = _rule(e, "rule", "immediate")
    w = _world(e, EngagementPosture.PRE_CLOSE.value)

    notification_dispatcher._dispatch(e.db, [w.deal])
    assert _dispatches_for(e, rule) == [] and conn.sent == []

    _set_posture(e, w.eng, EngagementPosture.DAY_0.value)  # control: same fixture, only the posture differs
    notification_dispatcher._dispatch(e.db, [w.deal])
    assert len(conn.sent) == 1 and _event_finding_ids(e, rule) == {w.deal}


def _promo(e, finding_id, asset_id):
    return score_history.Promotion(
        finding_canonical_id=finding_id, asset_canonical_id=asset_id,
        previous_band="elevated", new_band="high", previous_score=30, new_score=60, velocity_started=True,
    )


def test_promotions_drop_the_restricted_finding_and_open_control_sends_it(denv, monkeypatch):
    e = denv
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    rule = _rule(e, "rule", "immediate")
    w = _world(e, EngagementPosture.PRE_CLOSE.value)
    promos = [_promo(e, w.deal, w.deal_asset), _promo(e, w.ours, w.ours_asset)]

    notification_dispatcher._dispatch_promotions(e.db, promos)
    assert len(conn.sent) == 1  # reached
    assert _event_finding_ids(e, rule) == {w.ours}

    # only the restricted one: nothing new
    notification_dispatcher._dispatch_promotions(e.db, [promos[0]])
    assert len(conn.sent) == 1 and _event_finding_ids(e, rule) == {w.ours}

    _set_posture(e, w.eng, EngagementPosture.DAY_0.value)  # control
    notification_dispatcher._dispatch_promotions(e.db, [promos[0]])
    assert len(conn.sent) == 2 and _event_finding_ids(e, rule) == {w.deal, w.ours}


# ── 7. digest claim ──────────────────────────────────────────────────────────

def _deferred(e, rule, finding, minutes=30):
    d = _dispatch(e, rule, [(SimpleNamespace(id=finding), "high", None)], created_at=e.t1 - timedelta(minutes=minutes))
    _defer(e, d)
    return d


def _digest_id(e, d):
    e.db.expire_all()
    return e.db.get(AlertDispatch, d.id).digest_id


def test_claim_leaves_a_now_restricted_finding_out_of_the_body(denv):
    e = denv
    rule = _rule(e, "rule", "digest")
    w = _world(e, EngagementPosture.DAY_0.value)
    d_deal = _deferred(e, rule, w.deal)
    d_ours = _deferred(e, rule, w.ours)
    _set_posture(e, w.eng, EngagementPosture.PRE_CLOSE.value)

    dg = digest.claim(e.db, rule.id, e.t1)

    assert dg is not None and dg.outcome == "pending"  # reached: the ours finding is still digested
    assert dg.body["totals"]["findings"] == 1
    assert _finding_ids(dg.body) == {str(w.ours)}
    blob = json.dumps(dg.body)
    assert w.deal_host not in blob and str(w.deal) not in blob and w.ours_host in blob
    assert _digest_id(e, d_deal) == dg.id and _digest_id(e, d_ours) == dg.id  # both stay claimed


def test_claim_with_only_a_restricted_finding_is_empty(denv):
    e = denv
    rule = _rule(e, "rule", "digest")
    w = _world(e, EngagementPosture.DAY_0.value)
    d = _deferred(e, rule, w.deal)
    _set_posture(e, w.eng, EngagementPosture.ABANDONED.value)

    dg = digest.claim(e.db, rule.id, e.t1)

    assert dg is not None and dg.outcome == "empty" and dg.finding_count == 0
    assert _digest_id(e, d) == dg.id


# ── 8. addendum: the inet leg ────────────────────────────────────────────────

@pytest.mark.parametrize("posture,expected", [(EngagementPosture.PRE_CLOSE.value, False), (EngagementPosture.DAY_0.value, True)])
def test_ip_asset_under_a_cidr_target(denv, posture, expected):
    e = denv
    eng = e.world.engagement(EngagementPosture.PRE_CLOSE.value)
    _set_posture(e, eng, posture)
    e.world.target(engagement_id=eng, type_="cidr", value="192.0.2.0/24")
    asset = e.world.asset(asset_type="ip_address", value="192.0.2.10")
    f = e.world.finding(asset)
    assert (notification_scope.eligible_finding_ids(e.db, [f]) == {f}) is expected


# ── 9. digest view (re-check at send and on read-back) ───────────────────────

NARRATIVE_TEXT = "STORED-NARRATIVE-SENTENCE"


def _stored_digest(e, rule, w, *, narrative=True):
    """Claim a digest over both findings (or whichever are eligible NOW), with a stored
    narrative and a group write-up, as the real flow leaves it."""
    _deferred(e, rule, w.deal)
    _deferred(e, rule, w.ours)
    dg = digest.claim(e.db, rule.id, e.t1)
    body = copy.deepcopy(dg.body)
    for g in body["groups"]:
        g["writeup"] = {"summary": "stored write-up", "asset_count": 1, "written_at": "2026-01-01T00:00:00"}
    dg.body = body
    if narrative:
        dg.narrative_status = "succeeded"
        dg.narrative = {"statements": [{"text": f"{NARRATIVE_TEXT} {w.deal_host}", "cites": []}], "returned": 1, "dropped": 0}
        dg.narrative_reason = None
    e.db.commit()
    return dg


def test_view_unchanged_when_nothing_was_restricted(denv):
    e = denv
    rule = _rule(e, "rule", "digest")
    w = _world(e, EngagementPosture.DAY_0.value)
    dg = _stored_digest(e, rule, w)
    stored = copy.deepcopy(dg.body)

    v = digest.view(e.db, dg)

    assert _finding_ids(v.body) == {str(w.deal), str(w.ours)}  # reached: both listed, so the comparison ran on two
    assert v.body == stored and any("writeup" in g for g in v.body["groups"])
    assert v.narrative_status == "succeeded" and NARRATIVE_TEXT in json.dumps(v.narrative)
    assert v.narrative_reason is None


def test_view_withholds_after_a_finding_becomes_restricted_and_never_writes(denv):
    e = denv
    rule = _rule(e, "rule", "digest")
    w = _world(e, EngagementPosture.DAY_0.value)
    dg = _stored_digest(e, rule, w)
    _set_posture(e, w.eng, EngagementPosture.PRE_CLOSE.value)

    v = digest.view(e.db, dg)

    assert v.body["totals"]["findings"] == 1 and _finding_ids(v.body) == {str(w.ours)}  # reached: ours kept
    blob = json.dumps(v.body)
    assert w.deal_host not in blob and str(w.deal) not in blob
    assert not any("writeup" in g for g in v.body["groups"])
    assert v.narrative is None and v.narrative_status == "skipped" and v.narrative_reason == digest.NARRATIVE_WITHHELD
    assert v.body["rule"] == dg.body["rule"]

    e.db.expire_all()
    row = e.db.get(Digest, dg.id)
    assert row.body["totals"]["findings"] == 2 and w.deal_host in json.dumps(row.body)
    assert row.narrative_status == "succeeded" and NARRATIVE_TEXT in json.dumps(row.narrative)


def test_claim_time_exclusion_does_not_withhold_the_narrative(denv):
    e = denv
    rule = _rule(e, "rule", "digest")
    w = _world(e, EngagementPosture.PRE_CLOSE.value)
    dg = _stored_digest(e, rule, w)
    assert _finding_ids(dg.body) == {str(w.ours)}  # reached: restricted one already left out at claim

    v = digest.view(e.db, dg)

    assert v.narrative_status == "succeeded" and NARRATIVE_TEXT in json.dumps(v.narrative)
    assert any("writeup" in g for g in v.body["groups"])


def test_view_is_keyed_on_the_row_kind_not_the_body(denv):
    e = denv
    rule = _rule(e, "rule", "digest")
    w = _world(e, EngagementPosture.DAY_0.value)
    dg = _stored_digest(e, rule, w)
    _set_posture(e, w.eng, EngagementPosture.PRE_CLOSE.value)
    body = copy.deepcopy(dg.body)
    body["kind"] = RULE_KIND_ORG_DISCOVERY
    body["organizations"] = []
    dg.body = body
    e.db.commit()

    v = digest.view(e.db, dg)

    assert v.body["totals"]["findings"] == 1 and v.narrative_reason == digest.NARRATIVE_WITHHELD
    assert w.deal_host not in json.dumps(v.body)


def test_org_discovery_row_goes_through_filter_body(denv, monkeypatch):
    e = denv
    rule = _rule(e, "rule", "digest")
    w = _world(e, EngagementPosture.DAY_0.value)
    dg = _stored_digest(e, rule, w)
    dg.kind = RULE_KIND_ORG_DISCOVERY
    e.db.commit()
    marker = {"totals": {"candidates": 0, "organizations": 0}, "marker": True}
    monkeypatch.setattr(digest.candidate_digest, "filter_body", lambda db, d: marker)
    try:
        assert digest.view(e.db, dg).body is marker
    finally:
        dg.kind = "finding"
        e.db.commit()


# ── 10. send ─────────────────────────────────────────────────────────────────

def test_send_of_a_restricted_after_build_digest_omits_the_deal_and_the_narrative(denv, monkeypatch):
    e = denv
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    rule = _rule(e, "rule", "digest")
    w = _world(e, EngagementPosture.DAY_0.value)
    dg = _stored_digest(e, rule, w)
    _set_posture(e, w.eng, EngagementPosture.PRE_CLOSE.value)

    digest.send(e.db, dg)

    assert len(conn.sent) == 1
    sent = conn.sent[0]
    out = sent["subject"] + sent["text"]
    assert w.ours_host in sent["text"] and w.ours_cve in sent["text"]  # reached
    assert w.deal_host not in out and w.deal_cve not in out and NARRATIVE_TEXT not in out
    assert "1 finding" in sent["subject"]
    assert f"AI summary unavailable: {digest.NARRATIVE_WITHHELD}" in sent["text"]
    e.db.expire_all()
    assert e.db.get(Digest, dg.id).outcome == "sent"


def test_send_when_the_only_finding_became_restricted_is_empty_and_open_control_sends(denv, monkeypatch):
    e = denv
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    rule = _rule(e, "rule", "digest")
    w = _world(e, EngagementPosture.DAY_0.value)
    _deferred(e, rule, w.deal)
    dg = digest.claim(e.db, rule.id, e.t1)
    assert dg.outcome == "pending"  # reached: it was built with the finding

    _set_posture(e, w.eng, EngagementPosture.PRE_CLOSE.value)
    digest.send(e.db, dg)
    e.db.expire_all()
    row = e.db.get(Digest, dg.id)
    assert row.outcome == "empty" and row.sent_at is None and conn.sent == []

    _set_posture(e, w.eng, EngagementPosture.DAY_0.value)  # control
    digest.send(e.db, row)
    e.db.expire_all()
    row = e.db.get(Digest, dg.id)
    assert row.outcome == "sent" and row.sent_at is not None and len(conn.sent) == 1


# ── 11. API ──────────────────────────────────────────────────────────────────

def test_digest_api_rechecks_on_read(denv, admin):
    e, (h, _uid) = denv, admin
    rule = _rule(e, "rule", "digest")
    w = _world(e, EngagementPosture.DAY_0.value)
    dg = _stored_digest(e, rule, w)

    d = client.get(f"/api/notifications/digests/{dg.id}", headers=h).json()
    assert d["finding_count"] == 2 and d["event_count"] == 2 and d["narrative_status"] == "succeeded"  # control

    _set_posture(e, w.eng, EngagementPosture.PRE_CLOSE.value)
    d = client.get(f"/api/notifications/digests/{dg.id}", headers=h).json()
    assert d["finding_count"] == 1 and d["event_count"] == 1
    assert d["narrative"] is None and d["narrative_status"] == "skipped"
    assert d["narrative_reason"] == digest.NARRATIVE_WITHHELD
    assert w.deal_host not in json.dumps(d["body"]) and w.ours_host in json.dumps(d["body"])

    rows = client.get("/api/notifications/digests?limit=100", headers=h).json()
    item = next(r for r in rows if r["id"] == str(dg.id))
    assert item["finding_count"] == 1 and item["event_count"] == 1
    assert item["narrative_status"] == "skipped" and item["narrative_reason"] == digest.NARRATIVE_WITHHELD


def _alerts_for(h, rule):
    rows = client.get("/api/notifications/alerts?limit=200", headers=h).json()
    return [r for r in rows if r["rule_id"] == str(rule.id)]


def test_alerts_api_drops_restricted_events_and_empty_dispatches(denv, admin):
    e, (h, _uid) = denv, admin
    rule = _rule(e, "rule", "immediate")
    w = _world(e, EngagementPosture.DAY_0.value)
    both = _dispatch(e, rule, [(SimpleNamespace(id=w.deal), "high", None), (SimpleNamespace(id=w.ours), "high", None)])
    only_deal = _dispatch(e, rule, [(SimpleNamespace(id=w.deal), "high", None)])
    no_events = _dispatch(e, rule, [])

    got = {r["id"]: r for r in _alerts_for(h, rule)}  # control: day_0 shows everything
    assert got[str(both.id)]["event_count"] == 2 and str(only_deal.id) in got and str(no_events.id) in got

    _set_posture(e, w.eng, EngagementPosture.PRE_CLOSE.value)
    got = {r["id"]: r for r in _alerts_for(h, rule)}
    assert got[str(both.id)]["event_count"] == 1
    assert [ev["finding_id"] for ev in got[str(both.id)]["events"]] == [str(w.ours)]
    assert str(only_deal.id) not in got
    assert str(no_events.id) in got and got[str(no_events.id)]["event_count"] == 0
