"""Coverage for planning#233 slice 2a: per-rule alert digests
(`app.services.digest`, migration 0080, the dispatcher's `mode` handling, the
digest/settings API).

Synthetic values only (`example.com`, RFC 5737 addresses). The LLM is stubbed
at the TRANSPORT (`llm_connector._transport`), never by patching `structured`.
Every row a test creates is removed by the `denv` fixture.

Run:  backend/scripts/test.ps1 app/tests/test_digests.py
"""

import json
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError

from app.core.database import SessionLocal
from app.main import app
from app.models.alert_event import AlertDelivery, AlertDispatch, AlertEvent
from app.models.app_settings import AppSetting
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.audit import AuditLog
from app.models.digest import Digest
from app.models.engagement import EngagementPosture
from app.models.finding_canonical import FindingCanonical
from app.models.llm_call import LlmCall
from app.models.notification_rule import NotificationRule
from app.models.user import UserRole
from app.services import app_settings, digest, notification_dispatcher, scheduler
from app.services import llm_connector as llmc
from app.tests.test_alert_events import _Conn, _mk_asset, _mk_finding, _use_connectors
from app.tests.test_edgar_ingest_api import _cleanup_user, _make_user
from app.tests.test_finding_writeup import NARRATE_PRIMARY, _Transport, _World
from app.tests.test_llm_connector import (
    _configure_openrouter, _ok_response, _restore_app_setting, _restore_openrouter, _snapshot_app_setting,
)

client = TestClient(app)

_SETTING_KEYS = (
    digest.DIGEST_HOUR_KEY, digest.NARRATIVE_CAP_KEY, digest.BASE_URL_KEY, "llm.daily_budget_usd",
)


# ── fixtures and helpers ─────────────────────────────────────────────────────

class _Env:
    pass


@pytest.fixture
def denv():
    """A session, a unique suffix, `T1` (a minute from now, with the digest
    hour set to T1's hour, so `current_cutoff(T1)` is at or before T1 and the
    first digest is due) and the engagement/target world. Everything carrying
    the suffix is removed afterwards, dispatches first (rule deletion only
    NULLs their rule_id), then digests, rules, targets, findings, assets; the
    settings this file touches are restored."""
    e = _Env()
    e.suffix = uuid.uuid4().hex[:10]
    e.octet = 100
    e.db = SessionLocal()
    e.world = _World()
    e.t1 = datetime.now(timezone.utc) + timedelta(minutes=1)
    e.t2 = e.t1 + timedelta(days=1)
    snaps = {k: _snapshot_app_setting(e.db, k) for k in _SETTING_KEYS}
    app_settings.set_value(e.db, digest.DIGEST_HOUR_KEY, str(e.t1.hour))
    db, suffix = e.db, e.suffix
    try:
        yield e
    finally:
        db.rollback()
        like = f"%{suffix}%"
        digest_ids = [r[0] for r in db.query(Digest.id).filter(Digest.rule_name.like(like)).all()]
        if digest_ids:
            db.query(LlmCall).filter(LlmCall.task.in_([f"{digest.TASK_PREFIX}:{i}" for i in digest_ids])).delete(
                synchronize_session=False)
        db.query(AlertDispatch).filter(AlertDispatch.rule_name.like(like)).delete(synchronize_session=False)
        db.query(Digest).filter(Digest.rule_name.like(like)).delete(synchronize_session=False)
        db.query(NotificationRule).filter(NotificationRule.name.like(like)).delete(synchronize_session=False)
        db.commit()
        e.world.close()
        ids = [r[0] for r in db.query(AssetCanonical.id).filter(AssetCanonical.value.like(like)).all()]
        if ids:
            db.query(FindingCanonical).filter(FindingCanonical.asset_canonical_id.in_(ids)).delete(
                synchronize_session=False)
            db.query(AssetState).filter(AssetState.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
            db.query(AssetCanonical).filter(AssetCanonical.id.in_(ids)).delete(synchronize_session=False)
        db.commit()
        for k, v in snaps.items():
            _restore_app_setting(db, k, v)
        db.close()


def _rule(e, name, mode="digest", *, enabled=True, recipients=("alerts@example.com",), created_at=None,
          threshold="high"):
    kw = {"created_at": created_at} if created_at else {}
    rule = NotificationRule(
        id=uuid.uuid4(), name=f"{name}-{e.suffix}", enabled=enabled, severity_threshold=threshold,
        categories=[], recipients=list(recipients), mode=mode, **kw,
    )
    e.db.add(rule)
    e.db.commit()
    return rule


def _asset(e, n=None):
    if n is None:
        e.octet += 1
        n = e.octet
    # One literal documentation address; the suffix keeps each value unique.
    return _mk_asset(e.db, f"192.0.2.10-{n}-{e.suffix}")


def _finding(e, asset, fp, **kw):
    return _mk_finding(e.db, asset.id, fp, **kw)


def _dispatch(e, rule, specs, *, kind="new", created_at=None):
    """specs: [(finding, severity snapshot, detail | None)]."""
    kw = {"created_at": created_at} if created_at else {}
    d = AlertDispatch(rule_id=rule.id, rule_name=rule.name, kind=kind, **kw)
    e.db.add(d)
    e.db.flush()
    for f, sev, detail in specs:
        e.db.add(AlertEvent(dispatch_id=d.id, finding_id=f.id, severity=sev, detail=detail or {}))
    e.db.commit()
    return d


def _digests(e, rule):
    e.db.expire_all()
    return e.db.query(Digest).filter(Digest.rule_id == rule.id).order_by(Digest.period_end, Digest.id).all()


def _finding_ids(body):
    return {i["finding_id"] for g in body["groups"] for i in g["items"]}


def _digest_id_of(e, dispatch):
    e.db.expire_all()
    return e.db.get(AlertDispatch, dispatch.id).digest_id


# ── 1. dispatcher modes ──────────────────────────────────────────────────────

def _hi(e):
    return _finding(e, _asset(e, 10), "fp-hi", severity="high", cve_id="CVE-2024-90101")


def test_digest_rule_records_and_defers_and_never_sends(denv, monkeypatch):
    e = denv
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    rule = _rule(e, "rule", "digest", recipients=("a@example.com", "b@example.com"))
    hi = _hi(e)

    notification_dispatcher._dispatch(e.db, [hi.id])

    e.db.expire_all()
    (d,) = e.db.query(AlertDispatch).filter(AlertDispatch.rule_id == rule.id).all()
    assert [ev.finding_id for ev in e.db.query(AlertEvent).filter(AlertEvent.dispatch_id == d.id)] == [hi.id]
    (dl,) = e.db.query(AlertDelivery).filter(AlertDelivery.dispatch_id == d.id).all()
    assert (dl.connector_id, dl.outcome, dl.recipient_count) == (None, "deferred_to_digest", 2)
    assert conn.sent == []  # reached: the dispatch and its deferral were recorded above


def test_digest_rule_with_no_channel_is_deferred_not_no_channel(denv, monkeypatch):
    e = denv
    _use_connectors(monkeypatch, [])
    rule = _rule(e, "rule", "digest")
    hi = _hi(e)

    notification_dispatcher._dispatch(e.db, [hi.id])

    e.db.expire_all()
    (d,) = e.db.query(AlertDispatch).filter(AlertDispatch.rule_id == rule.id).all()
    (dl,) = e.db.query(AlertDelivery).filter(AlertDelivery.dispatch_id == d.id).all()
    assert (dl.connector_id, dl.outcome, dl.recipient_count) == (None, "deferred_to_digest", 1)


def test_digest_rule_without_recipients_is_still_deferred(denv, monkeypatch):
    e = denv
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    rule = _rule(e, "rule", "digest", recipients=())
    hi = _hi(e)

    notification_dispatcher._dispatch(e.db, [hi.id])

    e.db.expire_all()
    (d,) = e.db.query(AlertDispatch).filter(AlertDispatch.rule_id == rule.id).all()
    outcomes = [(dl.outcome, dl.recipient_count) for dl in e.db.query(AlertDelivery).filter(AlertDelivery.dispatch_id == d.id)]
    assert outcomes == [("deferred_to_digest", 0)]
    assert conn.sent == []


def test_both_rule_sends_and_records_and_immediate_is_unchanged(denv, monkeypatch):
    e = denv
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    both = _rule(e, "both", "both")
    imm = _rule(e, "imm", "immediate")
    hi = _hi(e)

    notification_dispatcher._dispatch(e.db, [hi.id])

    assert len(conn.sent) == 2, "the both rule and the immediate rule each send once"
    e.db.expire_all()
    for rule in (both, imm):
        (d,) = e.db.query(AlertDispatch).filter(AlertDispatch.rule_id == rule.id).all()
        assert len(e.db.query(AlertEvent).filter(AlertEvent.dispatch_id == d.id).all()) == 1
        (dl,) = e.db.query(AlertDelivery).filter(AlertDelivery.dispatch_id == d.id).all()
        assert (dl.connector_id, dl.outcome) == ("c1", "sent")


def test_digest_rule_is_sent_immediately_when_recording_fails(denv, monkeypatch):
    """Deferral is only honest if a dispatch exists for a digest to claim. If
    recording the selection fails, the alert goes out now, like an immediate
    rule's, and no dispatch row survives."""
    e = denv
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    rule = _rule(e, "rule", "digest")
    hi = _hi(e)
    reached = {"n": 0}

    def _boom(self, *a, **k):
        reached["n"] += 1
        raise RuntimeError("bookkeeping broke")

    monkeypatch.setattr(AlertEvent, "__init__", _boom)

    notification_dispatcher._dispatch(e.db, [hi.id])

    assert reached["n"] >= 1, "precondition: recording was reached and failed"
    assert len(conn.sent) == 1, "the alert must go out immediately"
    assert "CVE-2024-90101" in conn.sent[0]["text"]
    e.db.rollback()
    assert e.db.query(AlertDispatch).filter(AlertDispatch.rule_id == rule.id).count() == 0
    assert e.db.query(AlertDelivery).join(AlertDispatch).filter(AlertDispatch.rule_name == rule.name).count() == 0


def test_deferred_delivery_with_a_connector_violates_the_check(denv):
    e = denv
    rule = _rule(e, "rule", "digest")
    d = _dispatch(e, rule, [(_hi(e), "high", None)])
    e.db.add(AlertDelivery(dispatch_id=d.id, connector_id="c1", outcome="deferred_to_digest", recipient_count=1))
    with pytest.raises(IntegrityError):
        e.db.commit()
    e.db.rollback()
    e.db.add(AlertDelivery(dispatch_id=d.id, connector_id=None, outcome="deferred_to_digest", recipient_count=1))
    e.db.commit()  # and the NULL-connector form is accepted


# ── 2. current_cutoff ────────────────────────────────────────────────────────

def _utc(*a):
    return datetime(*a, tzinfo=timezone.utc)


def test_current_cutoff_before_at_and_after_the_hour():
    assert digest.current_cutoff(_utc(2030, 1, 2, 6, 59, 59), 7) == _utc(2030, 1, 1, 7)
    assert digest.current_cutoff(_utc(2030, 1, 2, 7, 0, 0), 7) == _utc(2030, 1, 2, 7)
    assert digest.current_cutoff(_utc(2030, 1, 2, 23, 59), 7) == _utc(2030, 1, 2, 7)


def test_current_cutoff_hour_zero_and_early_hours():
    assert digest.current_cutoff(_utc(2030, 1, 2, 13, 30), 0) == _utc(2030, 1, 2, 0)
    assert digest.current_cutoff(_utc(2030, 1, 2, 0, 0), 0) == _utc(2030, 1, 2, 0)
    assert digest.current_cutoff(_utc(2030, 1, 2, 2, 59), 3) == _utc(2030, 1, 1, 3)
    assert digest.current_cutoff(_utc(2030, 1, 2, 3, 0), 3) == _utc(2030, 1, 2, 3)


def test_current_cutoff_converts_to_utc_and_rejects_naive():
    plus2 = timezone(timedelta(hours=2))
    assert digest.current_cutoff(datetime(2030, 1, 2, 8, 0, tzinfo=plus2), 7) == _utc(2030, 1, 1, 7)
    with pytest.raises(ValueError):
        digest.current_cutoff(datetime(2030, 1, 2, 8, 0), 7)


# ── 3. due_rule_ids ──────────────────────────────────────────────────────────

def _digest_row(e, rule, period_end, **kw):
    row = Digest(
        rule_id=rule.id, rule_name=rule.name, period_start=period_end - timedelta(days=1),
        period_end=period_end, outcome="empty", **kw,
    )
    e.db.add(row)
    e.db.commit()
    return row


def test_due_rule_ids_modes_enabled_and_watermark(denv):
    e = denv
    db = e.db
    now = _utc(2030, 1, 2, 12, 0)
    app_settings.set_value(db, digest.DIGEST_HOUR_KEY, "7")
    fresh = _rule(e, "fresh", "digest")
    both = _rule(e, "both", "both")
    imm = _rule(e, "imm", "immediate")
    off = _rule(e, "off", "digest", enabled=False)
    caught_up = _rule(e, "caught-up", "digest")
    stale = _rule(e, "stale", "digest")
    _digest_row(e, caught_up, _utc(2030, 1, 2, 7, 0))            # == cutoff: not due
    _digest_row(e, stale, _utc(2030, 1, 2, 6, 59, 59))           # < cutoff: due
    mine = {fresh.id, both.id, imm.id, off.id, caught_up.id, stale.id}

    due = [r for r in digest.due_rule_ids(db, now) if r in mine]

    assert set(due) == {fresh.id, both.id, stale.id}
    created = {r.id: r.created_at for r in (fresh, both, stale)}
    assert due == sorted(due, key=lambda r: (created[r], r)), "ordered by rule creation, then id"


def test_changing_the_hour_changes_due_ness(denv):
    e = denv
    rule = _rule(e, "rule", "digest")
    _digest_row(e, rule, _utc(2030, 1, 2, 2, 0))
    now = _utc(2030, 1, 2, 5, 0)
    app_settings.set_value(e.db, digest.DIGEST_HOUR_KEY, "7")   # cutoff = Jan 1 07:00 -> caught up
    assert rule.id not in digest.due_rule_ids(e.db, now)
    app_settings.set_value(e.db, digest.DIGEST_HOUR_KEY, "3")   # cutoff = Jan 2 03:00 -> due
    assert rule.id in digest.due_rule_ids(e.db, now)
    app_settings.set_value(e.db, digest.DIGEST_HOUR_KEY, "25")  # out of range -> the default
    assert digest.digest_hour(e.db) == digest.DEFAULT_HOUR
    app_settings.set_value(e.db, digest.DIGEST_HOUR_KEY, "soon")
    assert digest.digest_hour(e.db) == digest.DEFAULT_HOUR


def test_claim_refuses_a_rule_that_is_not_due(denv):
    e = denv
    imm = _rule(e, "imm", "immediate")
    off = _rule(e, "off", "digest", enabled=False)
    caught_up = _rule(e, "caught", "digest")
    _digest_row(e, caught_up, e.t1)
    assert digest.claim(e.db, imm.id, e.t1) is None
    assert digest.claim(e.db, off.id, e.t1) is None
    assert digest.claim(e.db, caught_up.id, e.t1) is None
    assert digest.claim(e.db, uuid.uuid4(), e.t1) is None
    assert len(_digests(e, caught_up)) == 1 and _digests(e, imm) == [] and _digests(e, off) == []


def test_settings_helpers_clamp_and_validate(denv):
    db = denv.db
    app_settings.set_value(db, digest.NARRATIVE_CAP_KEY, "-4")
    assert digest.narrative_daily_cap(db) == 0
    app_settings.set_value(db, digest.NARRATIVE_CAP_KEY, "x")
    assert digest.narrative_daily_cap(db) == 0
    for raw, want in [("https://easm.example.com/", "https://easm.example.com"), ("ftp://x", ""),
                      ("javascript:alert(1)", ""), ("", ""), ("  http://easm.example.com/a/ ", "http://easm.example.com/a")]:
        app_settings.set_value(db, digest.BASE_URL_KEY, raw)
        assert digest.app_base_url(db) == want


# ── 4. claim = selection ─────────────────────────────────────────────────────

def test_each_rule_digests_exactly_its_own_events_and_the_next_period_is_empty(denv, monkeypatch):
    e = denv
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    a_rule, b_rule = _rule(e, "ruleA", "digest"), _rule(e, "ruleB", "both")
    a1, a2 = _asset(e, 11), _asset(e, 12)
    fa1 = _finding(e, a1, "fp-a1", title=f"Alpha issue {e.suffix}")
    fa2 = _finding(e, a1, "fp-a2", title=f"Alpha second {e.suffix}")
    fb = _finding(e, a2, "fp-b", title=f"Bravo issue {e.suffix}")
    da = _dispatch(e, a_rule, [(fa1, "high", None), (fa2, "high", None)])
    db_ = _dispatch(e, b_rule, [(fb, "high", None)])

    assert digest.run_due(e.t1) >= 2

    (dg_a,) = _digests(e, a_rule)
    (dg_b,) = _digests(e, b_rule)
    assert _finding_ids(dg_a.body) == {str(fa1.id), str(fa2.id)}
    assert _finding_ids(dg_b.body) == {str(fb.id)}
    assert _digest_id_of(e, da) == dg_a.id and _digest_id_of(e, db_) == dg_b.id
    assert dg_a.outcome == dg_b.outcome == "sent"
    texts = [m["text"] for m in conn.sent if e.suffix in m["text"]]
    assert len(texts) == 2
    a_text = next(t for t in texts if f"Alpha issue {e.suffix}" in t)
    b_text = next(t for t in texts if f"Bravo issue {e.suffix}" in t)
    assert f"Bravo issue {e.suffix}" not in a_text and f"Alpha issue {e.suffix}" not in b_text

    sent_before = len(conn.sent)
    digest.run_due(e.t2)

    first_a, second_a = _digests(e, a_rule)
    assert second_a.outcome == "empty" and second_a.event_count == 0 and second_a.finding_count == 0
    assert second_a.period_start == first_a.period_end
    assert second_a.sent_at is None
    assert [m for m in conn.sent[sent_before:] if e.suffix in m["text"]] == [], "an empty period sends nothing"


def test_run_due_one_failing_rule_does_not_stop_the_others(denv, monkeypatch):
    e = denv
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    r1, r2 = _rule(e, "r1", "digest"), _rule(e, "r2", "digest")
    real = digest.claim

    def flaky(db, rule_id, now):
        if rule_id == r1.id:
            raise RuntimeError("boom")
        return real(db, rule_id, now)

    monkeypatch.setattr(digest, "claim", flaky)
    digest.run_due(e.t1)
    assert _digests(e, r1) == []
    assert len(_digests(e, r2)) == 1, "the second rule was still processed"


def _defer(e, dispatch, recipients=1):
    e.db.add(AlertDelivery(dispatch_id=dispatch.id, connector_id=None, outcome="deferred_to_digest",
                           recipient_count=recipients))
    e.db.commit()


def _mark_sent(e, dispatch):
    e.db.add(AlertDelivery(dispatch_id=dispatch.id, connector_id="c1", outcome="sent", recipient_count=1))
    e.db.commit()


def test_a_rule_switched_back_to_immediate_still_digests_only_its_deferred_alerts(denv, monkeypatch):
    e = denv
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    rule = _rule(e, "rule", "digest")
    held = _hi(e)
    later = _finding(e, _asset(e, 11), "fp-later", severity="high", cve_id="CVE-2024-90102")

    notification_dispatcher._dispatch(e.db, [held.id])           # deferred
    assert conn.sent == [], "precondition: the digest-mode alert was held back"
    rule.mode = "immediate"
    e.db.commit()
    notification_dispatcher._dispatch(e.db, [later.id])          # sent normally
    assert len(conn.sent) == 1 and "CVE-2024-90102" in conn.sent[0]["text"]
    deferred_d, sent_d = e.db.query(AlertDispatch).filter(AlertDispatch.rule_id == rule.id).order_by(
        AlertDispatch.created_at).all()
    assert [dl.outcome for dl in e.db.query(AlertDelivery).filter(AlertDelivery.dispatch_id == deferred_d.id)] == [
        "deferred_to_digest"]

    assert rule.id in digest.due_rule_ids(e.db, e.t1)
    digest.run_due(e.t1)

    (dg,) = _digests(e, rule)
    assert _finding_ids(dg.body) == {str(held.id)}, "only the deferred dispatch's findings"
    assert _digest_id_of(e, deferred_d) == dg.id
    assert _digest_id_of(e, sent_d) is None, "the immediately-sent dispatch is not digested"
    assert dg.outcome == "sent"
    (msg,) = [m for m in conn.sent[1:] if m["subject"].startswith("Constellus digest") and e.suffix in m["subject"]]
    assert "CVE-2024-90101" in msg["text"] and "CVE-2024-90102" not in msg["text"]

    assert rule.id not in digest.due_rule_ids(e.db, e.t2), "nothing deferred is left: no longer due"
    assert digest.claim(e.db, rule.id, e.t2) is None


def test_an_old_deferred_dispatch_is_claimed_but_an_old_sent_one_is_not(denv):
    e = denv
    rule = _rule(e, "rule", "digest")
    prev = _digest_row(e, rule, e.t1)
    asset = _asset(e, 15)
    f_def, f_sent = _finding(e, asset, "fp-def"), _finding(e, asset, "fp-sent")
    old = prev.period_end - timedelta(hours=5)                    # well outside GRACE
    deferred = _dispatch(e, rule, [(f_def, "high", None)], created_at=old)
    _defer(e, deferred)
    sent = _dispatch(e, rule, [(f_sent, "high", None)], created_at=old)
    _mark_sent(e, sent)

    dg = digest.claim(e.db, rule.id, e.t2)

    assert dg is not None and dg.period_start == prev.period_end
    assert _digest_id_of(e, deferred) == dg.id, "never sent, so claimed whatever its age"
    assert _digest_id_of(e, sent) is None, "already sent, outside the grace window: not claimed"
    assert _finding_ids(dg.body) == {str(f_def.id)}


def test_a_disabled_rule_with_deferred_dispatches_is_not_due_and_not_claimed(denv):
    e = denv
    for mode in ("digest", "immediate"):
        rule = _rule(e, f"r-{mode}", mode)
        d = _dispatch(e, rule, [(_finding(e, _asset(e), f"fp-{mode}"), "high", None)],
                      created_at=e.t1 - timedelta(minutes=30))
        _defer(e, d)
        assert rule.id in digest.due_rule_ids(e.db, e.t1), "precondition: due while enabled"
        rule.enabled = False
        e.db.commit()

        assert rule.id not in digest.due_rule_ids(e.db, e.t1)
        assert digest.claim(e.db, rule.id, e.t1) is None
        assert _digests(e, rule) == [] and _digest_id_of(e, d) is None


# ── 5. late commit ───────────────────────────────────────────────────────────

def test_a_dispatch_committed_after_the_cutoff_lands_in_the_next_digest(denv):
    e = denv
    rule = _rule(e, "rule", "digest")
    asset = _asset(e, 13)
    first = digest.claim(e.db, rule.id, e.t1)
    assert first is not None and first.outcome == "empty"
    late_f, old_f = _finding(e, asset, "fp-late"), _finding(e, asset, "fp-old")
    late = _dispatch(e, rule, [(late_f, "high", None)], created_at=first.period_end - timedelta(minutes=10))
    old = _dispatch(e, rule, [(old_f, "high", None)], created_at=first.period_end - timedelta(hours=2))

    second = digest.claim(e.db, rule.id, e.t2)

    assert second is not None and second.period_start == first.period_end
    assert _digest_id_of(e, late) == second.id
    assert _finding_ids(second.body) == {str(late_f.id)}
    assert _digest_id_of(e, old) is None, "outside the one-hour grace window: not claimed"


def test_a_claimed_dispatch_is_never_claimed_twice(denv):
    e = denv
    rule = _rule(e, "rule", "digest")
    f = _finding(e, _asset(e, 14), "fp-1")
    d = _dispatch(e, rule, [(f, "high", None)], created_at=e.t1 - timedelta(minutes=30))
    first = digest.claim(e.db, rule.id, e.t1)
    second = digest.claim(e.db, rule.id, e.t2)
    assert _digest_id_of(e, d) == first.id
    assert first.finding_count == 1 and second.finding_count == 0 and second.outcome == "empty"


# ── 6. first floor ───────────────────────────────────────────────────────────

def test_first_digest_looks_back_24_hours_plus_grace_at_most(denv):
    e = denv
    rule = _rule(e, "rule", "digest", created_at=e.t1 - timedelta(days=3))
    asset = _asset(e, 15)
    f30, f2 = _finding(e, asset, "fp-30h"), _finding(e, asset, "fp-2h")
    d30 = _dispatch(e, rule, [(f30, "high", None)], created_at=e.t1 - timedelta(hours=30))
    d2 = _dispatch(e, rule, [(f2, "high", None)], created_at=e.t1 - timedelta(hours=2))

    dg = digest.claim(e.db, rule.id, e.t1)

    assert dg.period_start == e.t1 - digest.FIRST_FLOOR and dg.period_end == e.t1
    assert _digest_id_of(e, d2) == dg.id
    assert _digest_id_of(e, d30) is None
    assert _finding_ids(dg.body) == {str(f2.id)}


# ── 7. body ──────────────────────────────────────────────────────────────────

def _scenario(e):
    """Cluster (same type/source/fingerprint on two assets), a promotion with a
    band change, a resolved and an excluded finding. 7 events, 6 findings, 3
    assets, 5 new, 2 promotions."""
    a1, a2, a3 = _asset(e, 21), _asset(e, 22), _asset(e, 23)
    shared = f"shared-{e.suffix}"
    c1 = _finding(e, a1, shared, severity="low", title="Shared exposure on one", finding_type="cve")
    c2 = _finding(e, a2, shared, severity="low", title="Shared exposure on two", finding_type="cve")
    f_hi = _finding(e, a1, "fp-hi", severity="high", title="Plain high", cve_id="CVE-2024-90201")
    f_med = _finding(e, a3, "fp-med", severity="medium", title="Plain medium")
    f_res = _finding(e, a3, "fp-res", severity="high", title="Later resolved", state="resolved")
    f_ex = _finding(e, a3, "fp-ex", severity="high", title="Later excluded", verification="rejected_shared_infra")
    rule = _rule(e, "rule", "digest")
    _dispatch(e, rule, [(c1, "high", None), (c2, "high", None), (f_hi, "high", None),
                        (f_med, "medium", None), (f_res, "high", None)])
    _dispatch(e, rule, [
        (c1, "critical", {"previous_band": "elevated", "new_band": "imminent_compromise"}),
        (f_ex, "high", {"previous_band": None, "new_band": "elevated"}),
    ], kind="promotion")
    return rule, dict(c1=c1, c2=c2, f_hi=f_hi, f_med=f_med, f_res=f_res, f_ex=f_ex, a1=a1, a2=a2, a3=a3)


def _item(body, finding):
    return next(i for g in body["groups"] for i in g["items"] if i["finding_id"] == str(finding.id))


def test_body_totals_groups_annotations_and_ordering(denv):
    e = denv
    rule, w = _scenario(e)

    dg = digest.claim(e.db, rule.id, e.t1)
    body = dg.body

    assert body["totals"] == {
        "events": 7, "findings": 6, "assets": 3, "new": 5, "promotions": 2,
        "by_severity": {"critical": 1, "high": 4, "medium": 1, "low": 0, "info": 0},
    }
    assert (dg.event_count, dg.finding_count) == (7, 6)
    assert body["listed_findings"] == 6 and body["omitted_findings"] == 0
    assert body["rule"] == {"id": str(rule.id), "name": rule.name, "severity_threshold": "high"}
    assert body["period"]["end"] == e.t1.isoformat()
    json.dumps(body)  # serialisable

    kinds = [g["kind"] for g in body["groups"]]
    assert kinds == ["cluster", "asset", "asset"]
    cluster, big, small = body["groups"]
    assert cluster["key"] == {"finding_type": "cve", "source": "test", "fingerprint": f"shared-{e.suffix}"}
    assert (cluster["finding_count"], cluster["asset_count"], cluster["max_severity"]) == (2, 2, "critical")
    assert cluster["label"] == "Shared exposure on one", "labelled with the highest-severity member's title"
    assert big["key"] == {"asset_id": str(w["a3"].id)} and big["label"] == w["a3"].value
    assert (big["finding_count"], big["max_severity"]) == (3, "high")
    assert small["key"] == {"asset_id": str(w["a1"].id)} and small["finding_count"] == 1, \
        "within the same severity, the larger group first"

    # the highest snapshot wins over the finding's own (low) severity and over the 'high' new event
    c1 = _item(body, w["c1"])
    assert c1["severity"] == "critical" and c1["kinds"] == ["new", "promotion"]
    assert c1["band_change"] == {"from": "elevated", "to": "imminent_compromise"}
    assert _item(body, w["c2"])["severity"] == "high" and _item(body, w["c2"])["band_change"] is None
    assert _item(body, w["f_hi"])["cve_id"] == "CVE-2024-90201"
    assert _item(body, w["f_hi"])["path"] == f"/findings/{w['f_hi'].id}"

    # state / exclusion annotate, they do not remove
    res, ex = _item(body, w["f_res"]), _item(body, w["f_ex"])
    assert res["state_now"] == "resolved" and res["excluded_now"] is False
    assert ex["excluded_now"] is True and ex["state_now"] == "open" and ex["kinds"] == ["promotion"]
    assert ex["band_change"] == {"from": None, "to": "elevated"}

    # items: severity desc, then asset, title, id
    for g in body["groups"]:
        keys = [(-digest._RANK[i["severity"]], i["asset"], i["title"], i["finding_id"]) for i in g["items"]]
        assert keys == sorted(keys)
    assert [i["title"] for i in big["items"]] == ["Later excluded", "Later resolved", "Plain medium"]


def test_body_list_cap_truncates_items_but_keeps_counts_exact(denv, monkeypatch):
    e = denv
    monkeypatch.setattr(digest, "LIST_CAP", 3)
    rule, w = _scenario(e)

    body = digest.claim(e.db, rule.id, e.t1).body

    assert body["totals"]["findings"] == 6
    assert body["listed_findings"] == 3 and body["omitted_findings"] == 3
    assert body["listed_findings"] + body["omitted_findings"] == body["totals"]["findings"]
    cluster, big, small = body["groups"]
    assert [len(g["items"]) for g in (cluster, big, small)] == [2, 1, 0]
    assert (big["finding_count"], small["finding_count"], cluster["asset_count"]) == (3, 1, 2), "counts stay exact"
    assert small["items"] == [], "a group with no listed items is still present"


def test_empty_body_has_all_severity_keys(denv):
    e = denv
    rule = _rule(e, "rule", "digest")
    dg = digest.claim(e.db, rule.id, e.t1)
    assert dg.outcome == "empty"
    assert dg.body["totals"]["by_severity"] == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    assert dg.body["groups"] == [] and dg.body["listed_findings"] == 0 == dg.body["omitted_findings"]


# ── 8. grounding (unit) ──────────────────────────────────────────────────────

DATA = {
    "totals": {"events": 4, "findings": 3, "assets": 1},
    "groups": [{"label": "web.example.com",
                "items": [{"asset": "web.example.com", "title": "Exposed admin panel", "severity": "high"}]}],
}


def _st(text, *cites):
    return digest.Statement(text=text, cites=[digest.Cite(source_field=p, value=v) for p, v in cites])


def _ground(*statements):
    return digest.ground(digest.NarrativeOut(statements=list(statements)), DATA)


GOOD = _st("3 findings were found on web.example.com.", ("totals.findings", "3"),
           ("groups[0].items[0].asset", "web.example.com"))


def test_ground_keeps_a_statement_whose_cites_numbers_and_hosts_are_grounded():
    narrative, returned, dropped = _ground(GOOD)
    assert (returned, dropped) == (1, 0)
    assert narrative == {
        "statements": [{"text": "3 findings were found on web.example.com.", "cites": [
            {"source_field": "totals.findings", "value": "3"},
            {"source_field": "groups[0].items[0].asset", "value": "web.example.com"}]}],
        "returned": 1, "dropped": 0,
    }


@pytest.mark.parametrize("statement", [
    _st("5 findings were found.", ("totals.findings", "3")),                         # number not in any cite
    _st("Seen on other.example.com.", ("totals.findings", "3")),                     # hostname not in any cite
    _st("Seen on 198.51.100.7.", ("totals.findings", "3")),                          # IPv4 not in any cite
    _st("Seen on 2001:db8::1.", ("totals.findings", "3")),                           # IPv6 not in any cite
    _st("3 findings.", ("totals.nope", "3")),                                        # bad path
    _st("3 findings.", ("totals.findings", "9")),                                    # value not at the path
    _st("3 findings.", ("totals", "3")),                                             # not a leaf
    _st("Three findings."),                                                          # zero cites
    _st("3 findings.", *[("totals.findings", "3")] * 5),                             # too many cites
    _st("This is low priority, 3 findings.", ("totals.findings", "3")),              # de-escalating
    _st("A false positive among 3 findings.", ("totals.findings", "3")),            # de-escalating
    _st("   ", ("totals.findings", "3")),                                            # empty text
], ids=["number", "host", "ipv4", "ipv6", "bad-path", "wrong-value", "container", "no-cites", "many-cites",
        "low-priority", "false-positive", "blank"])
def test_ground_drops(statement):
    narrative, returned, dropped = _ground(statement)
    assert (narrative["statements"], returned, dropped) == ([], 1, 1)


@pytest.mark.parametrize("text, control, title", [
    ("Reset at https://evil.example/reset now.", "Reset at evil.example/reset now.",
     "visit evil.example/reset"),
    ("Details on www.example.com today.", "Details on example.com today.",
     "see www.example.com"),
], ids=["scheme", "www"])
def test_ground_drops_a_statement_containing_a_url_even_if_everything_else_is_grounded(text, control, title):
    data = {"item": {"title": title}}
    cite = ("item.title", title)
    # Control: the same statement without the URL marker is fully grounded and
    # kept, so only the URL check can be what drops the real one.
    kept = digest.ground(digest.NarrativeOut(statements=[_st(control, cite)]), data)
    assert (len(kept[0]["statements"]), kept[2]) == (1, 0)
    narrative, returned, dropped = digest.ground(digest.NarrativeOut(statements=[_st(text, cite)]), data)
    assert (narrative["statements"], returned, dropped) == ([], 1, 1)


def test_ground_matches_hosts_case_insensitively_and_inside_longer_values():
    s = _st("Look at WEB.Example.com now.", ("groups[0].items[0].asset", "web.example.com"))
    assert _ground(s)[2] == 0
    s = _st("Look at example.com now.", ("groups[0].items[0].asset", "web.example.com"))
    assert _ground(s)[2] == 0


def test_ground_caps_statements_at_eight_and_truncates_text():
    many = [GOOD] * 10
    narrative, returned, dropped = _ground(*many)
    assert len(narrative["statements"]) == digest.STATEMENTS_CAP == 8
    assert (returned, dropped) == (10, 2) and narrative["dropped"] == 2
    long = _st("3 " + "x" * 1000, ("totals.findings", "3"))
    assert len(_ground(long)[0]["statements"][0]["text"]) == digest.STATEMENT_CHARS


def test_narrative_input_hides_ids_and_links_but_keeps_everything_else(denv):
    e = denv
    rule, w = _scenario(e)
    body = digest.claim(e.db, rule.id, e.t1).body
    data = digest.narrative_input(body)
    block = json.dumps(data)
    assert '"finding_id"' not in block and '"path"' not in block
    assert "id" not in data["rule"] and data["rule"]["name"] == rule.name
    assert data["totals"] == body["totals"]
    assert "path" in body["groups"][0]["items"][0], "the stored body is untouched"
    assert data["groups"][0]["items"][0]["title"] == body["groups"][0]["items"][0]["title"]


# ── LLM stub ─────────────────────────────────────────────────────────────────

@pytest.fixture
def llm():
    db = SessionLocal()
    try:
        snapshot = _configure_openrouter(db)
    finally:
        db.close()
    installed: list[_Transport] = []

    def install(handler) -> _Transport:
        t = _Transport(handler)
        llmc._transport = t.transport
        installed.append(t)
        return t

    yield install
    llmc._transport = None
    _restore_openrouter(snapshot)


def _data_block(request) -> dict:
    content = json.loads(request.content)["messages"][1]["content"]
    return json.loads(content.split("<data>\n", 1)[1].rsplit("\n</data>", 1)[0])


def _narrative_response(statements):
    return _ok_response(model=NARRATE_PRIMARY, cost=0.001, content=json.dumps({"statements": statements}))


def _scripted(request):
    """One grounded statement built from the DATA the model actually received,
    and one whose number is nowhere in DATA."""
    data = _data_block(request)
    n, a = data["totals"]["findings"], data["totals"]["assets"]
    return _narrative_response([
        {"text": f"{n} findings across {a} assets need review.", "cites": [
            {"source_field": "totals.findings", "value": str(n)}, {"source_field": "totals.assets", "value": str(a)}]},
        {"text": "Also 9999 findings were fixed.", "cites": [{"source_field": "totals.findings", "value": str(n)}]},
    ])


def _simple_digest(e, monkeypatch=None, conns=None, mode="digest", n=1):
    rule = _rule(e, "rule", mode)
    asset = _asset(e)
    fs = [_finding(e, asset, f"fp-{i}", title=f"Digest issue {i} {e.suffix}") for i in range(n)]
    _dispatch(e, rule, [(f, "high", None) for f in fs])
    return rule, fs


# ── 9. narrative end to end ──────────────────────────────────────────────────

def test_a_successful_narrative_is_stored_grounded_and_rendered(denv, llm, monkeypatch):
    e = denv
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    t = llm(lambda request: _scripted(request))
    rule, fs = _simple_digest(e, n=2)

    assert digest.run_due(e.t1) >= 1

    (dg,) = _digests(e, rule)
    assert len(t.requests) == 1
    block = json.loads(t.requests[0].content)["messages"][1]["content"]
    assert "<data>" in block
    for forbidden in ('"finding_id"', '"path"', '"id"'):
        assert forbidden not in block
    assert dg.narrative_status == "succeeded" and dg.narrative_reason is None
    assert dg.model == NARRATE_PRIMARY and dg.ledger_ids
    assert dg.narrative["returned"] == 2 and dg.narrative["dropped"] == 1
    assert [s["text"] for s in dg.narrative["statements"]] == ["2 findings across 1 assets need review."]
    assert dg.outcome == "sent"
    (msg,) = [m for m in conn.sent if e.suffix in m["text"]]
    assert "2 findings across 1 assets need review." in msg["text"]
    assert "9999" not in msg["text"]
    assert "AI summary (each statement is tied to the records below)" in msg["text"]


def test_forced_strict_follows_the_engagements_of_the_assets(denv, llm):
    e = denv
    llm(lambda request: _scripted(request))

    def run(setup):
        rule = _rule(e, f"rule{uuid.uuid4().hex[:4]}", "digest")
        asset = _asset(e)
        setup(asset)
        _dispatch(e, rule, [(_finding(e, asset, "fp-s"), "high", None)])
        dg = digest.claim(e.db, rule.id, e.t1)
        eng, strict = digest.scope_for(e.db, dg)
        digest.narrate(e.db, dg)
        e.db.expire_all()
        dg = e.db.get(Digest, dg.id)
        assert dg.narrative_status == "succeeded", dg.narrative_reason  # the call was reached
        assert dg.forced_strict is strict
        return eng, strict

    assert run(lambda a: None) == (None, True), "no engagement at all"

    def one(a):
        eid = e.world.engagement(EngagementPosture.INTEGRATED.value)
        e.world.target(engagement_id=eid, link_asset=a.id)
        e.one_engagement = eid

    eng, strict = run(one)
    assert (eng, strict) == (e.one_engagement, False)

    def two(a):
        e.world.target(engagement_id=e.world.engagement(EngagementPosture.INTEGRATED.value), link_asset=a.id)
        e.world.target(engagement_id=e.world.engagement(EngagementPosture.INTEGRATED.value), link_asset=a.id)

    assert run(two) == (None, True), "assets spanning two engagements"


def test_scope_for_counts_omitted_findings_too(denv, monkeypatch):
    e = denv
    monkeypatch.setattr(digest, "LIST_CAP", 1)
    rule = _rule(e, "rule", "digest")
    a_in, a_out = _asset(e, 61), _asset(e, 62)
    eid = e.world.engagement(EngagementPosture.INTEGRATED.value)
    e.world.target(engagement_id=eid, link_asset=a_in.id)   # only the first asset has an engagement
    _dispatch(e, rule, [(_finding(e, a_in, "fp-a", severity="critical"), "critical", None),
                        (_finding(e, a_out, "fp-b", severity="high"), "high", None)])
    dg = digest.claim(e.db, rule.id, e.t1)
    assert dg.body["omitted_findings"] == 1
    assert digest.scope_for(e.db, dg) == (None, True), "the omitted finding's asset has no engagement"


# ── 10. the AI never blocks the digest ───────────────────────────────────────

def _run_one(e, monkeypatch):
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    rule, fs = _simple_digest(e)
    digest.run_due(e.t1)
    (dg,) = _digests(e, rule)
    (msg,) = [m for m in conn.sent if e.suffix in m["text"]]
    assert dg.outcome == "sent" and len(conn.sent) >= 1
    assert f"Digest issue 0 {e.suffix}" in msg["text"], "the deterministic body is there"
    return dg, msg


def test_cap_zero_still_sends_and_says_why(denv, llm, monkeypatch):
    app_settings.set_value(denv.db, digest.NARRATIVE_CAP_KEY, "0")
    t = llm(lambda request: _scripted(request))
    dg, msg = _run_one(denv, monkeypatch)
    assert t.requests == []
    assert (dg.narrative_status, dg.narrative_reason) == ("skipped", "AI digest summaries are turned off (cap 0)")
    assert "AI summary unavailable: AI digest summaries are turned off (cap 0)" in msg["text"]


def test_cap_reached_still_sends_and_says_why(denv, llm, monkeypatch):
    e = denv
    app_settings.set_value(e.db, digest.NARRATIVE_CAP_KEY, "1")
    e.db.add(Digest(rule_id=None, rule_name=f"earlier-{e.suffix}", period_start=e.t1 - timedelta(days=1),
                    period_end=e.t1, outcome="sent", narrative_status="succeeded"))
    e.db.commit()
    before = digest.narrative_count_today(e.db)
    assert before >= 1
    app_settings.set_value(e.db, digest.NARRATIVE_CAP_KEY, str(before))
    t = llm(lambda request: _scripted(request))
    dg, msg = _run_one(e, monkeypatch)
    assert t.requests == []
    assert dg.narrative_status == "skipped" and dg.narrative_reason == f"today's AI digest cap ({before}) is reached"
    assert f"AI summary unavailable: today's AI digest cap ({before}) is reached" in msg["text"]


def test_unconfigured_ai_still_sends_and_says_why(denv, monkeypatch):
    assert llmc._transport is None
    dg, msg = _run_one(denv, monkeypatch)
    assert (dg.narrative_status, dg.narrative_reason) == ("skipped", "AI is not configured")
    assert "AI summary unavailable: AI is not configured" in msg["text"]


def test_an_llm_http_500_still_sends_and_says_why(denv, llm, monkeypatch):
    monkeypatch.setattr(llmc, "_sleep", lambda s: None)
    t = llm(lambda request: httpx.Response(500, json={"error": {"message": "upstream down"}}))
    dg, msg = _run_one(denv, monkeypatch)
    assert len(t.requests) >= 1, "the call was attempted"
    assert dg.narrative_status == "failed" and dg.narrative_reason not in (None, "in progress")
    assert f"AI summary unavailable: {dg.narrative_reason}" in msg["text"]
    assert dg.narrative is None and dg.ledger_ids


def test_zero_surviving_statements_still_sends_and_says_why(denv, llm, monkeypatch):
    t = llm(lambda request: _narrative_response([
        {"text": "9999 findings.", "cites": [{"source_field": "totals.findings", "value": "1"}]}]))
    dg, msg = _run_one(denv, monkeypatch)
    assert len(t.requests) == 1
    assert dg.narrative_status == "failed"
    assert dg.narrative_reason == "no AI statement could be tied to its records"
    assert dg.narrative["statements"] == [] and dg.narrative["dropped"] == 1, "kept for audit"
    assert "AI summary unavailable: no AI statement could be tied to its records" in msg["text"]


# ── 11. delivery outcomes ────────────────────────────────────────────────────

def _claimed(e, mode="digest"):
    rule, fs = _simple_digest(e, mode=mode)
    return rule, digest.claim(e.db, rule.id, e.t1)


def test_no_connector_gives_no_channel(denv, monkeypatch):
    e = denv
    _use_connectors(monkeypatch, [])
    rule, dg = _claimed(e)
    digest.send(e.db, dg)
    e.db.expire_all()
    dg = e.db.get(Digest, dg.id)
    assert (dg.outcome, dg.deliveries, dg.attempts) == ("no_channel", [], 1) and dg.sent_at is not None


def test_a_rule_deleted_after_the_claim_gives_no_recipients(denv, monkeypatch):
    e = denv
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    rule, dg = _claimed(e)
    e.db.delete(e.db.get(NotificationRule, rule.id))
    e.db.commit()
    digest.send(e.db, dg)
    e.db.expire_all()
    dg = e.db.get(Digest, dg.id)
    assert dg.rule_id is None and dg.outcome == "no_recipients"
    assert conn.sent == []


def test_a_rule_without_recipients_gives_no_recipients(denv, monkeypatch):
    e = denv
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    rule = _rule(e, "rule", "digest", recipients=())
    dg = digest.claim(e.db, rule.id, e.t1)
    digest.send(e.db, dg)
    e.db.expire_all()
    assert e.db.get(Digest, dg.id).outcome == "no_recipients" and conn.sent == []


def test_one_ok_and_one_raising_connector_is_partial(denv, monkeypatch):
    e = denv
    ok, bad, falsy = _Conn("ok"), _Conn("raise"), _Conn("false")
    _use_connectors(monkeypatch, [("c-ok", ok), ("c-bad", bad), ("c-false", falsy)])
    rule, dg = _claimed(e)
    digest.send(e.db, dg)
    e.db.expire_all()
    dg = e.db.get(Digest, dg.id)
    assert dg.outcome == "partial"
    assert {d["connector_id"]: d["outcome"] for d in dg.deliveries} == {
        "c-ok": "sent", "c-bad": "raised", "c-false": "failed"}
    assert all(d["recipient_count"] == 1 for d in dg.deliveries)
    assert len(ok.sent) == len(bad.sent) == len(falsy.sent) == 1


def test_every_connector_failing_is_failed(denv, monkeypatch):
    e = denv
    _use_connectors(monkeypatch, [("c1", _Conn("raise")), ("c2", _Conn("false"))])
    rule, dg = _claimed(e)
    digest.send(e.db, dg)
    e.db.expire_all()
    assert e.db.get(Digest, dg.id).outcome == "failed"


# ── 12. stale pending ────────────────────────────────────────────────────────

def test_a_stale_pending_digest_is_resent_without_an_ai_call(denv, llm, monkeypatch):
    e = denv
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    t = llm(lambda request: _scripted(request))
    rule, dg = _claimed(e)
    fresh_rule, fresh = _claimed(e)
    e.db.query(Digest).filter(Digest.id == dg.id).update({"created_at": datetime.now(timezone.utc) - timedelta(hours=1)})
    e.db.commit()

    digest.retry_stale(e.db, datetime.now(timezone.utc))

    e.db.expire_all()
    dg, fresh = e.db.get(Digest, dg.id), e.db.get(Digest, fresh.id)
    assert t.requests == []
    assert dg.outcome == "sent" and dg.attempts == 1
    assert (dg.narrative_status, dg.narrative_reason) == ("skipped", "AI summary was not generated (resumed delivery)")
    (msg,) = [m for m in conn.sent if e.suffix in m["text"]]
    assert "AI summary unavailable: AI summary was not generated (resumed delivery)" in msg["text"]
    assert fresh.outcome == "pending" and fresh.attempts == 0, "a digest younger than 30 minutes is left alone"


def test_a_stale_pending_digest_out_of_attempts_is_abandoned(denv, monkeypatch):
    e = denv
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    rule, dg = _claimed(e)
    e.db.query(Digest).filter(Digest.id == dg.id).update(
        {"created_at": datetime.now(timezone.utc) - timedelta(hours=2), "attempts": digest.MAX_ATTEMPTS})
    e.db.commit()
    digest.retry_stale(e.db, datetime.now(timezone.utc))
    e.db.expire_all()
    assert e.db.get(Digest, dg.id).outcome == "abandoned"
    assert conn.sent == []


def test_a_resent_digest_keeps_a_stored_narrative(denv, monkeypatch):
    e = denv
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    rule, dg = _claimed(e)
    e.db.query(Digest).filter(Digest.id == dg.id).update({
        "created_at": datetime.now(timezone.utc) - timedelta(hours=1), "narrative_status": "succeeded",
        "narrative": {"statements": [{"text": "Stored statement.", "cites": []}], "returned": 1, "dropped": 0}})
    e.db.commit()
    digest.retry_stale(e.db, datetime.now(timezone.utc))
    (msg,) = [m for m in conn.sent if e.suffix in m["text"]]
    assert "Stored statement." in msg["text"]


# ── 13. render ───────────────────────────────────────────────────────────────

def _render_body(title='<script>alert(1)</script>'):
    item = {"finding_id": "f1", "asset_id": "a1", "asset": "192.0.2.50", "title": title, "severity": "high",
            "cve_id": "CVE-2024-90301", "kinds": ["new", "promotion"],
            "band_change": {"from": "elevated", "to": "imminent_compromise"}, "state_now": "resolved",
            "excluded_now": True, "path": "/findings/f1"}
    return {
        "rule": {"id": "r", "name": 'Rule <b>"x"</b>', "severity_threshold": "high"},
        "period": {"start": "2030-01-01T00:00:00+00:00", "end": "2030-01-02T00:00:00+00:00"},
        "totals": {"events": 2, "findings": 1, "assets": 1, "new": 1, "promotions": 1,
                   "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}},
        "groups": [{"kind": "asset", "label": "192.0.2.50", "finding_count": 1, "asset_count": 1,
                    "max_severity": "high", "key": {"asset_id": "a1"}, "items": [item]}],
        "listed_findings": 1, "omitted_findings": 4,
    }


def test_render_escapes_html_and_attributes():
    body = _render_body()
    subject, text, html = digest.render(body, "skipped", None, "AI is <not> configured", 'https://easm.example.com/a"b')
    assert "<script>" not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<b>" not in html and "&lt;b&gt;" in html
    assert 'href="https://easm.example.com/a&quot;b/findings/f1"' in html
    assert "AI summary unavailable: AI is &lt;not&gt; configured" in html
    assert subject == 'Constellus digest: 1 finding (Rule <b>"x"</b>)'
    assert "[HIGH] <script>alert(1)</script> — 192.0.2.50 (CVE-2024-90301)" in text
    assert "(promotion: elevated -> imminent_compromise)" in text
    assert "(now resolved)" in text and "(now excluded)" in text
    assert "… and 4 more" in text and "… and 4 more" in html


def test_render_links_are_absolute_only_with_a_base_url():
    body = _render_body("Plain title")
    _s, text, html = digest.render(body, "skipped", None, "off", "https://easm.example.com")
    assert 'href="https://easm.example.com/findings/f1"' in html
    assert "https://easm.example.com/findings/f1" in text
    _s, text, html = digest.render(body, "skipped", None, "off", "")
    assert "href" not in html and "<code>/findings/f1</code>" in html
    assert text.rstrip().splitlines()[-2].endswith("/findings/f1") or "/findings/f1" in text
    assert "http" not in text


def test_render_subject_is_one_line_and_pluralises():
    body = _render_body("t")
    body["rule"]["name"] = "multi\r\nline"
    body["totals"]["findings"] = 2
    subject = digest.render(body, "skipped", None, "x", "")[0]
    assert subject == "Constellus digest: 2 findings (multi line)"


@pytest.mark.parametrize("state, expect", [("resolved", "(now resolved)"), ("suppressed", "(now suppressed)"),
                                           ("open", None)])
def test_render_annotates_the_current_state_unless_open(state, expect):
    body = _render_body("t")
    item = body["groups"][0]["items"][0]
    item.update(state_now=state, excluded_now=False, band_change=None)
    _s, text, html = digest.render(body, "skipped", None, "off", "")
    if expect:
        assert expect in text and expect in html
        assert text.count("(now") == 1
    else:
        assert "(now" not in text and "(now" not in html


def test_render_shows_the_ai_section_only_when_it_succeeded():
    body = _render_body("t")
    narrative = {"statements": [{"text": "Kept <statement>.", "cites": []}], "returned": 1, "dropped": 0}
    _s, text, html = digest.render(body, "succeeded", narrative, None, "")
    assert "AI summary (each statement is tied to the records below)" in text and "Kept <statement>." in text
    assert "Kept &lt;statement&gt;." in html and "unavailable" not in text
    _s, text, _h = digest.render(body, "failed", narrative, "no AI statement could be tied to its records", "")
    assert "Kept <statement>." not in text
    assert "AI summary unavailable: no AI statement could be tied to its records" in text


# ── 14. API ──────────────────────────────────────────────────────────────────

@pytest.fixture
def admin():
    headers, uid = _make_user(UserRole.ADMIN.value)
    yield headers, uid
    _cleanup_user(uid)


def test_rule_mode_create_patch_and_validation(denv, admin):
    e, (h, _uid) = denv, admin
    name = f"api-rule-{e.suffix}"
    r = client.post("/api/notifications/rules", headers=h, json={"name": name, "recipients": ["a@example.com"]})
    assert r.status_code == 201 and r.json()["mode"] == "immediate"
    r = client.post("/api/notifications/rules", headers=h,
                    json={"name": f"{name}-d", "recipients": ["a@example.com"], "mode": "digest"})
    assert r.status_code == 201 and r.json()["mode"] == "digest"
    rid = r.json()["id"]
    assert client.patch(f"/api/notifications/rules/{rid}", headers=h, json={"mode": "both"}).json()["mode"] == "both"
    assert client.patch(f"/api/notifications/rules/{rid}", headers=h, json={"name": f"{name}-e"}).json()["mode"] == "both"
    for bad in ("weekly", "", "DIGESTS"):
        assert client.post("/api/notifications/rules", headers=h, json={
            "name": f"{name}-bad", "recipients": ["a@example.com"], "mode": bad}).status_code == 422
        assert client.patch(f"/api/notifications/rules/{rid}", headers=h, json={"mode": bad}).status_code == 422
    assert client.patch(f"/api/notifications/rules/{rid}", headers=h, json={"mode": "digest"}).json()["mode"] == "digest"
    listed = {r["name"]: r["mode"] for r in client.get("/api/notifications/rules", headers=h).json()}
    assert listed[name] == "immediate" and listed[f"{name}-e"] == "digest"
    assert f"{name}-bad" not in listed


def test_digests_list_is_newest_first_capped_and_admin_only(denv, admin):
    e, (h, _uid) = denv, admin
    now = datetime.now(timezone.utc)
    ids = []
    for i in range(3):
        row = Digest(rule_id=None, rule_name=f"hist{i}-{e.suffix}", period_start=now - timedelta(days=2),
                     period_end=now - timedelta(days=1), outcome="sent", event_count=i, finding_count=i,
                     deliveries=[{"connector_id": "c1", "outcome": "sent", "recipient_count": 1}],
                     created_at=now - timedelta(hours=10 - i), body={"x": i})
        e.db.add(row)
        e.db.commit()
        ids.append(str(row.id))
    r = client.get("/api/notifications/digests?limit=100", headers=h)
    assert r.status_code == 200
    mine = [d for d in r.json() if e.suffix in d["rule_name"]]
    assert [d["id"] for d in mine] == list(reversed(ids))
    assert set(mine[0]) == {"id", "kind", "rule_id", "rule_name", "period_start", "period_end", "event_count",
                            "finding_count", "outcome", "narrative_status", "narrative_reason", "deliveries",
                            "created_at", "sent_at"}
    assert len(client.get("/api/notifications/digests?limit=1", headers=h).json()) == 1
    for bad in (0, 101):
        assert client.get(f"/api/notifications/digests?limit={bad}", headers=h).status_code == 422
    vh, vuid = _make_user(UserRole.VIEWER.value)
    try:
        assert client.get("/api/notifications/digests", headers=vh).status_code == 403
        assert client.get(f"/api/notifications/digests/{ids[0]}", headers=vh).status_code == 403
    finally:
        _cleanup_user(vuid)


def test_digest_detail_includes_body_and_narrative_and_404s(denv, admin):
    e, (h, _uid) = denv, admin
    rule = _rule(e, "rule", "digest")
    dg = digest.claim(e.db, rule.id, e.t1)
    r = client.get(f"/api/notifications/digests/{dg.id}", headers=h)
    assert r.status_code == 200
    j = r.json()
    assert j["body"]["totals"]["events"] == 0 and j["narrative"] is None and j["outcome"] == "empty"
    assert client.get(f"/api/notifications/digests/{uuid.uuid4()}", headers=h).status_code == 404


def test_digest_settings_get_put_validation_and_audit(denv, admin):
    e, (h, uid) = denv, admin
    g = client.get("/api/notifications/digest-settings", headers=h)
    assert g.status_code == 200 and set(g.json()) == {"digest_hour_utc", "app_base_url"}
    assert client.put("/api/notifications/digest-settings", headers=h, json={"digest_hour_utc": 24}).status_code == 422
    assert client.put("/api/notifications/digest-settings", headers=h, json={"digest_hour_utc": -1}).status_code == 422
    for bad in ("javascript:alert(1)", "ftp://example.com", "https://", "https://exa mple.com",
                "https://easm.example.com/?q=1", "https://easm.example.com/#x", "https://" + "a" * 200 + ".com",
                "https://user@evil.example", "https://user:pw@evil.example/a", "http://@evil.example"):
        assert client.put("/api/notifications/digest-settings", headers=h,
                          json={"app_base_url": bad}).status_code == 422, bad
    r = client.put("/api/notifications/digest-settings", headers=h, json={"digest_hour_utc": 2})
    assert r.status_code == 200 and r.json()["digest_hour_utc"] == 2
    r = client.put("/api/notifications/digest-settings", headers=h,
                   json={"digest_hour_utc": 3, "app_base_url": "https://easm.example.com/"})
    assert r.status_code == 200
    assert r.json() == {"digest_hour_utc": 3, "app_base_url": "https://easm.example.com"}
    assert client.get("/api/notifications/digest-settings", headers=h).json() == r.json()
    e.db.expire_all()
    assert app_settings.get(e.db, digest.BASE_URL_KEY) == "https://easm.example.com"
    r = client.put("/api/notifications/digest-settings", headers=h, json={"app_base_url": ""})
    assert r.json()["app_base_url"] == ""
    row = e.db.query(AuditLog).filter(AuditLog.user_id == uid).order_by(AuditLog.occurred_at.desc()).first()
    assert row is not None and row.detail["changes"]["app_base_url"] == {"from": "https://easm.example.com", "to": ""}
    earlier = [
        r.detail.get("changes", {}) for r in e.db.query(AuditLog).filter(AuditLog.user_id == uid).all()
    ]
    assert {"from": 2, "to": 3} in [c.get("digest_hour_utc") for c in earlier]
    vh, vuid = _make_user(UserRole.VIEWER.value)
    try:
        assert client.put("/api/notifications/digest-settings", headers=vh, json={"digest_hour_utc": 5}).status_code == 403
    finally:
        _cleanup_user(vuid)


def test_llm_digest_settings_bounds_and_status_field(denv, admin):
    e, (h, uid) = denv, admin
    for bad in (-1, 1001, "lots"):
        assert client.put("/api/llm/digest-settings", headers=h, json={"narrative_daily_cap": bad}).status_code == 422
    r = client.put("/api/llm/digest-settings", headers=h, json={"narrative_daily_cap": 5})
    assert r.status_code == 200 and r.json()["daily_cap"] == 5
    s = client.get("/api/llm/status", headers=h).json()
    assert s["digest_narratives"]["daily_cap"] == 5 and s["digest_narratives"]["today"] >= 0
    e.db.expire_all()
    assert digest.narrative_daily_cap(e.db) == 5
    row = e.db.query(AuditLog).filter(AuditLog.user_id == uid).order_by(AuditLog.occurred_at.desc()).first()
    assert row.detail["changes"]["digest_narrative_daily_cap"]["to"] == 5
    ih, iuid = _make_user(UserRole.INTEGRATION_ADMIN.value)
    try:
        assert client.put("/api/llm/digest-settings", headers=ih, json={"narrative_daily_cap": 9}).status_code == 403
    finally:
        _cleanup_user(iuid)
    e.db.expire_all()
    assert digest.narrative_daily_cap(e.db) == 5


# ── scheduler ────────────────────────────────────────────────────────────────

def test_scheduler_registers_an_hourly_job_that_runs_the_digests(monkeypatch):
    jobs = []

    class _Sched:
        def add_job(self, func, **kw):
            jobs.append((func, kw))

    monkeypatch.setattr(scheduler, "_scheduler", _Sched())
    scheduler._register_alert_digests()
    (func, kw), = jobs
    assert kw["id"] == "alert_digests" and kw["name"] == "Alert digests (hourly check)"
    assert kw["replace_existing"] is True and kw["coalesce"] is True and kw["max_instances"] == 1
    trigger = kw["trigger"]
    fields = {f.name: str(f) for f in trigger.fields}
    assert fields["minute"] == "5" and fields["hour"] == "*"
    called = []
    monkeypatch.setattr(digest, "run_due", lambda: called.append(1))
    func()
    assert called == [1]
