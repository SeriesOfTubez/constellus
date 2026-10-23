"""Alert-event store + finding clusters (planning#233 slice 1).

Covers: the dispatcher records what each rule selected BEFORE any send (even
with no channel), records per-connector outcomes, never lets bookkeeping block
alerting; the alert-history API; the cluster API (route order, read-scope
applied before grouping, state/exclusion rules).

Run:  backend/scripts/test.ps1 app/tests/test_alert_events.py
Synthetic values only.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import findings as findings_api
from app.api import notifications as notifications_api
from app.api.deps import get_current_user
from app.core.database import SessionLocal, get_db
from app.models.alert_event import AlertDelivery, AlertDispatch, AlertEvent
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.finding_canonical import FindingCanonical
from app.models.notification_rule import NotificationRule
from app.models.user import User, UserRole
from app.services import notification_dispatcher, read_scope, score_history
from app.tests._users import user_with


# ── helpers ──────────────────────────────────────────────────────────────

def _mk_asset(db, value: str, estate: str | None = "claimed_ours") -> AssetCanonical:
    now = datetime.now(timezone.utc)
    row = AssetCanonical(
        id=uuid.uuid4(), asset_type="ip_address", value=value,
        first_seen_at=now, last_seen_at=now, ignored=False, tags=[],
    )
    db.add(row)
    db.commit()
    if estate is not None:
        db.add(AssetState(
            asset_canonical_id=row.id, estate=estate, open_ports=[],
            attributes={}, projected_at=now,
        ))
        db.commit()
    db.refresh(row)
    return row


def _mk_finding(
    db, asset_id, fingerprint: str, *, severity="high", category="vulnerability",
    title=None, cve_id=None, state="open", verification=None,
    finding_type="cve", source="test", last_seen_at=None,
) -> FindingCanonical:
    now = datetime.now(timezone.utc)
    row = FindingCanonical(
        id=uuid.uuid4(), asset_canonical_id=asset_id, finding_type=finding_type,
        source=source, fingerprint=fingerprint, severity=severity,
        title=title or f"Test finding {fingerprint}", state=state, category=category,
        cve_id=cve_id, verification=verification,
        first_seen_at=now, last_seen_at=last_seen_at or now, detail={}, tags=[],
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _mk_rule(db, name, *, threshold="high", categories=None, recipients=("alerts@example.com",)):
    rule = NotificationRule(
        id=uuid.uuid4(), name=name, enabled=True, severity_threshold=threshold,
        categories=list(categories or []), recipients=list(recipients),
    )
    db.add(rule)
    db.commit()
    return rule


class _Conn:
    """Connector double. `mode` is "ok" | "false" | "raise"."""

    def __init__(self, mode="ok"):
        self.mode = mode
        self.sent: list[dict] = []

    def send(self, subject, body_text, recipients, config, body_html=None):
        self.sent.append({"subject": subject, "text": body_text, "recipients": list(recipients)})
        if self.mode == "raise":
            raise RuntimeError("boom")
        return self.mode == "ok"


def _use_connectors(monkeypatch, conns):
    monkeypatch.setattr(
        notification_dispatcher, "_enabled_notification_connectors",
        lambda db: [(cid, c, {}) for cid, c in conns],
    )


@pytest.fixture
def env():
    """A session plus a unique suffix; everything created with the suffix in
    its name/value is removed afterwards (dispatches first: rule deletion only
    NULLs their rule_id, it does not delete them)."""
    suffix = uuid.uuid4().hex[:10]
    db = SessionLocal()
    try:
        yield db, suffix
    finally:
        db.rollback()
        db.query(AlertDispatch).filter(AlertDispatch.rule_name.like(f"%{suffix}%")).delete(synchronize_session=False)
        db.query(NotificationRule).filter(NotificationRule.name.like(f"%{suffix}%")).delete(synchronize_session=False)
        ids = [r[0] for r in db.query(AssetCanonical.id).filter(AssetCanonical.value.like(f"%{suffix}%")).all()]
        if ids:
            db.query(FindingCanonical).filter(FindingCanonical.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
            db.query(AssetState).filter(AssetState.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
            db.query(AssetCanonical).filter(AssetCanonical.id.in_(ids)).delete(synchronize_session=False)
        db.commit()
        db.close()


def _dispatches(db, suffix):
    db.expire_all()
    return (
        db.query(AlertDispatch).filter(AlertDispatch.rule_name.like(f"%{suffix}%"))
        .order_by(AlertDispatch.created_at, AlertDispatch.id).all()
    )


def _events(db, dispatch_id):
    return db.query(AlertEvent).filter(AlertEvent.dispatch_id == dispatch_id).all()


def _deliveries(db, dispatch_id):
    return db.query(AlertDelivery).filter(AlertDelivery.dispatch_id == dispatch_id).all()


def _high_and_low(db, suffix):
    asset = _mk_asset(db, f"192.0.2.10-{suffix}")
    hi = _mk_finding(db, asset.id, "fp-hi", severity="high", cve_id="CVE-2024-90101")
    lo = _mk_finding(db, asset.id, "fp-lo", severity="low", cve_id="CVE-2024-90102")
    return hi, lo


# ── dispatcher ───────────────────────────────────────────────────────────

def test_no_channel_still_records(env, monkeypatch):
    db, suffix = env
    _use_connectors(monkeypatch, [])
    rule = _mk_rule(db, f"rule-{suffix}")
    hi, lo = _high_and_low(db, suffix)

    notification_dispatcher._dispatch(db, [hi.id, lo.id])

    ds = _dispatches(db, suffix)
    assert len(ds) == 1
    assert ds[0].kind == "new" and ds[0].rule_name == f"rule-{suffix}" and ds[0].rule_id == rule.id
    evs = _events(db, ds[0].id)
    assert [(e.finding_id, e.severity) for e in evs] == [(hi.id, "high")]
    dl = _deliveries(db, ds[0].id)
    assert len(dl) == 1
    assert dl[0].outcome == "no_channel" and dl[0].connector_id is None and dl[0].recipient_count == 0


def test_sent_records_delivery_and_connector_receives(env, monkeypatch):
    db, suffix = env
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("conn-ok", conn)])
    _mk_rule(db, f"rule-{suffix}", recipients=("a@example.com", "b@example.com"))
    hi, lo = _high_and_low(db, suffix)

    notification_dispatcher._dispatch(db, [hi.id, lo.id])

    assert len(conn.sent) == 1, "the send must have been reached"
    assert "CVE-2024-90101" in conn.sent[0]["text"]
    assert "CVE-2024-90102" not in conn.sent[0]["text"]
    (d,) = _dispatches(db, suffix)
    (dl,) = _deliveries(db, d.id)
    assert (dl.connector_id, dl.outcome, dl.recipient_count) == ("conn-ok", "sent", 2)


def test_failed_and_raised_and_next_connector_still_sends(env, monkeypatch):
    db, suffix = env
    c_false, c_raise, c_ok = _Conn("false"), _Conn("raise"), _Conn("ok")
    _use_connectors(monkeypatch, [("c-false", c_false), ("c-raise", c_raise), ("c-ok", c_ok)])
    _mk_rule(db, f"rule-{suffix}")
    hi, lo = _high_and_low(db, suffix)

    notification_dispatcher._dispatch(db, [hi.id, lo.id])

    assert len(c_false.sent) == len(c_raise.sent) == len(c_ok.sent) == 1
    (d,) = _dispatches(db, suffix)
    outcomes = {dl.connector_id: dl.outcome for dl in _deliveries(db, d.id)}
    assert outcomes == {"c-false": "failed", "c-raise": "raised", "c-ok": "sent"}


def test_no_recipients_recorded_and_other_rule_still_sends(env, monkeypatch):
    db, suffix = env
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("conn-ok", conn)])
    _mk_rule(db, f"norecip-{suffix}", recipients=())
    _mk_rule(db, f"withrecip-{suffix}", recipients=("a@example.com",))
    hi, lo = _high_and_low(db, suffix)

    notification_dispatcher._dispatch(db, [hi.id, lo.id])

    by_name = {d.rule_name: d for d in _dispatches(db, suffix)}
    assert set(by_name) == {f"norecip-{suffix}", f"withrecip-{suffix}"}
    nr = by_name[f"norecip-{suffix}"]
    assert [e.finding_id for e in _events(db, nr.id)] == [hi.id]
    (dl,) = _deliveries(db, nr.id)
    assert (dl.outcome, dl.connector_id, dl.recipient_count) == ("no_recipients", None, 0)
    # The other rule DID send (the loop was reached past the empty-recipient rule).
    assert len(conn.sent) == 1 and conn.sent[0]["recipients"] == ["a@example.com"]
    (dl2,) = _deliveries(db, by_name[f"withrecip-{suffix}"].id)
    assert dl2.outcome == "sent"


def test_selection_equals_rule_match(env, monkeypatch):
    db, suffix = env
    _use_connectors(monkeypatch, [])
    r_high = _mk_rule(db, f"high-{suffix}", threshold="high")
    r_med = _mk_rule(db, f"med-{suffix}", threshold="medium", categories=["exposure"])
    asset = _mk_asset(db, f"192.0.2.20-{suffix}")
    specs = [
        ("critical", "vulnerability"), ("high", "exposure"), ("medium", "exposure"),
        ("medium", "vulnerability"), ("low", "exposure"), ("info", "vulnerability"),
    ]
    fs = [
        _mk_finding(db, asset.id, f"fp-{i}", severity=sev, category=cat)
        for i, (sev, cat) in enumerate(specs)
    ]

    notification_dispatcher._dispatch(db, [f.id for f in fs])

    by_name = {d.rule_name: d for d in _dispatches(db, suffix)}
    assert len(by_name) == 2
    for rule in (r_high, r_med):
        db.refresh(rule)
        expected = {f.id for f in fs if notification_dispatcher._rule_matches(rule, f)}
        assert expected, "the fixture must give every rule something to select"
        got = {e.finding_id for e in _events(db, by_name[rule.name].id)}
        assert got == expected


def test_promotion_path_records_detail(env, monkeypatch):
    db, suffix = env
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("conn-ok", conn)])
    _mk_rule(db, f"rule-{suffix}")
    hi, _lo = _high_and_low(db, suffix)
    promo = score_history.Promotion(
        finding_canonical_id=hi.id, asset_canonical_id=hi.asset_canonical_id,
        previous_band="elevated", new_band="high",
        previous_score=30, new_score=60, velocity_started=True,
    )

    notification_dispatcher._dispatch_promotions(db, [promo])

    (d,) = _dispatches(db, suffix)
    assert d.kind == "promotion"
    (e,) = _events(db, d.id)
    assert e.finding_id == hi.id
    assert e.detail == {
        "previous_band": "elevated", "new_band": "high",
        "previous_score": 30, "new_score": 60, "velocity_started": True,
    }
    assert len(conn.sent) == 1
    (dl,) = _deliveries(db, d.id)
    assert dl.outcome == "sent"


def test_excluded_and_not_ours_never_recorded(env, monkeypatch):
    db, suffix = env
    _use_connectors(monkeypatch, [])
    _mk_rule(db, f"rule-{suffix}")
    ours = _mk_asset(db, f"192.0.2.30-{suffix}", estate="claimed_ours")
    theirs = _mk_asset(db, f"192.0.2.31-{suffix}", estate="not_ours")
    f_ok = _mk_finding(db, ours.id, "fp-ok")
    f_excl = _mk_finding(db, ours.id, "fp-excl", verification="rejected_shared_infra")
    f_theirs = _mk_finding(db, theirs.id, "fp-theirs")
    assert "rejected_shared_infra" in notification_dispatcher.EXCLUDED_VERIFICATIONS

    notification_dispatcher._dispatch(db, [f_ok.id, f_excl.id, f_theirs.id])

    (d,) = _dispatches(db, suffix)
    assert [e.finding_id for e in _events(db, d.id)] == [f_ok.id]


def test_bookkeeping_failure_still_sends(env, monkeypatch):
    db, suffix = env
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("conn-ok", conn)])
    _mk_rule(db, f"rule-{suffix}")
    hi, lo = _high_and_low(db, suffix)

    def _boom(self, *a, **k):
        raise RuntimeError("bookkeeping broke")

    monkeypatch.setattr(AlertEvent, "__init__", _boom)

    notification_dispatcher._dispatch(db, [hi.id, lo.id])

    assert len(conn.sent) == 1, "alerting must not depend on bookkeeping"
    assert "CVE-2024-90101" in conn.sent[0]["text"]
    assert _dispatches(db, suffix) == [], "no partial dispatch row may survive"
    assert db.query(AlertDelivery).count() >= 0  # session usable after the rollback
    assert db.query(NotificationRule).filter(NotificationRule.name == f"rule-{suffix}").count() == 1


def test_send_needs_no_database_once_recording_failed(env, monkeypatch):
    """The recording commit (or its rollback) expires every loaded rule and
    finding. If the send re-read them, a database that went away during
    recording would block alerting too. Here the database refuses every
    statement from the moment recording fails; the send must still go out
    with the right content. (`_dispatch` and `_dispatch_promotions` share
    the one helper, so one path covers both.)"""
    from sqlalchemy import event

    from app.core.database import engine

    db, suffix = env
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("conn-ok", conn)])
    _mk_rule(db, f"rule-{suffix}")
    hi, lo = _high_and_low(db, suffix)
    hi_id, lo_id = hi.id, lo.id

    down = {"on": False, "refused": 0}

    def _refuse(conn_, cursor, statement, params, context, executemany):
        if down["on"]:
            down["refused"] += 1
            raise RuntimeError("database went away")

    def _boom(self, *a, **k):
        down["on"] = True
        raise RuntimeError("bookkeeping broke")

    monkeypatch.setattr(AlertEvent, "__init__", _boom)
    event.listen(engine, "before_cursor_execute", _refuse)
    try:
        notification_dispatcher._dispatch(db, [hi_id, lo_id])
        assert down["on"], "precondition: recording must have been reached and failed"
        assert len(conn.sent) == 1, "the send must not need the database"
        assert "CVE-2024-90101" in conn.sent[0]["text"]

    finally:
        event.remove(engine, "before_cursor_execute", _refuse)
        down["on"] = False
    db.rollback()
    assert _dispatches(db, suffix) == [], "no partial dispatch row may survive"


def test_rule_deletion_keeps_history(env, monkeypatch):
    db, suffix = env
    _use_connectors(monkeypatch, [])
    rule = _mk_rule(db, f"rule-{suffix}")
    hi, lo = _high_and_low(db, suffix)
    notification_dispatcher._dispatch(db, [hi.id, lo.id])
    (d,) = _dispatches(db, suffix)
    assert d.rule_id == rule.id

    db.delete(rule)
    db.commit()

    (d,) = _dispatches(db, suffix)
    assert d.rule_id is None and d.rule_name == f"rule-{suffix}"
    assert len(_events(db, d.id)) == 1


# ── APIs ─────────────────────────────────────────────────────────────────

def _client(role: UserRole) -> TestClient:
    app = FastAPI()
    app.include_router(notifications_api.router, prefix="/api/notifications")
    app.include_router(findings_api.router, prefix="/api/findings")

    def _db():
        s = SessionLocal()
        try:
            yield s
        finally:
            s.close()

    user = user_with(
        role.value, id=uuid.uuid4(), email=f"alerts-test-{role.value}@example.invalid",
        full_name="t", is_active=True,
    )
    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_current_user] = lambda: user
    return TestClient(app)


def test_alerts_api_newest_first_capped_events_and_admin_only(env):
    db, suffix = env
    asset = _mk_asset(db, f"192.0.2.40-{suffix}")
    sevs = ["info", "low", "medium", "medium", "high", "high", "critical"]
    fs = [
        _mk_finding(db, asset.id, f"fp-{i}", severity=s, title=f"T{i}-{s}")
        for i, s in enumerate(sevs)
    ]
    now = datetime.now(timezone.utc)
    old = AlertDispatch(rule_name=f"old-{suffix}", kind="new", created_at=now - timedelta(hours=2))
    new = AlertDispatch(rule_name=f"new-{suffix}", kind="promotion", created_at=now - timedelta(hours=1))
    db.add_all([old, new])
    db.flush()
    db.add_all([AlertEvent(dispatch_id=old.id, finding_id=f.id, severity=f.severity) for f in fs])
    db.add(AlertEvent(dispatch_id=new.id, finding_id=fs[0].id, severity="info", detail={"new_band": "high"}))
    db.add(AlertDelivery(dispatch_id=old.id, connector_id="conn-ok", outcome="sent", recipient_count=2))
    db.add(AlertDelivery(dispatch_id=new.id, connector_id=None, outcome="no_channel", recipient_count=0))
    db.commit()

    r = _client(UserRole.ADMIN).get("/api/notifications/alerts?limit=200")
    assert r.status_code == 200
    mine = [d for d in r.json() if suffix in d["rule_name"]]
    assert [d["rule_name"] for d in mine] == [f"new-{suffix}", f"old-{suffix}"]
    n, o = mine
    assert n["kind"] == "promotion" and n["event_count"] == 1
    assert n["events"][0]["detail"] == {"new_band": "high"}
    assert n["events"][0]["asset_value"] == f"192.0.2.40-{suffix}"
    assert n["deliveries"] == [{"connector_id": None, "outcome": "no_channel", "recipient_count": 0}]
    assert o["event_count"] == 7 and len(o["events"]) == 5
    assert [e["severity"] for e in o["events"]] == ["critical", "high", "high", "medium", "medium"]
    assert [e["title"] for e in o["events"][1:3]] == sorted(e["title"] for e in o["events"][1:3])
    assert o["deliveries"] == [{"connector_id": "conn-ok", "outcome": "sent", "recipient_count": 2}]

    assert _client(UserRole.INTEGRATION_ADMIN).get("/api/notifications/alerts").status_code == 200
    for role in (r_ for r_ in UserRole if r_ not in (UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)):
        assert _client(role).get("/api/notifications/alerts").status_code == 403, role
    assert _client(UserRole.ADMIN).get("/api/notifications/alerts?limit=0").status_code == 422
    assert _client(UserRole.ADMIN).get("/api/notifications/alerts?limit=201").status_code == 422


def _cluster(client, suffix, fp, state="open"):
    r = client.get("/api/findings/clusters", params={"state": state})
    assert r.status_code == 200, r.text  # also proves /clusters is not shadowed by /{finding_id}
    return [c for c in r.json() if c["fingerprint"] == fp]


def test_clusters_api(env, monkeypatch):
    db, suffix = env
    a1, a2, a3, a4, a5 = (_mk_asset(db, f"cl{i}-{suffix}.example.com", estate=None) for i in range(5))
    fp = f"cl: key {suffix}"  # colon + space on purpose
    t0 = datetime.now(timezone.utc)
    m1 = _mk_finding(db, a1.id, fp, severity="high", title="T-high-old", cve_id="CVE-2024-90201",
                     last_seen_at=t0 - timedelta(days=2))
    m2 = _mk_finding(db, a2.id, fp, severity="high", title="T-high-new", cve_id="CVE-2024-90201",
                     last_seen_at=t0)
    m3 = _mk_finding(db, a3.id, fp, severity="medium", title="T-medium", cve_id="CVE-2024-90201")
    _mk_finding(db, a4.id, fp, severity="critical", verification="rejected_shared_infra")  # excluded
    _mk_finding(db, a5.id, fp, severity="critical", state="resolved")  # not open
    # mixed-cve cluster
    fp_mixed = f"mixed-{suffix}"
    _mk_finding(db, a1.id, fp_mixed, severity="low", cve_id="CVE-2024-90202")
    _mk_finding(db, a2.id, fp_mixed, severity="low", cve_id=None)
    # single-asset key: must not appear
    fp_single = f"single-{suffix}"
    _mk_finding(db, a1.id, fp_single, severity="critical")
    _mk_finding(db, a1.id, fp_single, severity="critical", finding_type="other")

    client = _client(UserRole.VIEWER)

    (c,) = _cluster(client, suffix, fp)
    assert c["finding_count"] == 3 and c["asset_count"] == 3
    assert c["max_severity"] == "high"
    assert c["title"] == "T-high-new"
    assert c["cve_id"] == "CVE-2024-90201"
    assert c["finding_type"] == "cve" and c["source"] == "test"
    assert set(c["member_ids"]) == {str(m1.id), str(m2.id), str(m3.id)}
    (mx,) = _cluster(client, suffix, fp_mixed)
    assert mx["cve_id"] is None and mx["asset_count"] == 2 and mx["max_severity"] == "low"
    assert _cluster(client, suffix, fp_single) == []

    # state=all: the resolved member (a5) now counts; the excluded one (a4)
    # still does not, the same default exclusion list_findings keeps.
    (ca,) = _cluster(client, suffix, fp, state="all")
    assert ca["asset_count"] == 4 and ca["finding_count"] == 4
    assert ca["max_severity"] == "critical"
    # No state sent = the route's default (open), not "all".
    r = client.get("/api/findings/clusters")
    assert [x["asset_count"] for x in r.json() if x["fingerprint"] == fp] == [3]

    r = client.get("/api/findings/clusters/members", params={
        "finding_type": "cve", "source": "test", "fingerprint": fp,
    })
    assert r.status_code == 200, r.text
    assert {m["id"] for m in r.json()} == {str(m1.id), str(m2.id), str(m3.id)}
    assert client.get("/api/findings/clusters/members", params={"finding_type": "cve"}).status_code == 422

    # Read-scope is applied BEFORE grouping: hiding one asset drops the count.
    monkeypatch.setattr(
        read_scope, "finding_clause",
        lambda user, finding, asset: asset.id != a3.id,
    )
    (c2,) = _cluster(client, suffix, fp)
    assert c2["asset_count"] == 2 and c2["finding_count"] == 2
    assert set(c2["member_ids"]) == {str(m1.id), str(m2.id)}
    r = client.get("/api/findings/clusters/members", params={
        "finding_type": "cve", "source": "test", "fingerprint": fp,
    })
    assert {m["id"] for m in r.json()} == {str(m1.id), str(m2.id)}

    # ...and the group disappears when it falls to a single asset.
    monkeypatch.setattr(
        read_scope, "finding_clause",
        lambda user, finding, asset: ~asset.id.in_([a2.id, a3.id]),
    )
    assert _cluster(client, suffix, fp) == []
