"""Coverage for planning#233 slice 2b: AI write-ups for cross-asset finding
clusters (`app.services.cluster_writeup`, migration 0081, the
`/findings/clusters/ai-writeup` routes, the LLM settings, the scan hook and the
digest embed).

The LLM is scripted on `llm_connector._transport` and assertions read what the
TRANSPORT received. Synthetic rows only (`fabrikam.com` names, addresses from
`_docaddr.alloc()` via `_World`). Every row is deleted afterwards.

Run:  backend/scripts/test.sh app/tests/test_cluster_writeup.py
"""

import json
import pathlib
import re
import typing
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

from app.api import llm as llm_api
from app.core.config import settings
from app.core.database import SessionLocal
from app.main import app
from app.models.audit import AuditLog
from app.models.cluster_ai_writeup import ClusterAiWriteup
from app.models.engagement import EngagementPosture
from app.models.finding_canonical import FindingCanonical
from app.models.llm_call import LlmCall
from app.models.user import UserRole
from app.services import app_settings, digest, read_scope
from app.services import cluster_writeup as cw
from app.services import llm_connector as llmc
from app.tests.test_alert_events import _Conn, _use_connectors
from app.tests.test_digests import (
    _asset as d_asset, _digests, _dispatch, _finding as d_finding, _rule, _scripted, denv,  # noqa: F401
)
from app.tests.test_edgar_ingest_api import _cleanup_user, _make_user
from app.tests.test_finding_writeup import (  # noqa: F401
    NARRATE_PRIMARY, _run_scan_touching, _World, admin, llm, permissive, world,
)
from app.tests.test_llm_connector import (
    _ok_response, _restore_app_setting, _snapshot_app_setting,
)

client = TestClient(app)
URL = "/api/findings/clusters/ai-writeup"


# ── fixtures and helpers ─────────────────────────────────────────────────────

@pytest.fixture
def cluster(world):
    """A unique cluster key; its write-up rows and ledger rows are removed."""
    key = cw.Key("cve", "test", f"cw-{uuid.uuid4().hex[:12]}")
    yield key
    _purge(f"{key.fingerprint}%")


def _purge(pattern: str) -> None:
    db = SessionLocal()
    try:
        ids = [i for (i,) in db.query(ClusterAiWriteup.id).filter(ClusterAiWriteup.fingerprint.like(pattern))]
        if ids:
            db.query(LlmCall).filter(LlmCall.task.in_([cw.task_label(i) for i in ids])).delete(
                synchronize_session=False)
            db.query(ClusterAiWriteup).filter(ClusterAiWriteup.id.in_(ids)).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _member(world, key, asset_id=None, *, severity="high", title="Exposed admin panel", state="open",
            verification=None, cve="CVE-2099-0001", risk=50, asset_value=None):
    """One finding of `key` on a (new) asset. Returns (finding_id, asset_id)."""
    if asset_id is None:
        # DNS names, not addresses: the shared `_docaddr` pool is small and other files need it.
        asset_id = world.asset(
            asset_type="dns_record", value=asset_value or f"h-{uuid.uuid4().hex[:10]}.fabrikam.com",
            record_type="A")
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        f = FindingCanonical(
            id=uuid.uuid4(), asset_canonical_id=asset_id, finding_type=key.finding_type, source=key.source,
            fingerprint=key.fingerprint, severity=severity, title=title, state=state, category="vulnerability",
            cve_id=cve, verification=verification, risk_score=risk, epss_score=0.9712, kev=False,
            first_seen_at=now, last_seen_at=now, detail={}, tags=[],
        )
        db.add(f)
        db.commit()
        return f.id, asset_id
    finally:
        db.close()


def _cluster(world, key, n=2, **kw):
    return [_member(world, key, **kw) for _ in range(n)]


def _answer(summary="The same exposure is repeated across several assets.", context=None, note=None):
    return _ok_response(model=NARRATE_PRIMARY, cost=0.001, content=json.dumps({
        "summary": summary,
        "context": context if context is not None else [
            {"statement": "It is a CVE finding.", "source_field": "cluster.finding_type", "value": "cve"},
            {"statement": "Also postgres.", "source_field": "members[0].nothing", "value": "postgres"},
        ],
        "fix_steps": ["Restrict the admin panel to known sources."],
        "priority_note": note,
    }))


def _always(factory):
    return lambda request: factory()


def _db_call(fn):
    db = SessionLocal()
    try:
        return fn(db)
    finally:
        db.close()


def _rows(key):
    def q(db):
        rows = db.query(ClusterAiWriteup).filter(
            ClusterAiWriteup.fingerprint == key.fingerprint).order_by(ClusterAiWriteup.created_at).all()
        for r in rows:
            db.expunge(r)
        return rows
    return _db_call(q)


def _qs(key, **extra):
    q = f"finding_type={key.finding_type}&source={key.source}&fingerprint={key.fingerprint}"
    for k, v in extra.items():
        q += f"&{k}={v}"
    return f"{URL}?{q}"


def _prompt(t) -> str:
    return t.bodies()[0]["messages"][-1]["content"]


@pytest.fixture
def cw_settings():
    """Mode, cap and budget for one test; restored afterwards."""
    keys = (cw.MODE_KEY, cw.AUTO_CAP_KEY, "llm.daily_budget_usd")
    snaps = _db_call(lambda db: {k: _snapshot_app_setting(db, k) for k in keys})

    def set_(mode=None, cap=None, budget=None):
        db = SessionLocal()
        try:
            if mode is not None:
                app_settings.set_value(db, cw.MODE_KEY, mode)
            if cap is not None:
                app_settings.set_value(db, cw.AUTO_CAP_KEY, str(cap))
            if budget is not None:
                app_settings.set_value(db, "llm.daily_budget_usd", budget)
        finally:
            db.close()

    yield set_
    db = SessionLocal()
    try:
        for k, v in snaps.items():
            _restore_app_setting(db, k, v)
    finally:
        db.close()


# ── 1. eligibility ───────────────────────────────────────────────────────────

def test_fewer_than_two_assets_is_not_eligible_and_makes_no_row(world, cluster, llm, admin):
    _member(world, cluster)
    _member(world, cluster)
    solo_key = cw.Key("cve", "test", cluster.fingerprint + "-solo")
    _member(world, solo_key)
    t = llm(_always(_answer))
    db = SessionLocal()
    try:
        assert len(cw.members(db, solo_key)) == 1  # reached: a real one-finding key
        with pytest.raises(cw.NotEligible):
            cw.request_writeup(db, key=solo_key, user_id=None, force=False)
    finally:
        db.close()
    r = client.post(_qs(solo_key), headers=admin)
    assert r.status_code == 409 and "more than one asset" in r.json()["detail"]
    g = client.get(_qs(solo_key), headers=admin).json()
    assert g["eligible"] is False and g["ineligible_reason"]
    assert _rows(solo_key) == [] and t.requests == []
    _purge(f"{solo_key.fingerprint}%")


def test_a_medium_two_asset_cluster_is_eligible_on_demand(world, cluster, llm):
    _cluster(world, cluster, severity="medium")
    t = llm(_always(_answer))
    db = SessionLocal()
    try:
        row, cached = cw.request_writeup(db, key=cluster, user_id=None, force=False)
        assert cached is False and row.status == "queued"
    finally:
        db.close()
    assert [r.status for r in _rows(cluster)] == ["queued"] and t.requests == []


def test_excluded_and_closed_findings_are_not_members(world, cluster):
    _member(world, cluster)
    _member(world, cluster)
    _member(world, cluster, verification="rejected_shared_infra")
    _member(world, cluster, verification="ownership_unverifiable")
    _member(world, cluster, state="resolved")
    _member(world, cluster, verification="confirmed_ours")
    rows = _db_call(lambda db: cw.members(db, cluster))
    assert len(rows) == 3


# ── 2. cache and membership ──────────────────────────────────────────────────

def test_unchanged_cluster_is_a_cache_hit_and_a_new_asset_changes_the_hash(world, cluster, llm, admin):
    _cluster(world, cluster)
    t = llm(_always(_answer))
    r = client.post(_qs(cluster), headers=admin)
    assert r.status_code == 200 and r.json()["cached"] is False
    assert len(t.requests) == 1
    h1 = _db_call(lambda db: cw.current_hash(db, cluster))

    again = client.post(_qs(cluster), headers=admin).json()
    assert again["cached"] is True and again["writeup"]["id"]
    assert len(t.requests) == 1 and len(_rows(cluster)) == 1

    _member(world, cluster)  # a third asset
    assert _db_call(lambda db: cw.current_hash(db, cluster)) != h1
    g = client.get(_qs(cluster), headers=admin).json()
    assert g["inputs_changed"] is True and g["writeup"] is not None
    assert client.post(_qs(cluster), headers=admin).json()["cached"] is False
    assert len(t.requests) == 2
    assert client.post(_qs(cluster, force="true"), headers=admin).json()["cached"] is False
    assert len(t.requests) == 3


def test_big_cluster_lists_twenty_and_freezes_all_member_ids(world, cluster, llm, admin):
    made = _cluster(world, cluster, n=25)
    t = llm(_always(_answer))
    assert client.post(_qs(cluster), headers=admin).status_code == 200
    user = _prompt(t)
    assert '"more_members":5' in user and '"members_listed":20' in user and '"finding_count":25' in user
    assert user.count('"asset":') == 20
    (row,) = _rows(cluster)
    assert row.status == "succeeded"
    assert sorted(row.member_ids) == sorted(str(f) for f, _a in made)
    assert (row.finding_count, row.asset_count) == (25, 25)


def test_hash_depends_on_membership_beyond_the_listed_members():
    def rows(ids, sev="high"):
        return [(SimpleNamespace(id=i, severity=sev), None) for i in ids]
    a, b = [uuid.uuid4() for _ in range(25)], [uuid.uuid4() for _ in range(25)]
    assert cw.input_hash(rows(a)) == cw.input_hash(rows(list(reversed(a))))
    assert cw.input_hash(rows(a)) != cw.input_hash(rows(a[:-1] + [b[0]]))
    assert cw.input_hash(rows(a)) != cw.input_hash(rows(a, "critical"))


def test_score_drift_does_not_change_the_hash_but_severity_does(world, cluster):
    """EPSS / risk score move with every nightly re-score; hashing them would
    rewrite every High cluster after each scan and make "membership changed"
    a false claim (module docstring, "Cache")."""
    (fid, _a), _other = _cluster(world, cluster)
    h1 = _db_call(lambda db: cw.current_hash(db, cluster))
    assert h1 is not None  # reached: it is a cluster

    def drift(db):
        f = db.get(FindingCanonical, fid)
        f.epss_score, f.risk_score = 0.12, 91
        db.commit()
    _db_call(drift)
    assert _db_call(lambda db: cw.current_hash(db, cluster)) == h1

    def escalate(db):
        db.get(FindingCanonical, fid).severity = "critical"
        db.commit()
    _db_call(escalate)
    assert _db_call(lambda db: cw.current_hash(db, cluster)) != h1


# ── 3. one at a time ─────────────────────────────────────────────────────────

def test_a_second_request_while_queued_is_refused(world, cluster, llm, admin):
    _cluster(world, cluster)
    t = llm(_always(_answer))
    db = SessionLocal()
    try:
        row, _ = cw.request_writeup(db, key=cluster, user_id=None, force=False)
        assert row.status == "queued"  # reached
        with pytest.raises(cw.AlreadyRunning):
            cw.request_writeup(db, key=cluster, user_id=None, force=True)
    finally:
        db.close()
    r = client.post(_qs(cluster), headers=admin)
    assert r.status_code == 409 and "already" in r.json()["detail"]
    assert client.get(_qs(cluster), headers=admin).json()["pending"]["status"] == "queued"
    assert t.requests == [] and len(_rows(cluster)) == 1


def test_not_configured_is_refused_before_any_row(world, cluster, admin):
    from app.tests.test_llm_connector import _configure_openrouter, _restore_openrouter
    _cluster(world, cluster)
    snap = _db_call(lambda db: _configure_openrouter(db, enabled=False))
    try:
        r = client.post(_qs(cluster), headers=admin)
        assert r.status_code == 409 and "OpenRouter" in r.json()["detail"]
    finally:
        _restore_openrouter(snap)
    assert _rows(cluster) == []


def test_viewer_cannot_generate_but_can_read(world, cluster):
    _cluster(world, cluster)
    h, uid = _make_user(UserRole.VIEWER.value)
    try:
        assert client.post(_qs(cluster), headers=h).status_code == 403
        assert client.get(_qs(cluster), headers=h).status_code == 200
    finally:
        _cleanup_user(uid)
    assert _rows(cluster) == []


# ── 4. generate and scope ────────────────────────────────────────────────────

def test_generate_stores_a_grounded_payload(world, cluster, llm, admin):
    _cluster(world, cluster)
    t = llm(_always(_answer))
    assert client.post(_qs(cluster), headers=admin).json()["pending"]["status"] == "queued"
    r = client.get(_qs(cluster), headers=admin).json()
    assert len(t.requests) == 1 and t.bodies()[0]["model"] == NARRATE_PRIMARY
    (row,) = _rows(cluster)
    assert row.status == "succeeded" and row.model == NARRATE_PRIMARY and row.ledger_ids and row.input_hash
    assert (row.statements_returned, row.statements_dropped) == (2, 1)
    assert [c["source_field"] for c in row.payload["context"]] == ["cluster.finding_type"]
    assert row.summary_dropped is False and row.max_severity == "high" and row.requested_by_id is not None
    w = r["writeup"]
    assert w["summary"].startswith("The same exposure") and w["auto"] is False and w["asset_count"] == 2
    assert w["cost_usd"] == pytest.approx(0.001) and r["inputs_changed"] is False and r["hidden"] is False


def test_a_failed_call_freezes_the_inputs_and_says_why(world, cluster, llm, admin):
    made = _cluster(world, cluster)
    t = llm(_always(lambda: _ok_response(model=NARRATE_PRIMARY, content="not json")))
    assert client.post(_qs(cluster), headers=admin).status_code == 200
    assert t.requests
    (row,) = _rows(cluster)
    assert row.status == "failed" and row.error == "no model returned a usable write-up"
    assert row.input_hash and len(row.member_ids) == len(made) and row.payload is None
    assert client.get(_qs(cluster), headers=admin).json()["last_failure"]["error"] == row.error


def _provider(t):
    return t.bodies()[0]["provider"]


def _linked_cluster(world, key, engagement_ids):
    """One member per entry; each asset is linked to a target in that engagement (None = no engagement)."""
    for eid in engagement_ids:
        _f, a = _member(world, key)
        world.target(engagement_id=eid, link_asset=a)


def test_one_shared_engagement_is_not_forced_strict(world, cluster, llm, admin, permissive):
    eid = world.engagement(EngagementPosture.INTEGRATED.value)
    _linked_cluster(world, cluster, [eid, eid])
    t = llm(_always(_answer))
    client.post(_qs(cluster), headers=admin)
    assert len(t.requests) == 1 and "zdr" not in _provider(t)
    (row,) = _rows(cluster)
    assert row.forced_strict is False
    calls = _db_call(lambda db: db.query(LlmCall).filter(LlmCall.task == cw.task_label(row.id)).all())
    assert calls and {c.engagement_id for c in calls} == {eid}


def test_two_engagements_force_strict_and_keep_asset_names(world, cluster, llm, admin, permissive):
    e1 = world.engagement(EngagementPosture.INTEGRATED.value)
    e2 = world.engagement(EngagementPosture.INTEGRATED.value)
    host = f"app1-{uuid.uuid4().hex[:8]}.fabrikam.com"
    _f, a = _member(world, cluster, asset_value=host)
    world.target(engagement_id=e1, link_asset=a)
    _f, b = _member(world, cluster)
    world.target(engagement_id=e2, link_asset=b)
    t = llm(_always(_answer))
    client.post(_qs(cluster), headers=admin)
    assert len(t.requests) == 1 and _provider(t)["zdr"] is True
    assert host in _prompt(t) and '"spans_engagements":true' in _prompt(t)
    assert _rows(cluster)[0].forced_strict is True


def test_no_engagement_forces_strict(world, cluster, llm, admin, permissive):
    _cluster(world, cluster)  # no targets at all
    t = llm(_always(_answer))
    client.post(_qs(cluster), headers=admin)
    assert _provider(t)["zdr"] is True and _rows(cluster)[0].forced_strict is True


def test_scope_for_with_no_assets_is_strict():
    assert _db_call(lambda db: cw.scope_for(db, [])) == (None, True)


# ── 5. the summary may only name listed members ─────────────────────────────

def _run_summary(world, cluster, llm, admin, summary):
    host1, host2 = f"app1-{uuid.uuid4().hex[:8]}.fabrikam.com", f"app2-{uuid.uuid4().hex[:8]}.fabrikam.com"
    _member(world, cluster, asset_value=host1)
    _member(world, cluster, asset_value=host2)
    t = llm(_always(lambda: _answer(summary=summary.format(h1=host1, h2=host2))))
    client.post(_qs(cluster), headers=admin)
    assert len(t.requests) == 1  # reached
    return _rows(cluster)[0], host1


@pytest.mark.parametrize("summary", [
    "Seen on other-host.fabrikam.com as well.",
    "Details at https://fabrikam.com/advisory.",
    "Visit www.fabrikam.com for more.",
])
def test_a_summary_naming_something_not_listed_is_dropped(world, cluster, llm, admin, summary):
    row, _ = _run_summary(world, cluster, llm, admin, summary)
    assert row.status == "succeeded" and row.summary_dropped is True and row.payload["summary"] is None
    g = client.get(_qs(cluster), headers=admin).json()
    assert g["writeup"]["summary"] is None and g["writeup"]["summary_dropped"] is True


def test_a_summary_naming_a_listed_member_is_kept(world, cluster, llm, admin):
    row, host1 = _run_summary(world, cluster, llm, admin, "The panel is open on {h1} and {h2}.")
    assert row.summary_dropped is False and host1 in row.payload["summary"]


# ── 6. the per-viewer read gate ──────────────────────────────────────────────

def _generated(world, cluster, llm, admin, n=3):
    made = _cluster(world, cluster, n=n)
    t = llm(_always(_answer))
    assert client.post(_qs(cluster), headers=admin).status_code == 200
    assert len(t.requests) == 1 and _rows(cluster)[0].status == "succeeded"
    return made


def test_default_read_scope_shows_the_writeup(world, cluster, llm, admin):
    _generated(world, cluster, llm, admin)
    g = client.get(_qs(cluster), headers=admin).json()
    assert g["hidden"] is False and g["writeup"] is not None


def test_one_unreadable_member_hides_the_writeup(world, cluster, llm, admin, monkeypatch):
    made = _generated(world, cluster, llm, admin)
    blocked = made[0][0]
    monkeypatch.setattr(read_scope, "finding_clause", lambda user, finding, asset: finding.id != blocked)
    g = client.get(_qs(cluster), headers=admin).json()
    assert g["hidden"] is True and g["writeup"] is None and g["inputs_changed"] is None
    assert g["eligible"] is True  # reached: the cluster is there, only the write-up is withheld


def test_a_deleted_member_does_not_hide_the_writeup(world, cluster, llm, admin):
    made = _generated(world, cluster, llm, admin)
    db = SessionLocal()
    try:
        db.query(FindingCanonical).filter(FindingCanonical.id == made[0][0]).delete()
        db.commit()
        assert db.get(FindingCanonical, made[0][0]) is None
    finally:
        db.close()
    g = client.get(_qs(cluster), headers=admin).json()
    assert g["hidden"] is False and g["writeup"] is not None and g["inputs_changed"] is True


# ── 7. automatic write-ups ───────────────────────────────────────────────────

def _spy_candidates(monkeypatch):
    calls = []
    real = cw.auto_candidates
    monkeypatch.setattr(cw, "auto_candidates", lambda db, ids: calls.append(1) or real(db, ids))
    return calls


def _cand(ids):
    return _db_call(lambda db: cw.auto_candidates(db, ids))


def test_on_demand_mode_does_nothing_and_never_looks_for_candidates(world, cluster, llm, cw_settings, monkeypatch):
    made = _cluster(world, cluster, severity="critical")
    ids = [f for f, _a in made]
    t = llm(_always(_answer))
    calls = _spy_candidates(monkeypatch)
    cw_settings(mode="on_demand", cap=5)
    assert _cand(ids) == [cluster]  # a real candidate...
    calls.clear()
    assert cw.auto_generate(ids) == 0  # ...that on_demand leaves alone
    assert calls == [] and t.requests == [] and _rows(cluster) == []
    cw_settings(mode="auto_high")
    assert cw.auto_generate(ids) == 1
    assert calls == [1] and len(t.requests) == 1
    row = _rows(cluster)[0]
    assert row.status == "succeeded" and row.requested_by_id is None


def test_auto_takes_high_clusters_and_not_medium_ones(world, cluster, llm, cw_settings):
    med = cw.Key("cve", "test", cluster.fingerprint + "-med")
    high_ids = [f for f, _a in _cluster(world, cluster, severity="high")]
    med_ids = [f for f, _a in _cluster(world, med, severity="medium")]
    assert len(_db_call(lambda db: cw.members(db, med))) == 2  # a real two-asset medium cluster
    t = llm(_always(_answer))
    cw_settings(mode="auto_high", cap=5)
    assert _cand(high_ids + med_ids) == [cluster]
    assert cw.auto_generate(high_ids + med_ids) == 1
    assert len(t.requests) == 1 and _rows(med) == []
    _purge(f"{med.fingerprint}%")


def test_cap_one_with_two_candidates_writes_the_critical_one(world, cluster, llm, cw_settings):
    crit = cw.Key("cve", "test", cluster.fingerprint + "-crit")
    ids = [f for f, _a in _cluster(world, cluster, title="High exposure")]
    ids += [f for f, _a in _cluster(world, crit, severity="critical", title="Critical exposure")]
    t = llm(_always(_answer))
    cw_settings(mode="auto_high", cap=1)
    assert _cand(ids) == [crit, cluster]
    assert cw.auto_generate(ids) == 1
    assert len(t.requests) == 1 and "Critical exposure" in _prompt(t)
    assert _rows(cluster) == [] and len(_rows(crit)) == 1
    assert cw.auto_generate(ids) == 0 and len(t.requests) == 1  # cap reached
    _purge(f"{crit.fingerprint}%")


def test_a_failed_row_with_the_current_hash_is_not_retried(world, cluster, llm, cw_settings, monkeypatch):
    monkeypatch.setattr(llmc, "_sleep", lambda s: None)
    ids = [f for f, _a in _cluster(world, cluster)]
    t = llm(_always(lambda: _ok_response(model=NARRATE_PRIMARY, content="not json")))
    cw_settings(mode="auto_high", cap=5)
    assert cw.auto_generate(ids) == 1
    calls = len(t.requests)
    assert calls >= 1
    (row,) = _rows(cluster)
    assert row.status == "failed"
    assert row.input_hash == _db_call(lambda db: cw.current_hash(db, cluster))
    assert _cand(ids) == []
    assert cw.auto_generate(ids) == 0 and len(t.requests) == calls and len(_rows(cluster)) == 1


def test_changed_membership_requeues_and_an_unchanged_cluster_does_not(world, cluster, llm, cw_settings):
    ids = [f for f, _a in _cluster(world, cluster)]
    t = llm(_always(_answer))
    cw_settings(mode="auto_high", cap=5)
    assert cw.auto_generate(ids) == 1 and len(t.requests) == 1
    assert _cand(ids) == [] and cw.auto_generate(ids) == 0
    new, _a = _member(world, cluster)
    assert _cand(ids) == [cluster]  # reached: membership changed, so it IS a candidate again
    assert cw.auto_generate(ids + [new]) == 1
    assert len(t.requests) == 2 and len(_rows(cluster)) == 2


def test_an_active_row_blocks_a_candidate(world, cluster, cw_settings):
    ids = [f for f, _a in _cluster(world, cluster)]
    assert _cand(ids) == [cluster]
    db = SessionLocal()
    try:
        db.add(ClusterAiWriteup(finding_type=cluster.finding_type, source=cluster.source,
                                fingerprint=cluster.fingerprint, status="running"))
        db.commit()
    finally:
        db.close()
    assert _cand(ids) == []


def test_a_cluster_with_no_touched_member_is_not_a_candidate(world, cluster):
    ids = [f for f, _a in _cluster(world, cluster, severity="critical")]
    unrelated, _a = _member(world, cw.Key("cve", "test", cluster.fingerprint + "-other"))
    assert _cand(ids[:1]) == [cluster]  # touching ONE member suffices
    assert _cand([unrelated]) == []
    _purge(f"{cluster.fingerprint}-other%")


def test_start_auto_runs_on_its_own_named_thread(world, cluster, llm, cw_settings):
    import threading
    ids = [f for f, _a in _cluster(world, cluster)]
    names = []
    t = llm(lambda request: names.append(threading.current_thread().name) or _answer())
    cw_settings(mode="auto_high", cap=1)
    th = cw.start_auto(ids)
    assert th.daemon
    th.join(timeout=30)
    assert len(t.requests) == 1 and names == ["cluster-writeup-auto"]


# ── 8. settings API ──────────────────────────────────────────────────────────

def test_settings_put_is_audited_validated_and_reported_in_status(admin, cw_settings):
    cw_settings(mode="on_demand", cap=10)
    r = client.put("/api/llm/cluster-writeup-settings", headers=admin,
                   json={"mode": "auto_high", "auto_daily_cap": 4})
    assert r.status_code == 200, r.text
    assert r.json()["mode"] == "auto_high" and r.json()["daily_cap"] == 4
    s = client.get("/api/llm/status", headers=admin).json()["cluster_writeups"]
    assert s["mode"] == "auto_high" and s["daily_cap"] == 4 and s["today"] >= 0
    db = SessionLocal()
    try:
        assert cw.mode(db) == "auto_high" and cw.auto_daily_cap(db) == 4
        rows = db.query(AuditLog).order_by(AuditLog.occurred_at.desc()).limit(20).all()
        changes = [x.detail.get("changes", {}) for x in rows if x.detail]
    finally:
        db.close()
    assert any(c.get("cluster_writeup_mode") == {"from": "on_demand", "to": "auto_high"}
               and c.get("cluster_writeup_auto_daily_cap") == {"from": 10, "to": 4} for c in changes)
    for bad in ({"mode": "always", "auto_daily_cap": 4}, {"mode": "auto_high", "auto_daily_cap": -1},
                {"mode": "auto_high", "auto_daily_cap": 1001}, {"mode": "auto_high", "auto_daily_cap": "x"},
                {"auto_daily_cap": 4}):
        assert client.put("/api/llm/cluster-writeup-settings", headers=admin, json=bad).status_code == 422
    assert _db_call(lambda d: (cw.mode(d), cw.auto_daily_cap(d))) == ("auto_high", 4)


def test_settings_put_needs_admin():
    h, uid = _make_user(UserRole.INTEGRATION_ADMIN.value)
    try:
        r = client.put("/api/llm/cluster-writeup-settings", headers=h, json={"mode": "auto_high", "auto_daily_cap": 1})
        assert r.status_code == 403
    finally:
        _cleanup_user(uid)


def test_defaults_modes_and_literal_agree(cw_settings):
    assert app_settings.DEFAULTS[cw.MODE_KEY] == cw.DEFAULT_MODE == "on_demand"
    assert app_settings.DEFAULTS[cw.AUTO_CAP_KEY] == "10"
    assert typing.get_args(llm_api.ClusterWriteupSettingsUpdate.model_fields["mode"].annotation) == cw.MODES
    db = SessionLocal()
    try:
        app_settings.set_value(db, cw.MODE_KEY, "bogus")
        assert cw.mode(db) == cw.DEFAULT_MODE
    finally:
        db.close()


# ── 9. the digest embed ──────────────────────────────────────────────────────

@pytest.fixture
def cw_rows(denv):  # noqa: F811
    yield
    _purge(f"%{denv.suffix}%")


def _digest_cluster(e, *, summary="The same exposure is repeated across several assets."):
    """A pending-digest scenario: one cluster on two assets plus a succeeded write-up row for it."""
    a1, a2 = d_asset(e, 31), d_asset(e, 32)
    fp = f"cw-{e.suffix}"
    d_finding(e, a1, fp, severity="high", title=f"Clustered issue {e.suffix}")
    f2 = d_finding(e, a2, fp, severity="high", title=f"Clustered issue {e.suffix}")
    key = cw.Key("cve", "test", fp)
    rule = _rule(e, "rule", "digest")
    _dispatch(e, rule, [(f2, "high", None)] + [
        (f, "high", None) for f in e.db.query(FindingCanonical).filter(
            FindingCanonical.fingerprint == fp, FindingCanonical.id != f2.id)])
    e.db.add(ClusterAiWriteup(
        finding_type=key.finding_type, source=key.source, fingerprint=key.fingerprint, status="succeeded",
        payload={"summary": summary}, input_hash="old", finding_count=2, asset_count=2,
        finished_at=datetime.now(timezone.utc), member_ids=[str(f2.id)],
    ))
    e.db.commit()
    return rule, key


def _send(e, monkeypatch):
    conn = _Conn("ok")
    _use_connectors(monkeypatch, [("c1", conn)])
    digest.run_due(e.t1)
    return conn, [m for m in conn.sent if e.suffix in m["text"]]


def test_digest_embeds_the_summary_in_auto_high_in_digest_mode(denv, cw_rows, cw_settings, llm, monkeypatch):
    cw_settings(mode="auto_high_in_digest")
    rule, key = _digest_cluster(denv)
    t = llm(lambda request: _scripted(request))
    conn, msgs = _send(denv, monkeypatch)
    (dg,) = _digests(denv, rule)
    (g,) = [g for g in dg.body["groups"] if g["kind"] == "cluster"]
    assert g["writeup"]["summary"].startswith("The same exposure") and g["writeup"]["asset_count"] == 2
    assert g["writeup"]["inputs_changed"] is True  # stored hash "old" != the current one
    (msg,) = msgs
    assert "AI write-up of this issue across 2 assets (written " in msg["text"]
    assert "inputs changed since" in msg["text"] and "The same exposure is repeated" in msg["text"]
    # the digest's own narrative is grounded in deterministic data only
    assert len(t.requests) == 1
    sent = json.loads(t.requests[0].content)["messages"][1]["content"]
    assert "writeup" not in sent and "The same exposure" not in sent
    assert dg.outcome == "sent"


def test_digest_does_not_embed_in_auto_high_mode(denv, cw_rows, cw_settings, monkeypatch):
    cw_settings(mode="auto_high")
    rule, _ = _digest_cluster(denv)
    conn, msgs = _send(denv, monkeypatch)
    (dg,) = _digests(denv, rule)
    assert dg.outcome == "sent" and len(msgs) == 1  # reached: the digest went out
    assert all("writeup" not in g for g in dg.body["groups"])
    assert "AI write-up of this issue" not in msgs[0]["text"]


def test_digest_skips_a_summary_naming_a_host_outside_the_group(denv, cw_rows, cw_settings, monkeypatch):
    cw_settings(mode="auto_high_in_digest")
    rule, _ = _digest_cluster(denv, summary="Also seen on elsewhere-host.fabrikam.com.")
    conn, msgs = _send(denv, monkeypatch)
    (dg,) = _digests(denv, rule)
    assert dg.outcome == "sent" and len(msgs) == 1
    assert all("writeup" not in g for g in dg.body["groups"])


def test_a_failing_embed_never_stops_the_digest(denv, cw_rows, cw_settings, monkeypatch):
    cw_settings(mode="auto_high_in_digest")
    rule, _ = _digest_cluster(denv)
    reached = []

    def boom(db, d):
        reached.append(d.id)
        raise RuntimeError("embed failed")

    monkeypatch.setattr(cw, "embed_into_digest", boom)
    conn, msgs = _send(denv, monkeypatch)
    assert len(reached) == 1
    (dg,) = _digests(denv, rule)
    assert dg.outcome == "sent" and len(msgs) == 1
    assert "AI write-up of this issue" not in msgs[0]["text"]


def test_narrative_input_drops_writeups_and_render_shows_them():
    item = {"finding_id": "f1", "asset_id": "a1", "asset": "app1.fabrikam.com", "title": "T <b>", "severity": "high",
            "cve_id": None, "kinds": ["new"], "band_change": None, "state_now": "open", "excluded_now": False,
            "path": "/findings/f1"}
    wu = {"id": "w", "summary": "Repeated <i>everywhere</i>.", "written_at": "2030-01-01T00:00:00+00:00",
          "asset_count": 2, "finding_count": 2, "inputs_changed": True}
    body = {
        "rule": {"id": "r", "name": "Rule", "severity_threshold": "high"},
        "period": {"start": "2030-01-01T00:00:00+00:00", "end": "2030-01-02T00:00:00+00:00"},
        "totals": {"events": 1, "findings": 1, "assets": 1, "new": 1, "promotions": 0,
                   "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}},
        "groups": [{"kind": "cluster", "label": "T", "finding_count": 2, "asset_count": 2, "max_severity": "high",
                    "key": {"finding_type": "cve", "source": "test", "fingerprint": "x"}, "items": [item],
                    "writeup": wu}],
        "listed_findings": 1, "omitted_findings": 0,
    }
    data = digest.narrative_input(body)
    assert "writeup" not in data["groups"][0]
    assert body["groups"][0]["writeup"] == wu  # the stored body is untouched
    _s, text, html = digest.render(body, "skipped", None, "x", "")
    assert ("  AI write-up of this issue across 2 assets (written 2030-01-01, inputs changed since): "
            "Repeated <i>everywhere</i>.") in text
    assert "<p><em>AI write-up of this issue across 2 assets" in html and "&lt;i&gt;everywhere&lt;/i&gt;" in html
    del wu["inputs_changed"]
    _s, text, _h = digest.render(body, "skipped", None, "x", "")
    assert "(written 2030-01-01): " in text


# ── 10. the scan_executor hook ───────────────────────────────────────────────

def test_scan_hands_touched_findings_to_cluster_auto_after_completed(world, cluster, monkeypatch):
    from app.models.scan import ScanRun, ScanStatus
    (f, _a), _b = _cluster(world, cluster)
    run_id = uuid.uuid4()
    calls = []

    def capture(ids):
        status = _db_call(lambda db: db.get(ScanRun, run_id).status)
        calls.append((set(ids), status))

    monkeypatch.setattr(cw, "start_auto", capture)
    status, _ = _run_scan_touching(f, monkeypatch, lambda ids: None, run_id)
    assert status == ScanStatus.COMPLETED
    assert calls == [({f}, ScanStatus.COMPLETED)]


def test_cluster_auto_failing_to_start_does_not_fail_the_scan(world, cluster, monkeypatch):
    from app.models.scan import ScanStatus
    (f, _a), _b = _cluster(world, cluster)
    reached = []

    def boom(ids):
        reached.append(set(ids))
        raise RuntimeError("thread start failed")

    monkeypatch.setattr(cw, "start_auto", boom)
    status, _ = _run_scan_touching(f, monkeypatch, lambda ids: None, uuid.uuid4())
    assert reached == [{f}] and status == ScanStatus.COMPLETED


# ── 11. nothing that scores reads cluster write-ups ─────────────────────────

def test_no_scoring_module_reads_cluster_writeups():
    root = pathlib.Path(__file__).resolve().parents[1]
    allowed = {root / "services" / "cluster_writeup.py", root / "api" / "findings.py",
               root / "models" / "cluster_ai_writeup.py", root / "models" / "__init__.py"}
    # file -> (the uses it may make, the one use it must still make)
    narrow = {
        root / "services" / "scan_executor.py": (
            re.compile(r"from app\.services import cluster_writeup\n|cluster_writeup\.start_auto\(|ai\.cluster_writeups\.\w+"),
            "cluster_writeup.start_auto(touched_finding_ids)"),
        root / "api" / "llm.py": (
            re.compile(r"cluster_writeup\.(mode|auto_daily_cap|auto_count_today|MODE_KEY|AUTO_CAP_KEY|MODES)\b|"
                       r"(?<=import )cluster_writeup(?=, digest\n)|ai\.cluster_writeups\.\w+|"
                       r"ClusterWriteupStatus|ClusterWriteupSettingsUpdate|_cluster_writeups|"
                       r"put_cluster_writeup_settings|cluster_writeup_\w+|cluster-writeup-settings|cluster_writeups"),
            "cluster_writeup.auto_count_today(db)"),
        root / "services" / "app_settings.py": (re.compile(r"ai\.cluster_writeups\.\w+"), '"ai.cluster_writeups.mode"'),
        root / "services" / "digest.py": (
            re.compile(r"from app\.services import cluster_writeup\n|cluster_writeup\.(mode|embed_into_digest)\(|"
                       r"_embed_cluster_writeups|cluster write-ups?|cluster_writeup imports"),
            "cluster_writeup.embed_into_digest(db, digest)"),
    }
    pattern = re.compile(r"cluster_writeup|ClusterAiWriteup|cluster_ai_writeups")
    offenders = []
    for p in root.rglob("*.py"):
        if "tests" in p.parts or p in allowed:
            continue
        text = p.read_text(encoding="utf-8")
        if p in narrow:
            uses, required = narrow[p]
            assert required in text, f"{p.name}: the allowed use is gone; tighten this test"
            text = uses.sub("", text)
        if pattern.search(text):
            offenders.append(str(p.relative_to(root)))
    assert offenders == []
    assert pattern.search((root / "api" / "findings.py").read_text(encoding="utf-8"))  # the check is live
