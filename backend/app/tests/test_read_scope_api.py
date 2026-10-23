"""The routes moved onto `read_scope` (planning#261), with real tokens against
the `_scope_world.py` world. Every "hidden" assertion is paired with the same
request succeeding for an admin, so the path was reached.

Persona: `viewer` (global viewer: sees a3, a0), `viewer+E1` (also a1, a1L,
aMulti), `admin` (all seven).
"""

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.api import findings as findings_api
from app.core.database import SessionLocal
from app.main import app
from app.models.asset_edge import AssetEdge
from app.models.finding_canonical import FindingCanonical
from app.models.role_assignment import RoleAssignment
from app.services import chat, cluster_writeup
from app.tests._scope_world import ScopeWorld
from app.tests._users import user_with
from app.tests.test_edgar_ingest_api import _cleanup_user, _make_user

client = TestClient(app)

HIDDEN_FROM_VIEWER = ("a1", "a1L", "a2", "aMulti", "aBoth")
VISIBLE_TO_VIEWER = ("a3", "a0")


@pytest.fixture(scope="module")
def w():
    world = ScopeWorld().build()
    yield world
    world.close()


@pytest.fixture(scope="module")
def tokens(w):
    admin, admin_id = _make_user("admin")
    viewer, viewer_id = _make_user("viewer")
    scoped, scoped_id = _make_user("viewer")
    db = SessionLocal()
    try:
        db.add(RoleAssignment(user_id=scoped_id, role="viewer", engagement_id=w.E["E1"]))
        db.commit()
    finally:
        db.close()
    yield {"admin": admin, "viewer": viewer, "viewer+E1": scoped}
    for uid in (admin_id, viewer_id, scoped_id):
        _cleanup_user(uid)


def _get(tokens, who, url):
    return client.get(url, headers=tokens[who])


def _ids(rows, key="id") -> set[str]:
    return {r[key] for r in rows}


def test_asset_list(w, tokens):
    mine = {str(v) for v in w.a.values()}
    admin = _get(tokens, "admin", "/api/assets/")
    assert admin.status_code == 200 and mine <= _ids(admin.json())
    assert _ids(_get(tokens, "viewer", "/api/assets/").json()) & mine == {str(w.a[k]) for k in VISIBLE_TO_VIEWER}
    scoped = _ids(_get(tokens, "viewer+E1", "/api/assets/").json()) & mine
    assert scoped == {str(w.a[k]) for k in ("a3", "a0", "a1", "a1L", "aMulti")}


def test_asset_detail(w, tokens):
    url = f"/api/assets/{w.a['a1']}"
    assert _get(tokens, "admin", url).status_code == 200
    r = _get(tokens, "viewer", url)
    assert r.status_code == 404 and r.json()["detail"] == "Asset not found"
    assert _get(tokens, "viewer+E1", url).status_code == 200
    # an asset the viewer may read, and an unknown id, behave as before
    assert _get(tokens, "viewer", f"/api/assets/{w.a['a0']}").status_code == 200
    unknown = _get(tokens, "viewer", f"/api/assets/{uuid.uuid4()}")
    assert unknown.status_code == 404 and unknown.json() == r.json()


def test_finding_list(w, tokens):
    mine = {str(v) for v in w.f.values()}
    admin = _get(tokens, "admin", "/api/findings/")
    assert admin.status_code == 200 and mine <= _ids(admin.json())
    assert _ids(_get(tokens, "viewer", "/api/findings/").json()) & mine == {str(w.f[k]) for k in VISIBLE_TO_VIEWER}
    assert _ids(_get(tokens, "viewer+E1", "/api/findings/").json()) & mine == {
        str(w.f[k]) for k in ("a3", "a0", "a1", "a1L", "aMulti")}


@pytest.mark.parametrize("suffix", ["", "/ai-writeup", "/epss-history"])
def test_finding_detail_routes_hide_unreadable_findings(w, tokens, suffix):
    hidden = f"/api/findings/{w.f['a1']}{suffix}"
    visible = f"/api/findings/{w.f['a0']}{suffix}"
    assert _get(tokens, "admin", hidden).status_code == 200
    r = _get(tokens, "viewer", hidden)
    assert r.status_code == 404 and r.json()["detail"] == "Finding not found"
    assert _get(tokens, "viewer+E1", hidden).status_code == 200
    assert _get(tokens, "viewer", visible).status_code == 200


def test_security_score_counts_only_readable_findings(w, tokens):
    admin = _get(tokens, "admin", "/api/findings/security-score").json()
    viewer = _get(tokens, "viewer", "/api/findings/security-score").json()
    scoped = _get(tokens, "viewer+E1", "/api/findings/security-score").json()
    # every world finding is critical at risk 90, so they all sit in the worst band
    assert admin["band"] == viewer["band"] == scoped["band"]
    assert admin["worst_band_count"] - viewer["worst_band_count"] == len(HIDDEN_FROM_VIEWER)
    assert admin["worst_band_count"] - scoped["worst_band_count"] == 2          # a2 and aBoth stay shut
    assert admin["worst_band_new"] - viewer["worst_band_new"] == len(HIDDEN_FROM_VIEWER)
    hidden = {str(w.f[k]) for k in HIDDEN_FROM_VIEWER}
    assert not hidden & {b["id"] for b in viewer["breakdown"]}


@pytest.fixture
def aged(w):
    """a0's and a1's findings first seen 3 days ago; a1's resolved an hour ago. Restored after."""
    now = datetime.now(timezone.utc)
    db = SessionLocal()
    try:
        rows = {k: db.get(FindingCanonical, w.f[k]) for k in ("a0", "a1")}
        was = {k: (r.first_seen_at, r.state, r.resolved_at) for k, r in rows.items()}
        for r in rows.values():
            r.first_seen_at = now - timedelta(days=3)
        rows["a1"].state, rows["a1"].resolved_at = "resolved", now - timedelta(hours=1)
        db.commit()
    finally:
        db.close()
    yield
    db = SessionLocal()
    try:
        for k, (seen, state, resolved) in was.items():
            r = db.get(FindingCanonical, w.f[k])
            r.first_seen_at, r.state, r.resolved_at = seen, state, resolved
        db.commit()
    finally:
        db.close()


def test_security_score_trend_counts_are_scoped_too(w, tokens, aged):
    """worst_band_count_prev and worst_band_resolved each have their own query; the hidden, aged,
    just-resolved a1 finding must reach the admin's numbers and not the viewer's."""
    admin = _get(tokens, "admin", "/api/findings/security-score").json()
    viewer = _get(tokens, "viewer", "/api/findings/security-score").json()
    assert admin["worst_band_count_prev"] - viewer["worst_band_count_prev"] == 1
    assert admin["worst_band_resolved"] - viewer["worst_band_resolved"] == 1


def test_security_score_headline_is_the_worst_readable_finding(w, tokens):
    """The score is the single highest finding; a hidden hotter one must not set the viewer's."""
    db = SessionLocal()
    try:
        f = db.get(FindingCanonical, w.f["a1"])
        was = f.risk_score
        f.risk_score = 99
        db.commit()
    finally:
        db.close()
    try:
        admin = _get(tokens, "admin", "/api/findings/security-score").json()
        viewer = _get(tokens, "viewer", "/api/findings/security-score").json()
        scoped = _get(tokens, "viewer+E1", "/api/findings/security-score").json()
        assert admin["score"] == 99                                                 # reached
        assert viewer["score"] == 90
        assert scoped["score"] == 99
    finally:
        db = SessionLocal()
        try:
            f = db.get(FindingCanonical, w.f["a1"])
            f.risk_score = was
            db.commit()
        finally:
            db.close()


@pytest.fixture
def edges(w):
    """a0 -> a1 (hidden from the viewer), a0 -> T1 (a target of E1), a0 -> a3 (readable)."""
    now = datetime.now(timezone.utc)
    db = SessionLocal()
    made = []
    try:
        for tt, tid, et in (("asset_canonical", w.a["a1"], "resolves_to"),
                            ("target", w.T["T1"], "discovered_in_target"),
                            ("asset_canonical", w.a["a3"], "belongs_to_apex")):
            e = AssetEdge(source_type="asset_canonical", source_id=w.a["a0"], target_type=tt, target_id=tid,
                          edge_type=et, edge_metadata={}, first_seen_at=now, last_seen_at=now)
            db.add(e)
            db.flush()
            made.append(e.id)
        db.commit()
    finally:
        db.close()
    yield
    db = SessionLocal()
    try:
        db.query(AssetEdge).filter(AssetEdge.id.in_(made)).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _edge_node_ids(resp) -> set[str]:
    return {i["node_id"] for g in resp.json()["groups"] for i in g["items"]}


def test_edges_root_and_endpoints_follow_the_same_scope(w, tokens, edges):
    root_hidden = f"/api/edges/asset_canonical/{w.a['a1']}"
    # A hidden root answers exactly as an unknown id does: an empty graph, not
    # a 404 that an unknown id would not give (no existence oracle).
    assert _edge_node_ids(_get(tokens, "admin", root_hidden))   # reached: admin sees its edges
    unknown = _get(tokens, "viewer", f"/api/edges/asset_canonical/{uuid.uuid4()}")
    hidden = _get(tokens, "viewer", root_hidden)
    assert hidden.status_code == unknown.status_code == 200
    assert hidden.json() == unknown.json() == {"groups": []}
    assert _edge_node_ids(_get(tokens, "viewer+E1", root_hidden))

    from_a0 = f"/api/edges/asset_canonical/{w.a['a0']}"
    admin = _get(tokens, "admin", from_a0)
    assert {str(w.a["a1"]), str(w.T["T1"]), str(w.a["a3"])} <= _edge_node_ids(admin)   # reached
    viewer = _get(tokens, "viewer", from_a0)
    assert viewer.status_code == 200
    assert _edge_node_ids(viewer) == {str(w.a["a3"])}
    # no group counts a hidden endpoint either
    assert sum(g["total"] for g in viewer.json()["groups"]) == 1
    assert {str(w.a["a1"]), str(w.T["T1"])} <= _edge_node_ids(_get(tokens, "viewer+E1", from_a0))
    # a target root is gated by target_clause
    assert _edge_node_ids(_get(tokens, "admin", f"/api/edges/target/{w.T['T1']}"))
    assert _get(tokens, "viewer", f"/api/edges/target/{w.T['T1']}").json() == {"groups": []}


def test_chat_tools_run_as_the_asking_user(w):
    viewer, admin = user_with("viewer"), user_with("admin")
    for tool, key, ids in (("get_asset", "asset_id", w.a), ("get_finding", "finding_id", w.f)):
        args = json.dumps({key: str(ids["a1"])})
        ok = chat.run_tool(tool, args, admin)
        assert "error" not in ok.payload and ok.cite_ids == {str(ids["a1"])}          # reached
        denied = chat.run_tool(tool, args, viewer)
        assert denied.payload["error"] == "not_found" and denied.cite_ids == set()
        own = chat.run_tool(tool, json.dumps({key: str(ids["a0"])}), viewer)
        assert "error" not in own.payload


@pytest.fixture
def cluster(w):
    """One cluster key with a member on a0 (open to the viewer) and on a1 (not)."""
    key = cluster_writeup.Key("cve", "scope-cluster", uuid.uuid4().hex)
    now = datetime.now(timezone.utc)
    db = SessionLocal()
    made = []
    try:
        for k in ("a0", "a1"):
            f = FindingCanonical(id=uuid.uuid4(), asset_canonical_id=w.a[k], finding_type=key.finding_type,
                                 source=key.source, fingerprint=key.fingerprint, severity="high",
                                 title=f"cluster {k}", state="open", first_seen_at=now, last_seen_at=now,
                                 detail={}, tags=[])
            db.add(f)
            made.append(f.id)
        db.commit()
    finally:
        db.close()
    yield key
    db = SessionLocal()
    try:
        db.query(FindingCanonical).filter(FindingCanonical.id.in_(made)).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _cluster_url(key, verb="ai-writeup"):
    return (f"/api/findings/clusters/{verb}?finding_type={key.finding_type}"
            f"&source={key.source}&fingerprint={key.fingerprint}")


def test_cluster_write_up_state_is_the_viewers_view(w, tokens, cluster):
    admin = _get(tokens, "admin", _cluster_url(cluster))
    assert admin.status_code == 200 and admin.json()["eligible"] is True
    viewer = _get(tokens, "viewer", _cluster_url(cluster))
    assert viewer.status_code == 200 and viewer.json()["eligible"] is False   # one readable asset is not a cluster
    assert _get(tokens, "viewer+E1", _cluster_url(cluster)).json()["eligible"] is True


def test_requesting_a_cluster_write_up_needs_every_member_readable(w, cluster, monkeypatch):
    """FINDINGS_GENERATE_WRITEUP is admin-only today and an admin reads everything, so the 409 cannot
    be reached through a token. The handler is called directly with a user who lacks the read."""
    called = []

    def fake(db, *, key, user_id, force):
        called.append(key)
        raise cluster_writeup.NotConfigured("not configured here")

    monkeypatch.setattr(cluster_writeup, "request_writeup", fake)
    db = SessionLocal()
    try:
        def post(user):
            return findings_api.request_cluster_ai_writeup(
                finding_type=cluster.finding_type, source=cluster.source, fingerprint=cluster.fingerprint,
                request=None, background_tasks=None, force=False, db=db, current_user=user)

        admin = user_with("admin", id=uuid.uuid4())
        with pytest.raises(HTTPException) as reached:
            post(admin)
        assert reached.value.detail == "not configured here" and called == [cluster]   # got past the guard

        called.clear()
        with pytest.raises(HTTPException) as refused:
            post(user_with("integration_admin", id=uuid.uuid4()))
        assert refused.value.status_code == 409 and refused.value.detail == "cluster write-up unavailable"
        assert called == []                                                             # and no request was made
    finally:
        db.close()
