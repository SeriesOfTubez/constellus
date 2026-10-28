"""Page-capture API (planning#280 S5b-2a): POST/GET /api/organizations/candidates/{id}/captures.
Spool directories are tmp_path. Synthetic names (fabrikam.com) only.

Run with:  backend/scripts/test.sh app/tests/test_page_capture_api.py
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.core.database import SessionLocal
from app.models.authorisation_decision import AuthorisationDecision
from app.models.observer import Observer
from app.models.page_capture import PageCapture, PageCaptureRequest
from app.models.user import UserRole
from app.services import read_scope
from app.tests import _decision_log
from app.tests._org_world import World, client, hexid
from app.tests.test_org_discovery_schema import _insert_candidate

VIEWER = UserRole.VIEWER.value


@pytest.fixture
def env(tmp_path, monkeypatch):
    d = {k: tmp_path / k for k in ("spool", "proxylog", "images")}
    for sub in ("jobs", "claimed", "results"):
        (d["spool"] / sub).mkdir(parents=True)
    d["proxylog"].mkdir()
    d["images"].mkdir()
    monkeypatch.setenv("CAPTURE_SPOOL_DIR", str(d["spool"]))
    monkeypatch.setenv("CAPTURE_PROXYLOG_DIR", str(d["proxylog"]))
    monkeypatch.setenv("CAPTURE_IMAGES_DIR", str(d["images"]))
    return d


@pytest.fixture
def w(env):
    mark = _decision_log.watermark()
    world = World()
    world.cap_candidates = []
    try:
        yield world
    finally:
        world.db.rollback()
        ids = world.db.query(PageCapture.id).filter(PageCapture.candidate_id.in_(world.cap_candidates))
        world.db.query(PageCaptureRequest).filter(PageCaptureRequest.capture_id.in_(ids)).delete(
            synchronize_session=False
        )
        world.db.query(PageCapture).filter(PageCapture.candidate_id.in_(world.cap_candidates)).delete(
            synchronize_session=False
        )
        world.db.commit()
        world.close()
        _decision_log.cleanup_since(mark)


def _candidate(w, root=None):
    c = w.candidate(root or w.ours(), value=f"cap280-{hexid()}.fabrikam.com")
    w.cap_candidates.append(c.id)
    return c


def _post(candidate_id, headers):
    return client.post(f"/api/organizations/candidates/{candidate_id}/captures", headers=headers)


def _get(candidate_id, headers):
    return client.get(f"/api/organizations/candidates/{candidate_id}/captures", headers=headers)


def _counts(candidate_id):
    db = SessionLocal()
    try:
        caps = db.query(PageCapture).filter(PageCapture.candidate_id == candidate_id).count()
        decisions = db.query(AuthorisationDecision).count()
        return caps, decisions
    finally:
        db.close()


def test_202_queues_a_job_and_hides_filesystem_paths(w, env):
    c = _candidate(w)
    r = _post(c.id, w.headers())
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["status"] == "queued" and body["domain"] == c.value and body["has_image"] is False
    assert "image_path" not in body
    assert [p.name for p in (env["spool"] / "jobs").iterdir()] == [f"{body['id']}.json"]


def test_409_archive_first_not_built_for_a_pre_close_target(w, env):
    root, _eng = w.deal()
    c = _candidate(w, root)
    r = _post(c.id, w.headers())
    assert r.status_code == 409
    d = r.json()["detail"]
    assert d["rule"] == "archive_first:not_built" and d["message"]
    assert list((env["spool"] / "jobs").iterdir()) == []


def test_409_for_an_asn_candidate(w, env):
    root = w.ours()
    cid = _insert_candidate(w.db, root.id, kind="asn", value="AS64500", rir="ripe", rir_handle="FABRIKAM-A")
    r = _post(cid, w.headers())
    assert r.status_code == 409, r.text
    assert r.json()["detail"]["rule"] == "candidate:not_domain"
    assert _counts(cid)[0] == 0


def test_409_when_already_queued(w, env):
    c = _candidate(w)
    h = w.headers()
    assert _post(c.id, h).status_code == 202
    r = _post(c.id, h)
    assert r.status_code == 409
    assert r.json()["detail"]["rule"] == "capture:already_queued"
    assert _counts(c.id)[0] == 1


def test_404_for_an_invisible_candidate_writes_nothing(w, env, monkeypatch):
    c = _candidate(w)
    h = w.headers()
    before_caps, before_decisions = _counts(c.id)
    monkeypatch.setattr(read_scope, "domain_clause", lambda user, sc: sc.id != c.id)
    assert _post(c.id, h).status_code == 404
    assert _get(c.id, h).status_code == 404
    assert _counts(c.id) == (before_caps, before_decisions)
    assert list((env["spool"] / "jobs").iterdir()) == []


def test_403_for_a_non_admin(w, env):
    c = _candidate(w)
    assert _post(c.id, w.headers(role=VIEWER)).status_code == 403
    assert _counts(c.id)[0] == 0


def test_get_lists_newest_first_with_request_counts_and_no_paths(w, env):
    c = _candidate(w)
    other = _candidate(w)
    obs = w.db.query(Observer).filter(Observer.name == "page_capture").one()
    now = datetime.now(timezone.utc)

    def cap(candidate, age, status, **kw):
        row = PageCapture(
            candidate_id=candidate.id, domain=candidate.value, observer_id=obs.id,
            requested_url=f"https://{candidate.value}/", requested_at=now - timedelta(minutes=age),
            status=status, **kw,
        )
        w.db.add(row)
        w.db.flush()
        return row

    old = cap(c, 10, "failed", failure_reason="queue_timeout", finished_at=now)
    new = cap(c, 1, "done", finished_at=now, image_path="/captures/secret.webp", pinned_ip="192.0.2.10",
              image_bytes=10)
    foreign = cap(other, 5, "failed", failure_reason="queue_timeout", finished_at=now)
    for row, n in ((new, 3), (old, 1), (foreign, 4)):
        for seq in range(n):
            w.db.add(PageCaptureRequest(capture_id=row.id, seq=seq, decision="allow"))
    w.db.commit()

    r = _get(c.id, w.headers(role=VIEWER))
    assert r.status_code == 200, r.text
    rows = r.json()
    assert [x["id"] for x in rows] == [str(new.id), str(old.id)]
    assert [x["request_count"] for x in rows] == [3, 1]
    assert rows[0]["has_image"] is True and rows[1]["has_image"] is False
    assert rows[0]["pinned_ip"] == "192.0.2.10"
    assert "image_path" not in r.text and "secret.webp" not in r.text
    assert _get(_candidate(w).id, w.headers()).json() == []


def test_503_when_the_spool_is_unavailable(w, env):
    """A missing spool directory is a server fault: 503, not a 409 conflict. The
    row was inserted (the path was reached) and is failed spool_unavailable."""
    (env["spool"] / "jobs").rmdir()
    c = _candidate(w)
    r = _post(c.id, w.headers())
    assert r.status_code == 503, r.text
    assert r.json()["detail"]["rule"] == "spool_unavailable"
    with SessionLocal() as s:
        rows = s.query(PageCapture).filter(PageCapture.candidate_id == c.id).all()
        assert [(x.status, x.failure_reason) for x in rows] == [("failed", "spool_unavailable")]
