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
            status=status, user_agent_mode="stock", image_max_bytes=2097152, **kw,
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


# ── S5b-2b: image route, settings API ────────────────────────────────────────

import hashlib  # noqa: E402

from app.models.app_settings import AppSetting  # noqa: E402
from app.models.audit import AuditLog  # noqa: E402
from app.models.page_capture import USER_AGENT_MODES  # noqa: E402
from app.services import app_settings  # noqa: E402
from app.services import page_capture as pc  # noqa: E402

WEBP = b"RIFF" + b"\x10\x00\x00\x00" + b"WEBP" + b"VP8 " + b"\x00" * 32
_KEYS = (pc.REVISIT_DAYS_KEY, pc.USER_AGENT_MODE_KEY, pc.IDENTIFYING_UA_KEY, pc.MAX_IMAGE_BYTES_KEY,
         pc.QUEUE_TIMEOUT_KEY, pc.IMAGE_KEEP_COUNT_KEY, pc.PROXY_CONNECT_TIMEOUT_KEY,
         pc.PROXY_IDLE_TIMEOUT_KEY, pc.PROXY_MAX_CONNECTIONS_KEY)


@pytest.fixture
def cap_settings():
    db = SessionLocal()
    try:
        snaps = {k: (db.get(AppSetting, k).value if db.get(AppSetting, k) else None) for k in _KEYS}
    finally:
        db.close()
    yield
    s = SessionLocal()
    try:
        for k, v in snaps.items():
            row = s.get(AppSetting, k)
            if v is None and row is not None:
                s.delete(row)
            elif v is not None:
                app_settings.set_value(s, k, v)
        s.commit()
    finally:
        s.close()


def _image_row(w, env, candidate, data=WEBP, write=True):
    obs = w.db.query(Observer).filter(Observer.name == "page_capture").one()
    row = PageCapture(
        candidate_id=candidate.id, domain=candidate.value, observer_id=obs.id,
        requested_url=f"https://{candidate.value}/", status="done", finished_at=datetime.now(timezone.utc),
        user_agent_mode="stock", image_max_bytes=2097152,
    )
    w.db.add(row)
    w.db.flush()
    row.image_path = f"{row.id}.webp"
    row.image_bytes = len(data)
    row.image_sha256 = hashlib.sha256(data).hexdigest()
    w.db.commit()
    if write:
        (env["images"] / f"{row.id}.webp").write_bytes(data)
    return row


def _img(candidate_id, capture_id, headers):
    return client.get(f"/api/organizations/candidates/{candidate_id}/captures/{capture_id}/image", headers=headers)


def test_image_200_serves_exact_bytes_with_inert_headers(w, env):
    c = _candidate(w)
    row = _image_row(w, env, c)
    r = _img(c.id, row.id, w.headers(role=VIEWER))
    assert r.status_code == 200, r.text
    assert r.content == WEBP and r.headers["content-type"] == "image/webp"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "private, no-store"
    assert r.headers["content-security-policy"] == "default-src 'none'; sandbox"
    assert r.headers["content-disposition"] == f'inline; filename="{row.id}.webp"'


def test_image_404_for_another_candidates_capture(w, env):
    c, other = _candidate(w), _candidate(w)
    row = _image_row(w, env, other)
    assert _img(other.id, row.id, w.headers()).status_code == 200  # the file and row are servable
    assert _img(c.id, row.id, w.headers()).status_code == 404


def test_image_404_when_the_candidate_is_not_visible(w, env, monkeypatch):
    c = _candidate(w)
    row = _image_row(w, env, c)
    h = w.headers()
    assert _img(c.id, row.id, h).status_code == 200
    monkeypatch.setattr(read_scope, "domain_clause", lambda user, sc: sc.id != c.id)
    assert _img(c.id, row.id, h).status_code == 404


def test_image_404_when_image_path_is_none_or_row_missing(w, env):
    c = _candidate(w)
    row = _image_row(w, env, c)
    assert _img(c.id, row.id, w.headers()).status_code == 200
    row.image_path = None
    w.db.commit()
    assert _img(c.id, row.id, w.headers()).status_code == 404
    assert _img(c.id, uuid.uuid4(), w.headers()).status_code == 404


@pytest.mark.parametrize("tamper", ["../x.webp", "other"])
def test_image_404_when_image_path_is_tampered(w, env, tamper):
    c = _candidate(w)
    row = _image_row(w, env, c)
    assert _img(c.id, row.id, w.headers()).status_code == 200
    row.image_path = "../x.webp" if tamper == "../x.webp" else f"{uuid.uuid4()}.webp"
    w.db.commit()
    assert _img(c.id, row.id, w.headers()).status_code == 404


def test_image_404_for_a_symlink_a_sha_mismatch_and_an_oversize_file(w, env, tmp_path):
    c = _candidate(w)
    row = _image_row(w, env, c)
    h = w.headers()
    p = env["images"] / f"{row.id}.webp"
    assert _img(c.id, row.id, h).status_code == 200
    # sha mismatch
    p.write_bytes(WEBP[:-1] + b"\x01")
    assert _img(c.id, row.id, h).status_code == 404
    # symlink to a file whose sha matches
    p.unlink()
    elsewhere = tmp_path / "elsewhere.webp"
    elsewhere.write_bytes(WEBP)
    p.symlink_to(elsewhere)
    assert _img(c.id, row.id, h).status_code == 404
    # oversize vs the row cap, with a matching sha
    p.unlink()
    p.write_bytes(WEBP)
    assert _img(c.id, row.id, h).status_code == 200
    row.image_max_bytes = 8
    w.db.commit()
    assert _img(c.id, row.id, h).status_code == 404


def test_image_needs_a_login(w, env):
    c = _candidate(w)
    row = _image_row(w, env, c)
    assert client.get(f"/api/organizations/candidates/{c.id}/captures/{row.id}/image").status_code in (401, 403)


def test_post_audit_records_manual_and_response_carries_job_params(w, env):
    c = _candidate(w)
    r = _post(c.id, w.headers())
    assert r.status_code == 202, r.text
    assert r.json()["user_agent_mode"] == "stock" and r.json()["image_max_bytes"] == 2097152
    with SessionLocal() as s:
        rows = s.query(AuditLog).order_by(AuditLog.occurred_at.desc()).limit(30).all()
        changes = [x.detail.get("changes", {}) for x in rows if x.detail]
        assert any(c.get("capture") == r.json()["id"] and c.get("manual") is True for c in changes)


def test_409_message_for_unset_identifying_ua(w, env, cap_settings):
    h = w.headers()
    # the mode cannot be set to identifying through the API without a string: seed it directly
    with SessionLocal() as s:
        app_settings.set_value(s, pc.USER_AGENT_MODE_KEY, "identifying")
        app_settings.set_value(s, pc.IDENTIFYING_UA_KEY, "")
    c = _candidate(w)
    r = _post(c.id, h)
    assert r.status_code == 409
    assert r.json()["detail"]["rule"] == "capture:identifying_user_agent_unset" and r.json()["detail"]["message"]
    assert _counts(c.id)[0] == 0 and list((env["spool"] / "jobs").iterdir()) == []


# settings API

S = "/api/settings/capture"


def test_modes_literal_matches_the_model():
    from app.api.settings import CaptureSettingsUpdate
    from typing import get_args
    lit = CaptureSettingsUpdate.model_fields["user_agent_mode"].annotation
    assert {a for arg in get_args(lit) for a in get_args(arg)} - {None} == set(USER_AGENT_MODES)


def test_settings_get_defaults_and_permissions(w, cap_settings):
    r = client.get(S, headers=w.headers(role=VIEWER))
    assert r.status_code in (200, 403)
    ok = client.get(S, headers=w.headers())
    assert ok.status_code == 200
    assert set(ok.json()) == {"browse_revisit_days", "user_agent_mode", "identifying_user_agent",
                              "max_image_bytes", "queue_timeout_seconds", "image_keep_count",
                              "proxy_connect_timeout_seconds", "proxy_idle_timeout_seconds",
                              "proxy_max_connections"}
    assert client.get(S).status_code in (401, 403)
    assert client.put(S, headers=w.headers(role=VIEWER), json={"browse_revisit_days": 5}).status_code == 403
    assert client.put(S, json={"browse_revisit_days": 5}).status_code in (401, 403)


@pytest.mark.parametrize("bad", [
    {"browse_revisit_days": 0}, {"browse_revisit_days": 366}, {"max_image_bytes": 1000},
    {"max_image_bytes": pc.IMAGE_BYTES_CEILING + 1}, {"queue_timeout_seconds": 59},
    {"queue_timeout_seconds": 3601}, {"user_agent_mode": "sneaky"}, {"identifying_user_agent": "a\r\nb"},
    {"image_keep_count": 0}, {"image_keep_count": 51}, {"proxy_connect_timeout_seconds": 0},
    {"proxy_connect_timeout_seconds": 61}, {"proxy_idle_timeout_seconds": 4}, {"proxy_idle_timeout_seconds": 601},
    {"proxy_max_connections": 0}, {"proxy_max_connections": 1025},
    {"identifying_user_agent": "café"}, {"identifying_user_agent": "a" * 257}, {"browse_revisit_days": "x"},
])
def test_settings_put_bounds_are_422_and_write_nothing(w, cap_settings, bad):
    before = client.get(S, headers=w.headers()).json()
    assert client.put(S, headers=w.headers(), json=bad).status_code == 422
    assert client.get(S, headers=w.headers()).json() == before


def test_settings_cross_field_rule(w, cap_settings):
    h = w.headers()
    assert client.put(S, headers=h, json={"user_agent_mode": "stock", "identifying_user_agent": ""}).status_code == 200
    r = client.put(S, headers=h, json={"user_agent_mode": "identifying"})
    assert r.status_code == 422 and "identifying User-Agent" in r.json()["detail"]
    assert client.put(S, headers=h, json={"user_agent_mode": "identifying", "identifying_user_agent": ""}).status_code == 422
    assert client.get(S, headers=h).json()["user_agent_mode"] == "stock"
    # a string in the same request makes it valid
    ok = client.put(S, headers=h, json={"user_agent_mode": "identifying", "identifying_user_agent": "FabrikamScan/1.0"})
    assert ok.status_code == 200 and ok.json()["user_agent_mode"] == "identifying"
    # clearing the string while identifying is refused
    assert client.put(S, headers=h, json={"identifying_user_agent": ""}).status_code == 422
    assert client.get(S, headers=h).json()["identifying_user_agent"] == "FabrikamScan/1.0"


def test_settings_put_round_trips_and_audits_from_to(w, cap_settings):
    h = w.headers()
    base = client.put(S, headers=h, json={"browse_revisit_days": 30, "max_image_bytes": 2097152}).json()
    r = client.put(S, headers=h, json={"browse_revisit_days": 7, "queue_timeout_seconds": 900,
                                       "max_image_bytes": 2097152})
    assert r.status_code == 200, r.text
    assert r.json() == client.get(S, headers=h).json()
    assert r.json()["browse_revisit_days"] == 7 and r.json()["queue_timeout_seconds"] == 900
    assert r.json()["max_image_bytes"] == base["max_image_bytes"]
    with SessionLocal() as s:
        changes = [x.detail.get("changes", {}) for x in
                   s.query(AuditLog).order_by(AuditLog.occurred_at.desc()).limit(30).all() if x.detail]
        assert pc.revisit_days(s) == 7 and pc.queue_timeout_seconds(s) == 900
    hit = [c for c in changes if c.get("capture_browse_revisit_days") == {"from": 30, "to": 7}]
    assert hit and hit[0]["capture_queue_timeout_seconds"] == {"from": base["queue_timeout_seconds"], "to": 900}
    assert "capture_max_image_bytes" not in hit[0]  # only changed keys are audited


def test_settings_new_fields_round_trip_default_and_audit(w, cap_settings):
    h = w.headers()
    with SessionLocal() as s:
        for k in _KEYS[5:]:
            row = s.get(AppSetting, k)
            if row is not None:
                s.delete(row)
        s.commit()
    d = client.get(S, headers=h).json()
    assert (d["image_keep_count"], d["proxy_connect_timeout_seconds"], d["proxy_idle_timeout_seconds"],
            d["proxy_max_connections"]) == (3, 10, 30, 256)
    r = client.put(S, headers=h, json={"image_keep_count": 7, "proxy_connect_timeout_seconds": 20,
                                       "proxy_idle_timeout_seconds": 60, "proxy_max_connections": 100})
    assert r.status_code == 200, r.text
    assert r.json() == client.get(S, headers=h).json()
    assert (r.json()["image_keep_count"], r.json()["proxy_connect_timeout_seconds"],
            r.json()["proxy_idle_timeout_seconds"], r.json()["proxy_max_connections"]) == (7, 20, 60, 100)
    with SessionLocal() as s:
        assert pc.image_keep_count(s) == 7 and pc.proxy_max_connections(s) == 100
        changes = [x.detail.get("changes", {}) for x in
                   s.query(AuditLog).order_by(AuditLog.occurred_at.desc()).limit(30).all() if x.detail]
    hit = [c for c in changes if c.get("capture_image_keep_count") == {"from": 3, "to": 7}]
    assert hit
    assert hit[0]["capture_proxy_connect_timeout_seconds"] == {"from": 10, "to": 20}
    assert hit[0]["capture_proxy_idle_timeout_seconds"] == {"from": 30, "to": 60}
    assert hit[0]["capture_proxy_max_connections"] == {"from": 256, "to": 100}


def test_capture_response_carries_image_pruned_at(w, env):
    c = _candidate(w)
    row = _image_row(w, env, c)
    row.image_path = None
    row.image_pruned_at = datetime.now(timezone.utc)
    w.db.commit()
    live = _image_row(w, env, c)
    rows = {x["id"]: x for x in client.get(
        f"/api/organizations/candidates/{c.id}/captures", headers=w.headers()).json()}
    assert rows[str(row.id)]["image_pruned_at"] is not None and rows[str(row.id)]["has_image"] is False
    assert rows[str(live.id)]["image_pruned_at"] is None and rows[str(live.id)]["has_image"] is True
