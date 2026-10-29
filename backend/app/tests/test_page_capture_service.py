"""Page-capture service (planning#280 S5b-2a): `request_capture`, `ingest_results`,
`sweep_timeouts`. Spool directories are tmp_path; fixtures use the wire shape of
`docs/architecture/capture-spool.md` and the proxy's real log fields. Synthetic
names (fabrikam.com) and RFC 5737 addresses only.

Run with:  backend/scripts/test.sh app/tests/test_page_capture_service.py
"""

import json
import re
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.core.database import SessionLocal
from app.models.authorisation_decision import AuthorisationDecision
from app.models.observer import Observer
from app.models.page_capture import PageCapture, PageCaptureRequest
from app.models.scope_candidate import ScopeCandidate
from app.services import page_capture as pc
from app.tests import _decision_log
from app.tests._engagement import make_engagement
from app.tests._org_world import World, hexid

WEBP = b"RIFF" + b"\x10\x00\x00\x00" + b"WEBP" + b"VP8 " + b"\x00" * 32
PROXY_IP = "192.0.2.10"
OTHER_IP = "198.51.100.7"


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
    monkeypatch.setenv("CAPTURE_PROXY_KEY", "k" * 32)  # jobs carry a per-job proxy token (v3)
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
        world.db.query(PageCaptureRequest).filter(
            PageCaptureRequest.capture_id.in_(
                world.db.query(PageCapture.id).filter(PageCapture.candidate_id.in_(world.cap_candidates))
            )
        ).delete(synchronize_session=False)
        world.db.query(PageCapture).filter(PageCapture.candidate_id.in_(world.cap_candidates)).delete(
            synchronize_session=False
        )
        world.db.commit()
        world.close()
        _decision_log.cleanup_since(mark)


def _dom() -> str:
    return f"cap280-{hexid()}.fabrikam.com"


def _candidate(w, root=None, value=None):
    root = root or w.ours()
    c = w.candidate(root, value=value or _dom())
    w.cap_candidates.append(c.id)
    return c


def _queued(w, domain=None) -> PageCapture:
    """A queued row inserted directly (the ingest tests do not need request_capture)."""
    c = _candidate(w, value=domain)
    obs = w.db.query(Observer).filter(Observer.name == "page_capture").one()
    row = PageCapture(
        candidate_id=c.id, domain=c.value, observer_id=obs.id, requested_url=f"https://{c.value}/",
        requested_by_id=w.user().id, user_agent_mode="stock", image_max_bytes=pc.DEFAULT_MAX_IMAGE_BYTES,
    )
    w.db.add(row)
    w.db.commit()
    return row


def _result(row, **over) -> dict:
    r = {
        "v": 1, "capture_id": str(row.id), "requested_url": row.requested_url,
        "final_url": f"https://www.{row.domain}/home", "status": 200,
        "redirect_chain": [{"url": row.requested_url, "status": 301}],
        "title": "Fabrikam Home",
        "cert": {
            "subject": f"CN={row.domain}", "issuer": "CN=Example CA", "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2027-01-01T00:00:00Z", "san_dns": [row.domain.upper(), f"www.{row.domain}"],
            "sha256": "ab" * 32, "extra": "dropped",
        },
        "requests": [{"url": row.requested_url, "resource_type": "Document", "failure": None, "is_navigation": True}],
        "screenshot": {"file": "screenshot.webp", "bytes": len(WEBP), "quality": 80},
        "screenshot_omitted_reason": None, "user_agent": "TestAgent/1.0", "error": None,
    }
    r.update(over)
    return r


def _drop_result(env, row, result=None, image=WEBP, raw=None, name=None):
    d = env["spool"] / "results" / (name or str(row.id))
    d.mkdir()
    (d / "result.json").write_bytes(raw if raw is not None else json.dumps(result or _result(row)).encode())
    if image is not None:
        (d / "screenshot.webp").write_bytes(image)
    return d


def _plog(env, row, records, raw_extra=b""):
    lines = [json.dumps(r) for r in records]
    p = env["proxylog"] / f"{row.id}.jsonl"
    p.write_bytes(("\n".join(lines) + "\n").encode() + raw_extra)
    return p


def _rec(row, **over):
    r = {
        "ts": datetime.now(timezone.utc).isoformat(), "capture_id": str(row.id), "method": "GET", "scheme": "https",
        "host": f"www.{row.domain}", "port": 443, "resolved": [PROXY_IP], "pinned_ip": PROXY_IP,
        "decision": "allow", "reason": "ok", "bytes_up": 100, "bytes_down": 2000, "duration_ms": 12,
    }
    r.update(over)
    return r


def _later() -> datetime:
    return datetime.now(timezone.utc) + timedelta(seconds=60)


def _fresh(row_id) -> PageCapture:
    db = SessionLocal()
    try:
        row = db.get(PageCapture, row_id)
        db.expunge(row)
        return row
    finally:
        db.close()


def _requests(row_id) -> list[PageCaptureRequest]:
    db = SessionLocal()
    try:
        rows = db.query(PageCaptureRequest).filter(PageCaptureRequest.capture_id == row_id).order_by(
            PageCaptureRequest.seq
        ).all()
        for r in rows:
            db.expunge(r)
        return rows
    finally:
        db.close()


def _ingest(w, now=None) -> int:
    return pc.ingest_results(w.db, now=now or _later())


# ── ingest: happy path ───────────────────────────────────────────────────────


def test_ingest_retires_the_job_on_every_resolution(w, env):
    """Done, invalid and discarded results all delete `jobs/<id>.json` (and a claim if one
    is left): on S3 there is no claim file for the worker to remove, so the backend's
    delete is what stops a job being pulled again. An unrelated queued job stays.
    planning#318 S1b."""
    done, bad = _queued(w), _queued(w)
    orphan = uuid.uuid4()  # a result for a row that does not exist: the discard path
    _drop_result(env, done)
    _drop_result(env, bad, raw=b"not json")
    _drop_result(env, done, name=str(orphan))
    jobs, claimed = env["spool"] / "jobs", env["spool"] / "claimed"
    for i in (done.id, bad.id, orphan):
        (jobs / f"{i}.json").write_text("x")
        (claimed / f"{i}.json").write_text("x")
    other = uuid.uuid4()
    (jobs / f"{other}.json").write_text("x")

    assert _ingest(w) == 2  # the orphan is discarded, not resolved
    assert (_fresh(done.id).status, _fresh(bad.id).status) == ("done", "failed")
    for i in (done.id, bad.id, orphan):
        assert not (jobs / f"{i}.json").exists() and not (claimed / f"{i}.json").exists()
        assert not (env["spool"] / "results" / str(i)).exists()
    assert (jobs / f"{other}.json").exists()


def test_happy_path_ingests_fields_requests_image_and_cleans_up(w, env):
    row = _queued(w)
    d = _drop_result(env, row)
    plog = _plog(env, row, [
        _rec(row, host="cdn.fabrikam.com", pinned_ip=OTHER_IP, resolved=[OTHER_IP, "not-an-ip"]),
        _rec(row, capture_id=str(uuid.uuid4()), pinned_ip="203.0.113.9"),  # another capture's record
        _rec(row, decision="deny", pinned_ip=None, reason="blocked"),  # right host, not allowed
        _rec(row),  # the final document
        _rec(row, pinned_ip="203.0.113.66"),  # a later allow for the same host: not picked
    ], raw_extra=b"not json\n")

    assert _ingest(w) == 1

    r = _fresh(row.id)
    assert (r.status, r.failure_reason, r.finished_at is not None) == ("done", None, True)
    assert r.final_url == f"https://www.{row.domain}/home" and r.http_status == 200
    assert r.redirect_chain == [{"url": row.requested_url, "status": 301}]
    assert r.title == "Fabrikam Home" and r.user_agent == "TestAgent/1.0" and r.error is None
    assert r.cert == {
        "subject": f"CN={row.domain}", "issuer": "CN=Example CA", "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2027-01-01T00:00:00Z", "san_dns": [row.domain, f"www.{row.domain}"], "sha256": "ab" * 32,
    }
    assert r.cert_san_dns == [row.domain, f"www.{row.domain}"] and r.cert_sha256 == "ab" * 32
    assert str(r.pinned_ip) == PROXY_IP and r.proxy_log_truncated is False
    assert r.image_path == f"{row.id}.webp" and r.image_bytes == len(WEBP) and r.image_quality == 80
    assert r.image_sha256 and r.image_omitted_reason is None
    assert (env["images"] / f"{row.id}.webp").read_bytes() == WEBP
    assert oct((env["images"] / f"{row.id}.webp").stat().st_mode & 0o777) == oct(0o640)

    reqs = _requests(row.id)
    assert [q.seq for q in reqs] == [0, 1, 2, 3]  # the foreign-capture record and the malformed line are gone
    assert [q.host for q in reqs][:1] == ["cdn.fabrikam.com"]
    assert [str(i) for i in reqs[0].resolved] == [OTHER_IP]  # only valid IPs survive
    assert reqs[1].decision == "deny" and reqs[1].pinned_ip is None
    assert (reqs[3].bytes_up, reqs[3].bytes_down, reqs[3].duration_ms) == (100, 2000, 12)

    assert not d.exists() and not plog.exists()


def test_result_json_cannot_supply_pinned_ip(w, env):
    row = _queued(w)
    res = _result(row)
    res["pinned_ip"] = "203.0.113.9"
    res["cert"]["pinned_ip"] = "203.0.113.9"
    _drop_result(env, row, res)
    assert _ingest(w) == 1
    r = _fresh(row.id)
    assert r.status == "done" and r.pinned_ip is None  # no proxy log -> no pinned IP


# ── ingest: refusals ─────────────────────────────────────────────────────────


def _assert_failed(row, reason):
    r = _fresh(row.id)
    assert (r.status, r.failure_reason) == ("failed", reason) and r.finished_at is not None
    return r


def test_symlinked_result_json_is_refused(w, env):
    row = _queued(w)
    d = _drop_result(env, row, image=None)
    real = env["spool"] / "elsewhere.json"
    real.write_text(json.dumps(_result(row)))
    (d / "result.json").unlink()
    (d / "result.json").symlink_to(real)
    assert _ingest(w) == 1
    _assert_failed(row, "invalid_result")
    assert not d.exists() and real.exists()  # the link target was never followed or deleted


def test_symlinked_screenshot_is_refused(w, env):
    row = _queued(w)
    d = _drop_result(env, row, image=None)
    target = env["spool"] / "secret.bin"
    target.write_bytes(WEBP)
    (d / "screenshot.webp").symlink_to(target)
    assert _ingest(w) == 1
    r = _assert_failed(row, "invalid_result")
    assert r.image_path is None and not (env["images"] / f"{row.id}.webp").exists()
    assert target.exists()


def test_oversize_result_is_refused(w, env):
    row = _queued(w)
    big = json.dumps(_result(row, title="x" * pc.RESULT_MAX_BYTES)).encode()
    _drop_result(env, row, raw=big, image=None)
    assert _ingest(w) == 1
    _assert_failed(row, "invalid_result")


def test_bad_magic_keeps_the_capture_but_omits_the_image(w, env):
    row = _queued(w)
    _drop_result(env, row, image=b"RIFF\x00\x00\x00\x00WAVEjunk" + b"\x00" * 20)
    assert _ingest(w) == 1
    r = _fresh(row.id)
    assert r.status == "done" and r.image_path is None and r.image_omitted_reason == "invalid_image"
    assert not (env["images"] / f"{row.id}.webp").exists()


def test_oversize_image_keeps_the_capture_but_omits_the_image(w, env):
    row = _queued(w)
    _drop_result(env, row, image=WEBP + b"\x00" * pc.DEFAULT_MAX_IMAGE_BYTES)
    assert _ingest(w) == 1
    r = _fresh(row.id)
    assert r.status == "done" and r.image_omitted_reason == "invalid_image"


def test_claimed_screenshot_missing_is_invalid_image(w, env):
    row = _queued(w)
    _drop_result(env, row, image=None)
    assert _ingest(w) == 1
    assert _fresh(row.id).image_omitted_reason == "invalid_image"


def test_null_screenshot_carries_the_workers_omitted_reason(w, env):
    row = _queued(w)
    _drop_result(env, row, _result(row, screenshot=None, screenshot_omitted_reason="over_cap"), image=None)
    assert _ingest(w) == 1
    r = _fresh(row.id)
    assert r.status == "done" and r.image_omitted_reason == "over_cap" and r.image_path is None


def test_result_capture_id_mismatch_is_refused(w, env):
    row = _queued(w)
    _drop_result(env, row, _result(row, capture_id=str(uuid.uuid4())))
    assert _ingest(w) == 1
    _assert_failed(row, "invalid_result")


def test_unknown_id_is_discarded_without_touching_the_db(w, env):
    row = _queued(w)  # a bystander that must stay queued
    stranger = uuid.uuid4()
    d = env["spool"] / "results" / str(stranger)
    d.mkdir()
    (d / "result.json").write_text("{}")
    plog = env["proxylog"] / f"{stranger}.jsonl"
    plog.write_text("{}\n")
    assert _ingest(w) == 0
    assert not d.exists() and not plog.exists()
    assert _fresh(row.id).status == "queued"


def test_a_result_for_a_non_queued_row_is_discarded(w, env):
    row = _queued(w)
    row.status, row.failure_reason, row.finished_at = "failed", "timeout", datetime.now(timezone.utc)
    w.db.commit()
    d = _drop_result(env, row)
    plog = _plog(env, row, [_rec(row)])
    assert _ingest(w) == 0
    assert not d.exists() and not plog.exists()
    r = _fresh(row.id)
    assert r.failure_reason == "timeout" and r.final_url is None and _requests(row.id) == []


def test_a_young_result_is_left_alone_until_it_ages(w, env):
    row = _queued(w)
    d = _drop_result(env, row)
    assert pc.ingest_results(w.db, now=datetime.now(timezone.utc)) == 0
    assert d.exists() and _fresh(row.id).status == "queued"
    assert pc.ingest_results(w.db, now=_later()) == 1  # the same directory, once old enough
    assert not d.exists() and _fresh(row.id).status == "done"


def test_a_non_uuid_directory_is_removed_and_dot_names_are_ignored(w, env):
    (env["spool"] / "results" / "not-a-uuid").mkdir()
    (env["spool"] / "results" / ".hidden").mkdir()
    upper = env["spool"] / "results" / str(uuid.uuid4()).upper()
    upper.mkdir()
    assert _ingest(w) == 0
    assert not (env["spool"] / "results" / "not-a-uuid").exists() and not upper.exists()
    assert (env["spool"] / "results" / ".hidden").exists()


def test_a_non_uuid_symlink_is_unlinked_not_followed(w, env):
    victim = env["spool"] / "victim"
    victim.mkdir()
    (victim / "keep").write_text("x")
    (env["spool"] / "results" / "evil").symlink_to(victim)
    assert _ingest(w) == 0
    assert not (env["spool"] / "results" / "evil").is_symlink() and (victim / "keep").exists()


def test_a_symlinked_result_directory_for_a_queued_row_is_refused(w, env):
    row = _queued(w)
    victim = env["spool"] / "victim"
    victim.mkdir()
    (victim / "result.json").write_text(json.dumps(_result(row)))
    (env["spool"] / "results" / str(row.id)).symlink_to(victim)
    assert pc.ingest_results(w.db, now=_later()) == 1
    _assert_failed(row, "invalid_result")
    assert (victim / "result.json").exists()


def test_capture_error_fails_the_row_but_keeps_the_fields(w, env):
    row = _queued(w)
    _drop_result(env, row, _result(row, error="net::ERR_NAME_NOT_RESOLVED", status=None, cert=None), image=None)
    assert _ingest(w) == 1
    r = _assert_failed(row, "capture_error")
    assert r.error == "net::ERR_NAME_NOT_RESOLVED" and r.final_url and r.title == "Fabrikam Home"


def test_field_sanitising(w, env):
    row = _queued(w)
    res = _result(
        row, final_url="javascript:alert(1)", status=99, title="t" * 5000 + "\x00",
        redirect_chain=[{"url": "ftp://x", "status": 301}, {"url": "https://a.fabrikam.com/", "status": "x"}],
        user_agent="u" * 600,
        cert={"subject": "s" * 2000, "san_dns": ["ok.fabrikam.com", 5, "d" * 300], "sha256": "zz"},
    )
    _drop_result(env, row, res, image=None)
    assert _ingest(w) == 1
    r = _fresh(row.id)
    assert r.final_url is None and r.http_status is None
    assert len(r.title) == 1024 and len(r.user_agent) == 512
    assert r.redirect_chain == [
        {"url": "ftp://x", "status": 301}, {"url": "https://a.fabrikam.com/", "status": None},
    ]
    assert r.cert == {"san_dns": ["ok.fabrikam.com"]} and r.cert_sha256 is None


def test_truncated_proxylog_is_flagged(w, env, monkeypatch):
    monkeypatch.setattr(pc, "PROXYLOG_MAX_BYTES", 600)
    row = _queued(w)
    _drop_result(env, row)
    _plog(env, row, [_rec(row) for _ in range(5)])
    assert _ingest(w) == 1
    r = _fresh(row.id)
    assert r.status == "done" and r.proxy_log_truncated is True
    assert 1 <= len(_requests(row.id)) < 5


def test_an_exception_in_ingest_fails_that_row_only(w, env, monkeypatch):
    bad, good = _queued(w), _queued(w)
    _drop_result(env, bad)
    _drop_result(env, good)
    real = pc._ingest_proxylog

    def boom(db, row, path):
        if row.id == bad.id:
            raise RuntimeError("boom")
        return real(db, row, path)

    monkeypatch.setattr(pc, "_ingest_proxylog", boom)
    assert _ingest(w) == 2
    _assert_failed(bad, "ingest_error")
    assert _fresh(good.id).status == "done"


# ── timeout sweep ────────────────────────────────────────────────────────────


def test_timeout_sweep_fails_old_queued_rows_and_removes_job_and_claim(w, env):
    old, fresh = _queued(w), _queued(w)
    old.requested_at = datetime.now(timezone.utc) - timedelta(seconds=pc.DEFAULT_QUEUE_TIMEOUT_S + 60)
    w.db.commit()
    for sub in ("jobs", "claimed"):
        (env["spool"] / sub / f"{old.id}.json").write_text("{}")
    (env["spool"] / "jobs" / f"{fresh.id}.json").write_text("{}")
    assert pc.sweep_timeouts(w.db) == 1
    r = _assert_failed(old, "timeout")
    assert r.finished_at is not None
    assert not (env["spool"] / "jobs" / f"{old.id}.json").exists()
    assert not (env["spool"] / "claimed" / f"{old.id}.json").exists()
    assert _fresh(fresh.id).status == "queued" and (env["spool"] / "jobs" / f"{fresh.id}.json").exists()


def test_timeout_sweep_also_removes_the_result_and_proxylog_of_the_swept_row_only(w, env):
    old, other = _queued(w), _queued(w)
    old.requested_at = datetime.now(timezone.utc) - timedelta(seconds=pc.DEFAULT_QUEUE_TIMEOUT_S + 60)
    w.db.commit()
    (env["spool"] / "jobs" / f"{old.id}.json").write_text("{}")
    old_dir = _drop_result(env, old)
    other_dir = _drop_result(env, other)
    old_log = _plog(env, old, [])
    other_log = _plog(env, other, [])
    assert old_dir.exists() and old_log.exists()  # the plant reached the sweep
    assert pc.sweep_timeouts(w.db) == 1
    assert not old_dir.exists() and not old_log.exists()
    assert not (env["spool"] / "jobs" / f"{old.id}.json").exists()
    assert (other_dir / "result.json").exists() and other_log.exists()


def test_timeout_sweep_leaves_a_recent_row_alone(w, env):
    row = _queued(w)
    (env["spool"] / "jobs" / f"{row.id}.json").write_text("{}")
    assert pc.sweep_timeouts(w.db, now=datetime.now(timezone.utc) + timedelta(seconds=pc.DEFAULT_QUEUE_TIMEOUT_S - 60)) == 0
    assert _fresh(row.id).status == "queued" and (env["spool"] / "jobs" / f"{row.id}.json").exists()


# ── request_capture ──────────────────────────────────────────────────────────


def _no_job_files(env):
    return [p for p in (env["spool"] / "jobs").iterdir()]


def _rows_for(candidate_id):
    db = SessionLocal()
    try:
        return db.query(PageCapture).filter(PageCapture.candidate_id == candidate_id).count()
    finally:
        db.close()


def test_request_capture_commits_the_row_before_the_job_exists_and_writes_the_contract_job(w, env, monkeypatch):
    c = _candidate(w)
    user = w.user()
    seen = {}
    real_rename = os.rename

    def spy(src, dst):
        db2 = SessionLocal()  # a second session: sees only what is committed
        try:
            seen["row_visible"] = db2.query(PageCapture).filter(PageCapture.candidate_id == c.id).count() == 1
            seen["status"] = db2.query(PageCapture.status).filter(PageCapture.candidate_id == c.id).scalar()
        finally:
            db2.close()
        seen["tmp_name"] = os.path.basename(src)
        seen["mode"] = os.stat(src).st_mode & 0o777
        return real_rename(src, dst)

    monkeypatch.setattr(pc.os, "rename", spy)
    before = int(pc.time.time())
    row = pc.request_capture(w.db, candidate_id=c.id, user=user, manual=True)

    assert seen["row_visible"] is True and seen["status"] == "queued" and seen["tmp_name"] == f".{row.id}.tmp"
    assert seen["mode"] & 0o117 == 0  # owner/group read-write at most, nothing for others, no execute
    job_path = env["spool"] / "jobs" / f"{row.id}.json"
    written = json.loads(job_path.read_text())
    exp = written["proxy_expires"]
    lo = before + pc.queue_timeout_seconds(w.db) + pc.CREDENTIAL_RUN_MARGIN_S
    assert lo <= exp <= lo + 10  # minted at request time, not a constant
    assert written == {
        "v": 3, "capture_id": str(row.id), "url": f"https://{c.value}/", "user_agent_mode": "stock",
        "mode": "live", "proxy_token": pc.proxy_token(str(row.id), "live", exp), "proxy_expires": exp,
        "viewport": {"width": 1280, "height": 800}, "max_image_bytes": 2097152, "webp_qualities": [80, 60, 40],
    }
    assert re.fullmatch(r"[0-9a-f]{64}", written["proxy_token"])
    assert len(job_path.read_bytes()) <= pc.JOB_MAX_BYTES
    assert [p.name for p in _no_job_files(env)] == [job_path.name]  # the tmp name is gone
    r = _fresh(row.id)
    assert (r.status, r.domain, r.requested_url, r.requested_by_id) == ("queued", c.value, f"https://{c.value}/", user.id)
    obs = w.db.query(Observer).filter(Observer.name == "page_capture").one()
    assert r.observer_id == obs.id


def test_a_restricting_posture_with_an_unavailable_archive_refuses_and_writes_nothing(w, env, monkeypatch):
    from app.tests.test_page_capture_archive import mock_wayback

    seen = mock_wayback(monkeypatch, status=429)
    root = w.entity()
    eng = make_engagement(w.db, "pre_close", subject_entity_id=root.id)
    w.engagements.append(eng.id)
    w.db.refresh(root)
    c = _candidate(w, root)
    with pytest.raises(pc.CaptureRefused) as e:
        pc.request_capture(w.db, candidate_id=c.id, user=w.user(), manual=True)
    assert e.value.rule == "archive:lookup_unavailable"
    assert len(seen) == 1  # the lookup was reached
    assert _rows_for(c.id) == 0 and _no_job_files(env) == []


def test_a_second_request_while_one_is_queued_is_refused(w, env):
    c = _candidate(w)
    first = pc.request_capture(w.db, candidate_id=c.id, user=w.user(), manual=True)
    with pytest.raises(pc.CaptureRefused) as e:
        pc.request_capture(w.db, candidate_id=c.id, user=w.user(), manual=True)
    assert e.value.rule == "capture:already_queued"
    assert _rows_for(c.id) == 1 and [p.name for p in _no_job_files(env)] == [f"{first.id}.json"]


def test_an_overlong_domain_is_refused_before_any_write(w, env):
    # The DB's CHECK already enforces per-label shape, so the one shape it lets through that the
    # producer's own validator refuses is a name over 253 characters in total.
    root = w.ours()
    long_name = ".".join(["a" * 63] * 4) + ".com"
    assert len(long_name) > 253
    c = ScopeCandidate(root_entity_id=root.id, kind="domain", value=long_name)
    w.db.add(c)
    w.db.commit()
    w.cap_candidates.append(c.id)
    with pytest.raises(pc.CaptureRefused) as e:
        pc.request_capture(w.db, candidate_id=c.id, user=w.user(), manual=True)
    assert e.value.rule == "candidate:invalid_domain"
    assert _rows_for(c.id) == 0 and _no_job_files(env) == []


@pytest.mark.parametrize("bad", [
    "FABRIKAM.com", "nodot", "a..fabrikam.com", "-a.fabrikam.com", "fabrikam.com.", "fabrikam.com:8080",
    "fabrikam.com/x", "u@fabrikam.com", "192.0.2.1", "a_b.fabrikam.com", ("a" * 64) + ".fabrikam.com", "",
    "fabrikam.com\n", " fabrikam.com", None, ".".join(["a" * 63] * 4) + ".com",
])
def test_hostname_validator_rejects(bad):
    assert pc._valid_hostname(bad) is False


def test_a_gate_denial_queues_nothing_and_is_logged(w, env):
    root = w.ours()
    c = _candidate(w, root)
    w.db.query(Observer).filter(Observer.name == "page_capture").update({"noise_class": "silent"})
    w.db.commit()
    try:
        with pytest.raises(pc.CaptureRefused) as e:
            pc.request_capture(w.db, candidate_id=c.id, user=w.user(), manual=True)
    finally:
        w.db.rollback()
        w.db.query(Observer).filter(Observer.name == "page_capture").update({"noise_class": "browse"})
        w.db.commit()
    assert e.value.rule == "observer:noise_mismatch"
    assert _rows_for(c.id) == 0 and _no_job_files(env) == []
    db = SessionLocal()
    try:
        assert db.query(AuthorisationDecision).filter(
            AuthorisationDecision.evidence_snapshot["candidate_id"].astext == str(c.id)
        ).count() == 1
    finally:
        db.close()


def test_an_unwritable_spool_marks_the_row_failed(w, env, monkeypatch):
    c = _candidate(w)
    (env["spool"] / "jobs").rmdir()
    (env["spool"] / "jobs").write_text("a file where the jobs directory should be")
    with pytest.raises(pc.CaptureRefused) as e:
        pc.request_capture(w.db, candidate_id=c.id, user=w.user(), manual=True)
    assert e.value.rule == "spool_unavailable"
    db = SessionLocal()
    try:
        (r,) = db.query(PageCapture).filter(PageCapture.candidate_id == c.id).all()
        assert (r.status, r.failure_reason) == ("failed", "spool_unavailable") and r.finished_at is not None
    finally:
        db.close()


def test_request_capture_fails_closed_on_unknown_store(w, env, monkeypatch):
    c = _candidate(w)
    monkeypatch.setenv("CAPTURE_STORE", "bogus")
    with pytest.raises(pc.CaptureRefused) as e:
        pc.request_capture(w.db, candidate_id=c.id, user=w.user(), manual=True)
    assert e.value.rule == "spool_unavailable"
    db = SessionLocal()
    try:
        (r,) = db.query(PageCapture).filter(PageCapture.candidate_id == c.id).all()
        assert (r.status, r.failure_reason) == ("failed", "spool_unavailable") and r.finished_at is not None
    finally:
        db.close()
    assert not list(_no_job_files(env))


def test_job_carries_store_fields_when_the_store_provides_them(w, env, monkeypatch):
    c = _candidate(w)
    calls, written = [], {}
    fields = {"store": {"result_put": "u1", "screenshot_put": "u2", "expires": 5}}

    class Fake:
        def check_spool(self):
            pass

        def job_fields(self, capture_id, expires_at):
            calls.append((capture_id, expires_at))
            return fields

        def put_job(self, capture_id, payload):
            written[capture_id] = payload

    monkeypatch.setattr(pc, "get_store", lambda: Fake())
    row = pc.request_capture(w.db, candidate_id=c.id, user=w.user(), manual=True)
    assert list(written) == [str(row.id)]  # the put was reached
    job = json.loads(written[str(row.id)])
    assert job["store"] == fields["store"] and job["v"] == 3
    assert calls == [(str(row.id), job["proxy_expires"])]


def test_hostname_validator_accepts_ordinary_names():
    for ok in ("fabrikam.com", "a-b.c-d.fabrikam.com", "xn--bcher-kva.example.com", "a.b"):
        assert pc._valid_hostname(ok)


def test_a_missing_spool_directory_marks_the_row_failed(w, env):
    c = _candidate(w)
    (env["spool"] / "claimed").rmdir()
    with pytest.raises(pc.CaptureRefused) as e:
        pc.request_capture(w.db, candidate_id=c.id, user=w.user(), manual=True)
    assert e.value.rule == "spool_unavailable"
    assert _rows_for(c.id) == 1 and _no_job_files(env) == []


def test_a_symlinked_spool_directory_is_refused(w, env):
    c = _candidate(w)
    (env["spool"] / "results").rmdir()
    (env["spool"] / "results").symlink_to(env["images"])
    with pytest.raises(pc.CaptureRefused) as e:
        pc.request_capture(w.db, candidate_id=c.id, user=w.user(), manual=True)
    assert e.value.rule == "spool_unavailable"


def test_the_unique_index_closes_the_race_between_the_precheck_and_the_insert(w, env, monkeypatch):
    c = _candidate(w)
    obs = w.db.query(Observer).filter(Observer.name == "page_capture").one()
    real = pc._valid_hostname

    def a_concurrent_request_lands_first(value):
        db2 = SessionLocal()
        try:
            db2.add(PageCapture(candidate_id=c.id, domain=c.value, observer_id=obs.id, requested_url="https://x.fabrikam.com/", user_agent_mode="stock", image_max_bytes=pc.DEFAULT_MAX_IMAGE_BYTES))
            db2.commit()
        finally:
            db2.close()
        return real(value)

    monkeypatch.setattr(pc, "_valid_hostname", a_concurrent_request_lands_first)
    with pytest.raises(pc.CaptureRefused) as e:
        pc.request_capture(w.db, candidate_id=c.id, user=w.user(), manual=True)
    assert e.value.rule == "capture:already_queued"  # reached via the index, not the pre-check
    db = SessionLocal()
    try:
        assert db.query(PageCapture).filter(PageCapture.candidate_id == c.id, PageCapture.status == "queued").count() == 1
    finally:
        db.close()
    assert _no_job_files(env) == []


# ── pinned_ip selection, orphan image, tick ──────────────────────────────────


def test_pinned_ip_follows_the_final_urls_explicit_port_and_ignores_denied_records(w, env):
    row = _queued(w)
    _drop_result(env, row, _result(row, final_url=f"https://www.{row.domain}:8443/x"))
    _plog(env, row, [
        _rec(row, port=443, pinned_ip="203.0.113.9"),  # right host, wrong port
        _rec(row, port=8443, decision="deny", pinned_ip="203.0.113.66"),  # right host and port, denied
        _rec(row, port=8443, pinned_ip=PROXY_IP),
    ])
    assert _ingest(w) == 1
    assert str(_fresh(row.id).pinned_ip) == PROXY_IP


@pytest.mark.parametrize("url,ok", [
    ("https://user:pw@fabrikam.com/", False), ("https://fabrikam.com:99999/", False), ("https://[2001:db8::1]/", True),
    ("ftp://fabrikam.com/", False), ("https:///nohost", False), ("https://fabrikam.com", True),
])
def test_final_url_parsing(url, ok):
    assert (pc._http_url(url) is not None) is ok


def test_an_orphan_image_is_removed_when_the_commit_fails(w, env, monkeypatch):
    row = _queued(w)
    _drop_result(env, row)
    real_commit = w.db.commit
    calls = {"n": 0}

    def commit():
        calls["n"] += 1
        if calls["n"] == 1:
            assert (env["images"] / f"{row.id}.webp").exists()  # the image was stored before the failing commit
            raise RuntimeError("commit failed")
        return real_commit()

    monkeypatch.setattr(w.db, "commit", commit)
    assert _ingest(w) == 1
    assert not (env["images"] / f"{row.id}.webp").exists()
    r = _assert_failed(row, "ingest_error")
    assert r.image_path is None


def test_an_orphan_image_is_removed_when_a_later_guard_rejects(w, env, monkeypatch):
    row = _queued(w)
    _drop_result(env, row)

    def reject(*a, **k):
        raise pc._Invalid("invalid_result")

    monkeypatch.setattr(pc, "_ingest_proxylog", lambda *a, **k: None)  # proxylog runs before the image; keep it inert
    real_store = pc._store_image

    def store_then_reject(*a, **k):
        real_store(*a, **k)
        raise pc._Invalid("invalid_result")

    monkeypatch.setattr(pc, "_store_image", store_then_reject)
    assert _ingest(w) == 1
    assert not (env["images"] / f"{row.id}.webp").exists()
    _assert_failed(row, "invalid_result")


def test_tick_runs_on_an_empty_spool(w, env):
    pc.tick()  # nothing to do: must not raise


def test_tick_with_a_missing_spool_logs_and_does_not_raise(w, env, caplog):
    (env["spool"] / "jobs").rmdir()
    with caplog.at_level("ERROR"):
        pc.tick()
    assert "the spool is missing; skipping ingest" in caplog.text


def test_tick_ingests_a_result(w, env):
    row = _queued(w)
    d = _drop_result(env, row)
    os.utime(d, (0, 0))  # old enough for the real clock
    pc.tick()
    assert _fresh(row.id).status == "done"


def test_open_regular_refuses_a_fifo_without_blocking(tmp_path):
    """A FIFO swapped in after the lstat must not hang the scheduler thread on
    open: O_NONBLOCK returns at once and the fstat refuses it. A regular file
    still opens (the positive path is reached)."""
    from app.services import page_capture as pc

    fifo = tmp_path / "result.json"
    os.mkfifo(fifo)
    with pytest.raises(OSError):
        pc._open_regular(str(fifo))

    regular = tmp_path / "ok.json"
    regular.write_bytes(b"{}")
    fd = pc._open_regular(str(regular))
    os.close(fd)


# ── S5b-2b: settings, revisit budget, user-agent mode, v2 job ────────────────

from app.models.app_settings import AppSetting  # noqa: E402
from app.services import app_settings  # noqa: E402

_CAPTURE_KEYS = (
    pc.REVISIT_DAYS_KEY, pc.USER_AGENT_MODE_KEY, pc.IDENTIFYING_UA_KEY, pc.MAX_IMAGE_BYTES_KEY, pc.QUEUE_TIMEOUT_KEY,
    pc.ARCHIVE_FRESHNESS_DAYS_KEY,
)


@pytest.fixture
def cap_settings():
    """Override capture.* settings for one test; AppSetting rows are global, so
    every key is restored (or deleted if it had no row) afterwards."""
    db = SessionLocal()
    try:
        snaps = {k: (db.get(AppSetting, k).value if db.get(AppSetting, k) else None) for k in _CAPTURE_KEYS}
    finally:
        db.close()

    def set_(**kv):
        s = SessionLocal()
        try:
            for k, v in kv.items():
                app_settings.set_value(s, getattr(pc, k), str(v))
        finally:
            s.close()

    yield set_
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


def _row_for(w, candidate, status, *, finished_ago_days=None, domain=None):
    obs = w.db.query(Observer).filter(Observer.name == "page_capture").one()
    now = datetime.now(timezone.utc)
    row = PageCapture(
        candidate_id=candidate.id, domain=domain or candidate.value, observer_id=obs.id,
        requested_url=f"https://{candidate.value}/", status=status, user_agent_mode="stock",
        image_max_bytes=pc.DEFAULT_MAX_IMAGE_BYTES,
        finished_at=None if finished_ago_days is None else now - timedelta(days=finished_ago_days),
        failure_reason="timeout" if status == "failed" else None,
    )
    w.db.add(row)
    w.db.commit()
    return row


def _auto(w, c):
    return pc.request_capture(w.db, candidate_id=c.id, user=w.user(), manual=False)


def _assert_refused_clean(w, env, c, rule):
    """The gate allowed (a decision was logged for this candidate's request path
    is not needed): the refusal is the budget/UA rule, with no new row and no job."""
    before = _rows_for(c.id)
    with pytest.raises(pc.CaptureRefused) as e:
        _auto(w, c)
    assert e.value.rule == rule
    assert _rows_for(c.id) == before and _no_job_files(env) == []


def test_budget_refuses_an_automatic_request_after_a_recent_done_row_under_another_candidate(w, env):
    shared = _dom()
    other = _candidate(w, value=shared)
    _row_for(w, other, "done", finished_ago_days=1)
    # a second candidate with the same domain value under another root
    c = _candidate(w, root=w.ours(), value=shared)
    _assert_refused_clean(w, env, c, "capture:revisit_budget")


def test_budget_refuses_when_the_same_domain_is_queued_under_another_candidate(w, env):
    shared = _dom()
    other = _candidate(w, value=shared)
    _row_for(w, other, "queued")
    c = _candidate(w, root=w.ours(), value=shared)
    _assert_refused_clean(w, env, c, "capture:revisit_budget")


def test_budget_allows_when_the_done_row_is_older_than_the_window_and_ignores_failed(w, env, cap_settings):
    cap_settings(REVISIT_DAYS_KEY=2)
    shared = _dom()
    other = _candidate(w, value=shared)
    _row_for(w, other, "done", finished_ago_days=3)
    _row_for(w, other, "failed", finished_ago_days=0)
    c = _candidate(w, root=w.ours(), value=shared)
    row = _auto(w, c)  # the path past the budget was reached: a row and a job exist
    assert row.status == "queued" and (env["spool"] / "jobs" / f"{row.id}.json").exists()


def test_budget_boundary_a_done_row_inside_the_window_refuses(w, env, cap_settings):
    cap_settings(REVISIT_DAYS_KEY=2)
    shared = _dom()
    other = _candidate(w, value=shared)
    _row_for(w, other, "done", finished_ago_days=1)
    _assert_refused_clean(w, env, _candidate(w, root=w.ours(), value=shared), "capture:revisit_budget")


def test_manual_bypasses_the_budget(w, env):
    shared = _dom()
    other = _candidate(w, value=shared)
    _row_for(w, other, "done", finished_ago_days=0)
    c = _candidate(w, root=w.ours(), value=shared)
    row = pc.request_capture(w.db, candidate_id=c.id, user=w.user(), manual=True)
    assert row.status == "queued" and (env["spool"] / "jobs" / f"{row.id}.json").exists()


def test_manual_bypasses_a_queued_row_on_the_same_domain_under_another_candidate(w, env):
    shared = _dom()
    other = _candidate(w, value=shared)
    _row_for(w, other, "queued")
    c = _candidate(w, root=w.ours(), value=shared)
    row = pc.request_capture(w.db, candidate_id=c.id, user=w.user(), manual=True)
    assert row.status == "queued"


def test_manual_is_a_required_keyword(w, env):
    c = _candidate(w)
    with pytest.raises(TypeError):
        pc.request_capture(w.db, candidate_id=c.id, user=w.user())  # type: ignore[call-arg]


def test_identifying_mode_with_no_string_is_refused_before_any_write(w, env, cap_settings):
    cap_settings(USER_AGENT_MODE_KEY="identifying", IDENTIFYING_UA_KEY="")
    c = _candidate(w)
    before = _rows_for(c.id)
    with pytest.raises(pc.CaptureRefused) as e:
        pc.request_capture(w.db, candidate_id=c.id, user=w.user(), manual=True)
    assert e.value.rule == "capture:identifying_user_agent_unset"
    assert _rows_for(c.id) == before == 0 and _no_job_files(env) == []


def test_identifying_mode_writes_the_user_agent_into_the_v2_job_and_the_row(w, env, cap_settings):
    cap_settings(USER_AGENT_MODE_KEY="identifying", IDENTIFYING_UA_KEY="FabrikamScan/1.0 (+https://fabrikam.com/scan)",
                 MAX_IMAGE_BYTES_KEY=1048576)
    c = _candidate(w)
    row = pc.request_capture(w.db, candidate_id=c.id, user=w.user(), manual=True)
    job = json.loads((env["spool"] / "jobs" / f"{row.id}.json").read_text())
    assert job["v"] == 3 and job["user_agent_mode"] == "identifying"
    assert job["user_agent"] == "FabrikamScan/1.0 (+https://fabrikam.com/scan)"
    assert job["max_image_bytes"] == 1048576
    r = _fresh(row.id)
    assert (r.user_agent_mode, r.image_max_bytes) == ("identifying", 1048576)


def test_stock_mode_job_has_no_user_agent_key_even_if_a_string_is_stored(w, env, cap_settings):
    cap_settings(USER_AGENT_MODE_KEY="stock", IDENTIFYING_UA_KEY="FabrikamScan/1.0")
    c = _candidate(w)
    row = pc.request_capture(w.db, candidate_id=c.id, user=w.user(), manual=True)
    job = json.loads((env["spool"] / "jobs" / f"{row.id}.json").read_text())
    assert job["v"] == 3 and job["user_agent_mode"] == "stock" and "user_agent" not in job


@pytest.mark.parametrize("key,value,expect", [
    ("REVISIT_DAYS_KEY", "0", pc.DEFAULT_REVISIT_DAYS), ("REVISIT_DAYS_KEY", "366", pc.DEFAULT_REVISIT_DAYS),
    ("REVISIT_DAYS_KEY", "soon", pc.DEFAULT_REVISIT_DAYS), ("REVISIT_DAYS_KEY", "7", 7),
    ("MAX_IMAGE_BYTES_KEY", "100", pc.DEFAULT_MAX_IMAGE_BYTES),
    ("MAX_IMAGE_BYTES_KEY", str(pc.IMAGE_BYTES_CEILING + 1), pc.DEFAULT_MAX_IMAGE_BYTES),
    ("MAX_IMAGE_BYTES_KEY", "x", pc.DEFAULT_MAX_IMAGE_BYTES), ("MAX_IMAGE_BYTES_KEY", "131072", 131072),
    ("QUEUE_TIMEOUT_KEY", "59", pc.DEFAULT_QUEUE_TIMEOUT_S), ("QUEUE_TIMEOUT_KEY", "3601", pc.DEFAULT_QUEUE_TIMEOUT_S),
    ("QUEUE_TIMEOUT_KEY", "", pc.DEFAULT_QUEUE_TIMEOUT_S), ("QUEUE_TIMEOUT_KEY", "120", 120),
])
def test_numeric_accessors_clamp_to_the_default(w, cap_settings, key, value, expect):
    cap_settings(**{key: value})
    fn = {"REVISIT_DAYS_KEY": pc.revisit_days, "MAX_IMAGE_BYTES_KEY": pc.max_image_bytes,
          "QUEUE_TIMEOUT_KEY": pc.queue_timeout_seconds}[key]
    assert fn(w.db) == expect


def test_mode_and_user_agent_accessors_fall_back(w, cap_settings):
    cap_settings(USER_AGENT_MODE_KEY="aggressive")
    assert pc.user_agent_mode(w.db) == "stock"
    cap_settings(USER_AGENT_MODE_KEY="identifying")
    assert pc.user_agent_mode(w.db) == "identifying"
    for bad in ("", "Agent\r\nX-Evil: 1", "Agént/1.0", "a" * (pc.USER_AGENT_MAX + 1), "tab\there"):
        cap_settings(IDENTIFYING_UA_KEY=bad)
        assert pc.identifying_user_agent(w.db) is None, repr(bad)
    cap_settings(IDENTIFYING_UA_KEY="a" * pc.USER_AGENT_MAX)
    assert pc.identifying_user_agent(w.db) == "a" * pc.USER_AGENT_MAX


def test_valid_user_agent_rejects_non_strings():
    assert not pc.valid_user_agent(None) and not pc.valid_user_agent(5) and not pc.valid_user_agent("")
    assert pc.valid_user_agent("Mozilla/5.0 (X11)")


def test_ingest_enforces_the_cap_the_job_asked_for_not_the_current_setting(w, env, cap_settings):
    row = _queued(w)
    row.image_max_bytes = pc.IMAGE_BYTES_MIN  # the row's cap, smaller than the file
    w.db.commit()
    _drop_result(env, row, image=WEBP + b"\x00" * pc.IMAGE_BYTES_MIN)
    assert _ingest(w) == 1
    r = _fresh(row.id)
    assert r.status == "done" and r.image_path is None and r.image_omitted_reason == "invalid_image"


def test_ingest_accepts_a_file_within_a_row_cap_larger_than_the_current_setting(w, env, cap_settings):
    cap_settings(MAX_IMAGE_BYTES_KEY=pc.IMAGE_BYTES_MIN)  # the setting shrank after the job was queued
    row = _queued(w)
    row.image_max_bytes = 1024 * 1024
    w.db.commit()
    img = WEBP + b"\x00" * (pc.IMAGE_BYTES_MIN + 10)
    _drop_result(env, row, image=img)
    assert _ingest(w) == 1
    r = _fresh(row.id)
    assert r.image_path == f"{row.id}.webp" and r.image_bytes == len(img)


def test_ingest_never_exceeds_the_ceiling_even_if_the_row_says_so(w, env):
    row = _queued(w)
    row.image_max_bytes = pc.IMAGE_BYTES_CEILING * 2
    w.db.commit()
    _drop_result(env, row, image=WEBP + b"\x00" * pc.IMAGE_BYTES_CEILING)
    assert _ingest(w) == 1
    assert _fresh(row.id).image_omitted_reason == "invalid_image"


def test_sweep_honours_the_queue_timeout_setting(w, env, cap_settings):
    cap_settings(QUEUE_TIMEOUT_KEY=120)
    row = _queued(w)
    row.requested_at = datetime.now(timezone.utc) - timedelta(seconds=300)  # fresh at the 600s default
    w.db.commit()
    (env["spool"] / "jobs" / f"{row.id}.json").write_text("{}")
    assert pc.sweep_timeouts(w.db) == 1
    _assert_failed(row, "timeout")
    assert not (env["spool"] / "jobs" / f"{row.id}.json").exists()


def test_sweep_with_a_longer_setting_leaves_a_row_that_the_default_would_sweep(w, env, cap_settings):
    cap_settings(QUEUE_TIMEOUT_KEY=3600)
    row = _queued(w)
    row.requested_at = datetime.now(timezone.utc) - timedelta(seconds=700)
    w.db.commit()
    assert pc.sweep_timeouts(w.db) == 0
    assert _fresh(row.id).status == "queued"


# ── read_stored_image ────────────────────────────────────────────────────────


def _stored(w, env, data=WEBP, **over):
    """A done row with a real stored image written the way _store_image does."""
    row = _queued(w)
    pc._store_image(row, str(row.id), data, 80)
    for k, v in over.items():
        setattr(row, k, v)
    row.status, row.finished_at = "done", datetime.now(timezone.utc)
    w.db.commit()
    return row


def test_read_stored_image_returns_the_exact_bytes(w, env):
    assert pc.read_stored_image(_stored(w, env)) == WEBP


def test_read_stored_image_returns_none_when_the_store_is_unavailable(w, env, monkeypatch):
    """A misconfigured store (StoreConfigError is an OSError) must not surface as a 500 from
    the image route: the wrapper logs and returns None. planning#318 S1b."""
    row = _stored(w, env)
    monkeypatch.setenv("CAPTURE_STORE", "bogus")
    assert pc.read_stored_image(row) is None
    monkeypatch.setenv("CAPTURE_STORE", "filesystem")
    assert pc.read_stored_image(row) == WEBP  # the row itself is fine: only the store was unreachable


@pytest.mark.parametrize("tamper", ["../x.webp", "{other}.webp", "x.webp"])
def test_read_stored_image_refuses_a_tampered_name(w, env, tamper):
    # A valid image with the row's own sha256 is planted at the tampered name,
    # so only the name pin can refuse it (without the plant the read would fail
    # on a missing file and the test would pass vacuously).
    row = _stored(w, env)
    row.image_path = tamper.format(other=uuid.uuid4())
    planted = env["images"] / row.image_path
    planted.write_bytes(WEBP)
    assert planted.resolve().read_bytes() == WEBP
    assert pc.read_stored_image(row) is None


def test_read_stored_image_refuses_an_absolute_name(w, env):
    row = _stored(w, env)
    row.image_path = "/etc/passwd"
    assert pc.read_stored_image(row) is None


def test_read_stored_image_refuses_a_symlink(w, env, tmp_path):
    row = _stored(w, env)
    p = env["images"] / f"{row.id}.webp"
    p.unlink()
    target = tmp_path / "elsewhere.webp"
    target.write_bytes(WEBP)
    p.symlink_to(target)
    assert pc.read_stored_image(row) is None


def test_read_stored_image_refuses_a_sha_mismatch_bad_magic_and_oversize(w, env):
    row = _stored(w, env)
    (env["images"] / f"{row.id}.webp").write_bytes(WEBP[:-1] + b"\x01")
    assert pc.read_stored_image(row) is None  # sha
    bad = b"RIFF\x00\x00\x00\x00WAVEjunk" + b"\x00" * 20
    (env["images"] / f"{row.id}.webp").write_bytes(bad)
    row.image_sha256 = __import__("hashlib").sha256(bad).hexdigest()
    assert pc.read_stored_image(row) is None  # magic, with a matching sha
    big = WEBP + b"\x00" * 200
    (env["images"] / f"{row.id}.webp").write_bytes(big)
    row.image_sha256 = __import__("hashlib").sha256(big).hexdigest()
    row.image_max_bytes = 100
    assert pc.read_stored_image(row) is None  # oversize vs the row cap
    row.image_max_bytes = 4096
    assert pc.read_stored_image(row) == big  # the same file passes once the cap allows (path reached)


def test_read_stored_image_missing_file_is_none(w, env):
    row = _stored(w, env)
    (env["images"] / f"{row.id}.webp").unlink()
    assert pc.read_stored_image(row) is None


# ── S5c-b1: per-job proxy credential (job v3) ────────────────────────────────

CID = "00000000-0000-4000-8000-000000000001"
LIVE_VEC = "fd4cc753d722f5681637818178f5319706eb2b66b6c19cc182666f4d6e9e1382"


def test_proxy_token_contract_vectors(monkeypatch):
    monkeypatch.setenv("CAPTURE_PROXY_KEY", "k" * 32)
    # Same vectors as docs/architecture/capture-spool.md and capture-proxy's tests.
    assert pc.proxy_token(CID, "live", 2000000000) == LIVE_VEC
    assert pc.proxy_token(CID, "archive", 2000000000) == (
        "ec9eb6417283118f7de8b8013f57c6b86582311497a3921e31bca75ca696ea9a"
    )


def test_proxy_token_unknown_mode_and_non_canonical_id_raise(env):
    with pytest.raises(ValueError):
        pc.proxy_token(CID, "admin", 2000000000)
    with pytest.raises(ValueError):
        pc.proxy_token(CID.replace("-", ""), "live", 2000000000)  # valid UUID, not canonical


@pytest.mark.parametrize("key", ["", "k" * 31, "   " + "k" * 31 + "  "])
def test_proxy_token_is_none_without_a_usable_key(env, monkeypatch, key):
    monkeypatch.setenv("CAPTURE_PROXY_KEY", key)
    assert pc.proxy_token(CID, "live", 2000000000) is None
    monkeypatch.delenv("CAPTURE_PROXY_KEY")
    assert pc.proxy_token(CID, "live", 2000000000) is None


def test_proxy_key_is_stripped_before_use(env, monkeypatch):
    monkeypatch.setenv("CAPTURE_PROXY_KEY", "  " + "k" * 32 + "\n")
    assert pc.proxy_token(CID, "live", 2000000000) == LIVE_VEC


@pytest.mark.parametrize("exp", [0, -1, 10**12, True, "2000000000", 1.5])
def test_proxy_token_rejects_a_bad_exp(env, exp):
    with pytest.raises(ValueError):
        pc.proxy_token(CID, "live", exp)


@pytest.mark.parametrize("key", [None, "k" * 31])
def test_request_refused_when_the_proxy_key_is_missing_or_short(w, env, monkeypatch, key):
    c = _candidate(w)
    user = w.user()
    if key is None:
        monkeypatch.delenv("CAPTURE_PROXY_KEY")
    else:
        monkeypatch.setenv("CAPTURE_PROXY_KEY", key)
    with pytest.raises(pc.CaptureRefused) as e:
        pc.request_capture(w.db, candidate_id=c.id, user=user, manual=True)
    assert e.value.rule == "capture:not_configured"
    assert _rows_for(c.id) == 0 and _no_job_files(env) == []
    # Precondition: the very same call with the key set gets past every gate and queues.
    monkeypatch.setenv("CAPTURE_PROXY_KEY", "k" * 32)
    row = pc.request_capture(w.db, candidate_id=c.id, user=user, manual=True)
    assert _rows_for(c.id) == 1 and (env["spool"] / "jobs" / f"{row.id}.json").exists()
