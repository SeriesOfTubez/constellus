"""Pure-function tests for capture.spool / capture.worker (no browser, no Playwright)."""

import json
import os
import stat
import sys

import pytest

from capture import spool, worker

ID = "0190a1b2-c3d4-7e5f-8a6b-1234567890ab"


def _mk(root):
    for d in ("jobs", "claimed", "results"):
        (root / d).mkdir()
    return worker.check_dirs(str(root))


def job(**over):
    j = {
        "v": 1,
        "capture_id": ID,
        "url": "https://example.com/",
        "viewport": {"width": 1280, "height": 800},
        "max_image_bytes": 2097152,
        "webp_qualities": [80, 60, 40],
    }
    j.update(over)
    return json.dumps(j).encode()


def test_playwright_is_not_imported_by_the_pure_modules():
    assert "playwright" not in sys.modules


def test_valid_job_roundtrips():
    j = spool.validate_job(job(), ID)
    assert j["url"] == "https://example.com/" and j["webp_qualities"] == [80, 60, 40]


@pytest.mark.parametrize(
    "raw",
    [
        job(v=2),
        job(v=True),
        job(capture_id="0190a1b2-c3d4-7e5f-8a6b-1234567890ac"),
        job(url="file:///etc/passwd"),
        job(url="ftp://example.com/"),
        job(url="https:///nohost"),
        job(url="https://example.com:99999/"),
        job(url=5),
        job(viewport={"width": 1, "height": 800}),
        job(viewport="big"),
        job(max_image_bytes=0),
        job(max_image_bytes=True),
        job(webp_qualities=[]),
        job(webp_qualities=[101]),
        job(webp_qualities=[1] * 6),
        b"not json",
        b"[]",
        b"x" * (spool.JOB_MAX_BYTES + 1),
        job(url="https://example.com/" + "a" * 20000),
    ],
)
def test_invalid_jobs_are_rejected(raw):
    with pytest.raises(spool.InvalidJob):
        spool.validate_job(raw, ID)


@pytest.mark.parametrize(
    "name,ok",
    [
        (f"{ID}.json", True),
        (f".{ID}.json", False),
        (f"{ID.upper()}.json", False),
        (f"{ID}x.json", False),
        ("../x.json", False),
        (f"{ID}.jsonl", False),
        ("a" * 36 + ".json", False),
        (ID.replace("-", "") + ".json", False),
    ],
)
def test_job_names(name, ok):
    assert (spool.job_id_from_name(name) == ID) is ok


def test_pick_screenshot_first_that_fits():
    seen = []

    def take(q):
        seen.append(q)
        return b"x" * {80: 300, 60: 200, 40: 50}[q]

    assert spool.pick_screenshot(take, [80, 60, 40], 250) == (b"x" * 200, 60, None)
    assert seen == [80, 60]  # stopped at the first fit


def test_pick_screenshot_over_cap_and_error():
    assert spool.pick_screenshot(lambda q: b"x" * 10, [80, 60], 5) == (None, None, "over_cap")

    def boom(q):
        raise TimeoutError("slow")

    assert spool.pick_screenshot(boom, [80], 5) == (None, None, "error:TimeoutError")


def _captured(n_requests):
    return {
        "requested_url": "https://example.com/",
        "final_url": "https://example.com/",
        "status": 200,
        "redirect_chain": [{"url": "http://example.com/", "status": 301}],
        "title": "Example",
        "cert": {"subject": "CN=example.com", "issuer": "CN=ca", "not_before": "a", "not_after": "b",
                 "san_dns": ["example.com"], "sha256": "ab"},
        "requests": [
            {"url": f"https://example.com/{i}", "resource_type": "script", "failure": None, "is_navigation": i == 0}
            for i in range(n_requests)
        ],
        "error": None,
    }


def test_build_result_shape():
    r, img = spool.build_result(ID, captured=_captured(3), shot=(b"IMG", 80, None), user_agent="UA")
    assert img == b"IMG"
    assert r["v"] == 1 and r["capture_id"] == ID and r["status"] == 200
    assert r["screenshot"] == {"file": "screenshot.webp", "bytes": 3, "quality": 80}
    assert r["screenshot_omitted_reason"] is None and r["error"] is None
    assert len(r["requests"]) == 3 and "requests_truncated" not in r
    assert r["cert"]["san_dns"] == ["example.com"]


def test_build_result_without_image():
    r, img = spool.build_result(ID, captured=_captured(1), shot=(None, None, "over_cap"))
    assert img is None and r["screenshot"] is None and r["screenshot_omitted_reason"] == "over_cap"


def test_requests_capped_at_500_and_flagged():
    r, _ = spool.build_result(ID, captured=_captured(spool.MAX_REQUESTS + 50))
    assert len(r["requests"]) == spool.MAX_REQUESTS and r["requests_truncated"] is True


def test_result_json_capped_at_1mib():
    c = _captured(500)
    for q in c["requests"]:
        q["url"] = "https://example.com/" + "a" * 1900
        q["failure"] = "f" * 1000
    c["cert"]["san_dns"] = ["d" * 300 + ".example.com"] * 2000
    c["redirect_chain"] = [{"url": "u" * 5000, "status": 302}] * 100
    before = len(json.dumps(c))
    assert before > spool.RESULT_MAX_BYTES  # precondition: the input really is too big
    r, _ = spool.build_result(ID, captured=c)
    assert len(spool.serialise(r)) <= spool.RESULT_MAX_BYTES
    assert r["requests_truncated"] is True and len(r["requests"]) < 500


def test_invalid_job_result():
    r, img = spool.build_result(ID, error="invalid_job")
    assert r["error"] == "invalid_job" and img is None and r["screenshot"] is None
    assert r["v"] == 1 and r["capture_id"] == ID


def test_write_result_atomic_dir_and_modes(tmp_path):
    os.umask(spool.WORKER_UMASK)  # what the worker does at startup
    results = tmp_path / "results"
    results.mkdir()
    r, img = spool.build_result(ID, captured=_captured(1), shot=(b"RIFF....WEBP", 80, None))
    final = spool.write_result(str(results), ID, r, img)
    assert final == str(results / ID)
    assert sorted(os.listdir(final)) == ["result.json", "screenshot.webp"]
    assert [p.name for p in results.iterdir()] == [ID]  # no .tmp left
    assert stat.S_IMODE(os.stat(final).st_mode) == 0o770  # setgid comes from the parent
    for n in os.listdir(final):
        assert stat.S_IMODE(os.stat(os.path.join(final, n)).st_mode) == 0o660
    assert json.loads((results / ID / "result.json").read_bytes())["capture_id"] == ID


def test_no_chmod_in_worker_modules():
    import inspect

    for mod in (spool, worker):
        assert "chmod" not in inspect.getsource(mod).replace("no chmod", "").replace("No chmod", "")


def test_check_dirs_fails_when_subdirs_missing(tmp_path):
    with pytest.raises(SystemExit):
        worker.check_dirs(str(tmp_path))
    assert list(tmp_path.iterdir()) == []  # nothing created


def test_write_result_refuses_non_uuid(tmp_path):
    with pytest.raises(ValueError):
        spool.write_result(str(tmp_path), "../x", {}, None)
    assert list(tmp_path.iterdir()) == []


def test_write_result_replaces_stale_tmp(tmp_path):
    (tmp_path / f".{ID}.tmp").mkdir()
    (tmp_path / f".{ID}.tmp" / "junk").write_text("x")
    spool.write_result(str(tmp_path), ID, {"v": 1}, None)
    assert os.listdir(tmp_path / ID) == ["result.json"]


def test_claim_next_oldest_first_and_ignores_junk(tmp_path):
    jobs, claimed, _ = _mk(tmp_path)
    a, b = "0190a1b2-0000-7000-8000-000000000001", "0190a1b2-0000-7000-8000-000000000002"
    for name in (f"{b}.json", f"{a}.json", f".{a}.tmp", "junk.json", f"{ID.upper()}.json"):
        open(os.path.join(jobs, name), "w").write("{}")
    assert worker.claim_next(jobs, claimed) == a
    assert worker.claim_next(jobs, claimed) == b
    assert worker.claim_next(jobs, claimed) is None  # junk is never claimed
    assert sorted(os.listdir(claimed)) == [f"{a}.json", f"{b}.json"]


def test_claim_loses_race_gracefully(tmp_path, monkeypatch):
    jobs, claimed, _ = _mk(tmp_path)
    a, b = "0190a1b2-0000-7000-8000-000000000001", "0190a1b2-0000-7000-8000-000000000002"
    for n in (a, b):
        open(os.path.join(jobs, f"{n}.json"), "w").write("{}")
    real = os.rename

    def rename(src, dst):
        if src.endswith(f"{a}.json"):
            os.unlink(src)  # another worker took it first
        return real(src, dst)

    monkeypatch.setattr(worker.os, "rename", rename)
    assert worker.claim_next(jobs, claimed) == b


def test_process_invalid_job_writes_invalid_job_result_without_a_browser(tmp_path):
    jobs, claimed, results = _mk(tmp_path)
    path = os.path.join(claimed, f"{ID}.json")
    open(path, "wb").write(job(url="file:///etc/passwd"))
    worker.process(ID, path, results)
    r = json.loads(open(os.path.join(results, ID, "result.json")).read())
    assert r["error"] == "invalid_job" and r["final_url"] is None
    assert "playwright" not in sys.modules  # the browser path was never reached
