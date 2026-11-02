"""Pure-function tests for capture.spool / capture.worker (no browser, no Playwright)."""

import json
import os
import stat
import sys

import pytest

from capture import spool, store_s3, worker

ID = "0190a1b2-c3d4-7e5f-8a6b-1234567890ab"
TOKEN = "ab" * 32  # 64 lowercase hex
EXP = 2000000000
ARCHIVE_URL = "https://web.archive.org/web/2020/https://example.com/"


def _mk(root):
    for d in ("jobs", "claimed", "results"):
        (root / d).mkdir()
    return worker.check_dirs(str(root))


_ABSENT = object()


_ABSENT = object()


def job(**over):
    j = {
        "v": 3,
        "capture_id": ID,
        "url": "https://example.com/",
        "mode": "live",
        "proxy_token": TOKEN,
        "proxy_expires": EXP,
        "viewport": {"width": 1280, "height": 800},
        "max_image_bytes": 2097152,
        "webp_qualities": [80, 60, 40],
        "user_agent_mode": "stock",
    }
    j.update(over)
    for k in [k for k, v in over.items() if v is _ABSENT]:
        del j[k]
    return json.dumps(j).encode()


def test_playwright_is_not_imported_by_the_pure_modules():
    assert "playwright" not in sys.modules
    import capture.store_s3  # noqa: F401 - the S3 module must be as pure as spool

    assert "playwright" not in sys.modules


def test_valid_job_roundtrips():
    j = spool.validate_job(job(), ID)
    assert j["url"] == "https://example.com/" and j["webp_qualities"] == [80, 60, 40]


@pytest.mark.parametrize(
    "raw",
    [
        job(v=1),
        job(v=2),
        job(mode=_ABSENT),
        job(mode="Live"),
        job(mode="admin"),
        job(mode=None),
        job(mode=["live"]),
        job(proxy_token=_ABSENT),
        job(proxy_token="a" * 63),
        job(proxy_token="a" * 65),
        job(proxy_token="A" * 64),
        job(proxy_token=TOKEN[:-1] + "g"),
        job(proxy_token=12345),
        job(proxy_token=None),
        job(proxy_expires=_ABSENT),
        job(proxy_expires=True),
        job(proxy_expires=0),
        job(proxy_expires=-1),
        job(proxy_expires=10**12),
        job(proxy_expires="2000000000"),
        job(proxy_expires=1.5),
        job(proxy_expires=None),
        job(mode="archive", url="http://web.archive.org/web/2020/https://example.com/"),
        job(mode="archive", url="https://example.com/web/2020/x"),
        job(mode="archive", url="https://web.archive.org.evil.test/web/2020/x"),
        job(mode="archive", url="https://web.archive.org:8443/web/2020/x"),
        job(mode="archive", url="https://user@web.archive.org/web/2020/x"),
        job(mode="archive", url="https://user:pw@web.archive.org/web/2020/x"),
        job(mode="archive", url="https://web.archive.org/save/https://example.com/"),
        job(mode="archive", url="https://web.archive.org/"),
        job(mode="archive", url="https://web.archive.org/web/save/https://example.com/"),
        job(mode="archive", url="https://1.2.3.4/web/2020/x"),
        job(mode="archive", url="https://[::1]/web/2020/x"),
        job(v=True),
        job(user_agent_mode=_ABSENT),
        job(user_agent_mode="Stock"),
        job(user_agent_mode="spoofed"),
        job(user_agent_mode=None),
        job(user_agent_mode=1),
        job(user_agent_mode=["stock"]),
        job(user_agent_mode="identifying"),
        job(user_agent_mode="identifying", user_agent=None),
        job(user_agent_mode="identifying", user_agent=5),
        job(user_agent_mode="identifying", user_agent=""),
        job(user_agent_mode="identifying", user_agent="a" * 257),
        job(user_agent_mode="identifying", user_agent="Bot/1.0\r\nX-Evil: 1"),
        job(user_agent_mode="identifying", user_agent="Bot\t1.0"),
        job(user_agent_mode="identifying", user_agent="Bot/1.0 \u00e9"),
        job(user_agent_mode="identifying", user_agent="Bot\x7f"),
        job(user_agent_mode="stock", user_agent="Bot/1.0"),
        job(user_agent_mode="stock", user_agent=None),
        job(user_agent_mode="stock", user_agent=""),
        job(max_image_bytes=8 * 1024 * 1024 + 1),
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


def test_valid_archive_job_passes_and_carries_mode_and_token():
    for url in (ARCHIVE_URL, "https://WEB.ARCHIVE.ORG:443/web/2020/x"):
        j = spool.validate_job(job(mode="archive", url=url), ID)
        assert j["mode"] == "archive" and j["proxy_token"] == TOKEN and j["url"] == url


def test_valid_live_job_carries_mode_and_token():
    j = spool.validate_job(job(), ID)
    assert j["mode"] == "live" and j["proxy_token"] == TOKEN


@pytest.mark.parametrize(
    "url,ok",
    [
        ("https://web.archive.org/web/2020/https://example.com/", True),
        ("https://web.archive.org/web/2026/http://x.example/", True),
        ("https://web.archive.org/", False),
        ("https://web.archive.org/save/https://x.example/", False),
        ("https://web.archive.org/images/x.png", False),
        ("https://web.archive.org/web/save/https://x.example/", False),
        ("https://web.archive.org/web/", False),
        ("https://web.archive.org/web/20261005000556cs_/https://x.example/a.css", True),
        ("https://WEB.Archive.ORG/web/1/x", True),
        ("https://web.archive.org:443/web/1/x", True),
        ("http://web.archive.org/web/1/x", False),
        ("https://example.com/web/1/x", False),
        ("https://web.archive.org.evil.test/", False),
        ("https://evil-web.archive.org/", False),
        ("https://web.archive.org:80/web/1/x", False),  # valid path: only the port fails
        ("https://web.archive.org:8443/web/1/x", False),  # valid path: only the port fails
        ("https://web.archive.org:99999/web/1/x", False),  # valid path: only the port fails
        ("data:text/html,hi", False),
        ("about:blank", False),
        ("", False),
        ("::::", False),
        ("https://[::1/", False),
    ],
)
def test_archive_request_allowed(url, ok):
    assert spool.archive_request_allowed(url) is ok


def test_stock_job_returns_no_user_agent():
    j = spool.validate_job(job(), ID)
    assert j["user_agent_mode"] == "stock" and j["user_agent"] is None


def test_identifying_job_carries_the_user_agent():
    ua = "ExampleScanner/1.0 (+https://scanner.example.test/about)"
    j = spool.validate_job(job(user_agent_mode="identifying", user_agent=ua), ID)
    assert j["user_agent_mode"] == "identifying" and j["user_agent"] == ua


def test_identifying_user_agent_256_printable_chars_accepted():
    ua = "".join(chr(0x20 + i % 95) for i in range(256))  # spans 0x20..0x7e
    assert len(ua) == 256
    assert spool.validate_job(job(user_agent_mode="identifying", user_agent=ua), ID)["user_agent"] == ua


def test_max_image_bytes_boundary_is_8_mib():
    assert spool.MAX_IMAGE_BYTES_LIMIT == 8 * 1024 * 1024
    ok = spool.validate_job(job(max_image_bytes=8 * 1024 * 1024), ID)
    assert ok["max_image_bytes"] == 8 * 1024 * 1024


def test_result_version_is_independent_of_job_version():
    assert spool.JOB_VERSION == 3
    r, _ = spool.build_result(ID, error="x")
    assert r["v"] == 1


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

    for mod in (spool, worker, store_s3):
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


def _run_job(tmp_path, raw):
    jobs, claimed, results = _mk(tmp_path)
    path = os.path.join(claimed, f"{ID}.json")
    open(path, "wb").write(raw)
    worker.process(ID, path, results)
    return json.loads(open(os.path.join(results, ID, "result.json")).read())


def test_worker_identifying_mode_hands_the_job_ua_to_the_context(tmp_path, fake_playwright):
    ua = "ExampleScanner/1.0 (+https://scanner.example.test/about)"
    r = _run_job(tmp_path, job(user_agent_mode="identifying", user_agent=ua))
    assert r["error"] is None  # the fake capture really ran end to end
    assert [kw["user_agent"] for kw in fake_playwright.context_kwargs] == [ua]
    # No stock probe context in this mode: the only context is the capture one.
    assert r["user_agent"] == ua


def test_worker_stock_mode_uses_the_browser_ua_without_headless_marker(tmp_path, fake_playwright):
    r = _run_job(tmp_path, job())
    stock = "Mozilla/5.0 (X11; Linux) Chrome/999.0 Safari/537.36"
    assert r["error"] is None
    kws = fake_playwright.context_kwargs
    assert len(kws) == 2 and "user_agent" not in kws[0]  # probe context, then capture context
    assert kws[1]["user_agent"] == stock
    assert r["user_agent"] == stock


class _FakeRoute:
    def __init__(self, url):
        self.request = type("Req", (), {"url": url})()
        self.calls = []

    def abort(self, reason=None):
        self.calls.append(("abort", reason))

    def continue_(self):
        self.calls.append(("continue",))


def test_worker_passes_per_job_credential_to_the_proxy_setting(tmp_path, fake_playwright):
    r = _run_job(tmp_path, job())
    assert r["error"] is None
    (kw,) = fake_playwright.launch_kwargs
    assert kw["proxy"]["username"] == f"{ID}|live|{EXP}"
    assert kw["proxy"]["password"] == TOKEN


def test_worker_live_job_installs_no_route(tmp_path, fake_playwright):
    r = _run_job(tmp_path, job())
    assert r["error"] is None
    assert len(fake_playwright.contexts) == 2  # precondition: the capture context was made
    assert all(c.routes == [] for c in fake_playwright.contexts)


def test_worker_archive_job_installs_archive_only_route(tmp_path, fake_playwright):
    other = "cd" * 32
    r = _run_job(tmp_path, job(mode="archive", url=ARCHIVE_URL, proxy_token=other))
    assert r["error"] is None
    (kw,) = fake_playwright.launch_kwargs
    assert kw["proxy"]["username"] == f"{ID}|archive|{EXP}" and kw["proxy"]["password"] == other
    routed = [c for c in fake_playwright.contexts if c.routes]
    assert len(routed) == 1 and len(routed[0].routes) == 1
    pattern, handler = routed[0].routes[0]
    assert pattern == "**/*"
    bad, good = _FakeRoute("https://example.com/x"), _FakeRoute("https://web.archive.org/web/1/x")
    handler(bad)
    handler(good)
    assert bad.calls == [("abort", "blockedbyclient")]
    assert good.calls == [("continue",)]


# --- the `store` object (S3 job mode) ----------------------------------------

NETLOC = "s3.example.com:9000"
PUT_R = f"https://{NETLOC}/res/results/{ID}/result.json?X-Amz-Signature=aa"
PUT_S = f"https://{NETLOC}/res/results/{ID}/screenshot.webp?X-Amz-Signature=bb"
PUT_C = f"https://{NETLOC}/res/claims/{ID}?X-Amz-SignedHeaders=host%3Bif-none-match&X-Amz-Signature=cc"


def _store(**over):
    s = {
        "result_put": PUT_R,
        "screenshot_put": PUT_S,
        "claim_put": PUT_C,
        "claim_headers": {"If-None-Match": "*"},
        "expires": EXP,
    }
    s.update(over)
    return s


def test_filesystem_mode_refuses_a_job_carrying_store():
    with pytest.raises(spool.InvalidJob, match="store not allowed"):
        spool.validate_job(job(store=_store()), ID)


def test_filesystem_job_result_has_store_none():
    assert spool.validate_job(job(), ID)["store"] is None


def test_validate_store_happy_path_returns_exactly_the_five_keys():
    out = spool.validate_store({**_store(), "extra": 1}, NETLOC, False)
    assert out == _store()
    assert sorted(out) == ["claim_headers", "claim_put", "expires", "result_put", "screenshot_put"]


def test_validate_store_host_compare_is_case_insensitive():
    assert spool.validate_store(_store(), NETLOC.upper(), False)["expires"] == EXP


def test_validate_store_accepts_a_bucket_subdomain_of_the_store_host_only():
    virtual = _store(result_put=PUT_R.replace(NETLOC, "res." + NETLOC))  # virtual-hosted style
    assert spool.validate_store(virtual, NETLOC, False)["result_put"] == virtual["result_put"]
    with pytest.raises(spool.InvalidJob, match="host"):  # a look-alike host without the dot
        spool.validate_store(_store(result_put=PUT_R.replace(NETLOC, "evil" + NETLOC)), NETLOC, False)


@pytest.mark.parametrize(
    "obj,allow_http",
    [
        (None, False),
        ([], False),
        ("x", False),
        (_store(result_put=_ABSENT), False),
        (_store(result_put=5), False),
        (_store(result_put=""), False),
        (_store(screenshot_put=None), False),
        (_store(result_put="ftp://" + NETLOC + "/x"), False),
        (_store(result_put="file:///etc/passwd"), False),
        (_store(result_put=PUT_R.replace("https", "http")), False),  # http needs the flag
        (_store(screenshot_put=PUT_S.replace(NETLOC, "evil.example.net")), False),  # host mismatch
        (_store(result_put=PUT_R.replace(NETLOC, "user@" + NETLOC)), False),
        (_store(result_put="https:///x"), False),
        (_store(result_put=PUT_R + "a" * spool.MAX_STORE_URL_CHARS), False),
        (_store(expires=True), False),
        (_store(expires=0), False),
        (_store(expires=10**12), False),
        (_store(expires="2000000000"), False),
        (_store(expires=_ABSENT), False),
    ],
)
def test_validate_store_rejects(obj, allow_http):
    if isinstance(obj, dict):
        obj = {k: v for k, v in obj.items() if v is not _ABSENT}
    with pytest.raises(spool.InvalidJob):
        spool.validate_store(obj, NETLOC, allow_http)


@pytest.mark.parametrize(
    "claim,why",
    [
        (_ABSENT, "missing"),
        (None, "non-string"),
        (5, "non-string"),
        ("", "empty"),
        (PUT_C.replace(NETLOC, "evil.example.net"), "wrong host"),
        (PUT_C.replace("https", "http"), "http without allow_http"),
        (PUT_C.replace(NETLOC, "user@" + NETLOC), "userinfo"),
        ("https:///x", "no host"),
    ],
)
def test_validate_store_claim_put_is_required_and_validated(claim, why):
    obj = {k: v for k, v in _store(claim_put=claim).items() if v is not _ABSENT}
    with pytest.raises(spool.InvalidJob, match="claim_put"):
        spool.validate_store(obj, NETLOC, False)


@pytest.mark.parametrize(
    "headers",
    [
        _ABSENT,
        None,
        [("If-None-Match", "*")],
        {},
        {"If-None-Match": "*", "x-goog-if-generation-match": "0"},
        {"If-None-Match": "abc"},
        {"if-none-match": "*"},
        {"x-goog-if-generation-match": 0},
        {"x-goog-if-generation-match": "1"},
        {"Authorization": "x"},
    ],
)
def test_validate_store_claim_headers_is_required_and_an_exact_allowed_pair(headers):
    obj = {k: v for k, v in _store(claim_headers=headers).items() if v is not _ABSENT}
    with pytest.raises(spool.InvalidJob, match="claim_headers"):
        spool.validate_store(obj, NETLOC, False)


@pytest.mark.parametrize("pair", [{"If-None-Match": "*"}, {"x-goog-if-generation-match": "0"}])
def test_validate_store_accepts_each_allowed_claim_header_pair(pair):
    out = spool.validate_store(_store(claim_headers=pair), NETLOC, False)
    assert out["claim_headers"] == pair and out["claim_headers"] is not pair


def test_validate_store_http_allowed_only_with_the_flag():
    http = _store(
        result_put=PUT_R.replace("https", "http"),
        screenshot_put=PUT_S.replace("https", "http"),
        claim_put=PUT_C.replace("https", "http"),
    )
    with pytest.raises(spool.InvalidJob):
        spool.validate_store(http, NETLOC, False)
    assert spool.validate_store(http, NETLOC, True) == http


def test_validate_store_without_netloc_skips_the_host_check():
    other = _store(result_put="https://other.example.org/x")
    assert spool.validate_store(other, None, False)["result_put"] == "https://other.example.org/x"


def test_s3_job_carries_the_store():
    j = spool.validate_job(job(store=_store()), ID, store="s3", store_netloc=NETLOC)
    assert j["store"] == _store() and j["url"] == "https://example.com/"


def test_s3_job_without_store_is_invalid():
    with pytest.raises(spool.InvalidJob):
        spool.validate_job(job(), ID, store="s3", store_netloc=NETLOC)


def test_unknown_store_mode_is_a_programming_error():
    with pytest.raises(ValueError):
        spool.validate_job(job(), ID, store="other")
