"""capture.store_s3 + the worker's S3 mode (planning#318 S1c).

Offline tests use botocore's Stubber and a local http.server; the live tests run
against a real S3 (RustFS) and are skipped unless CAPTURE_S3_TEST_ENDPOINT is set."""

import io
import json
import os
import socket
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

import botocore.session
import pytest
from botocore.config import Config
from botocore.response import StreamingBody
from botocore.stub import Stubber

from capture import spool, store_s3, worker
from test_spool import EXP, ID, job

ID2 = "0190a1b2-c3d4-7e5f-8a6b-1234567890ac"
ID3 = "0190a1b2-c3d4-7e5f-8a6b-1234567890ad"
BUCKET = "jobs-bucket"
NETLOC = "s3.example.com:9000"
PUT_R = f"https://{NETLOC}/res/results/{ID}/result.json?X-Amz-Signature=aa"
PUT_S = f"https://{NETLOC}/res/results/{ID}/screenshot.webp?X-Amz-Signature=bb"
STORE = {"result_put": PUT_R, "screenshot_put": PUT_S, "expires": EXP}


class _Sentinel(Exception):
    pass


def _cfg(**over):
    env = {
        "CAPTURE_S3_ENDPOINT": "https://S3.Example.com:9000",
        "CAPTURE_S3_BUCKET_JOBS": BUCKET,
        "CAPTURE_S3_ACCESS_KEY": "AKIAEXAMPLE",
        "CAPTURE_S3_SECRET_KEY": "secret-example",
    }
    env.update(over)
    return store_s3.config_from_env({k: v for k, v in env.items() if v is not None})


@pytest.fixture
def stubbed():
    client = store_s3.make_client(_cfg())
    with Stubber(client) as stub:
        yield client, stub


def _body(data: bytes):
    return StreamingBody(io.BytesIO(data), len(data))


def s3_job(**over):
    return job(store=STORE, **over)


# --- config -------------------------------------------------------------------

def test_config_happy_path_and_defaults():
    cfg = _cfg()
    assert cfg.netloc == "s3.example.com:9000"  # lowercased
    assert cfg.region == "us-east-1" and cfg.path_style is True and cfg.allow_http is False
    assert cfg.bucket == BUCKET and cfg.access_key == "AKIAEXAMPLE"


@pytest.mark.parametrize(
    "over,var",
    [
        ({"CAPTURE_S3_ENDPOINT": None}, "CAPTURE_S3_ENDPOINT"),
        ({"CAPTURE_S3_ENDPOINT": "http://s3.example.com"}, "CAPTURE_S3_ENDPOINT"),
        ({"CAPTURE_S3_ENDPOINT": "https://user@s3.example.com"}, "CAPTURE_S3_ENDPOINT"),
        ({"CAPTURE_S3_ENDPOINT": "https://"}, "CAPTURE_S3_ENDPOINT"),
        ({"CAPTURE_S3_ENDPOINT": "ftp://s3.example.com"}, "CAPTURE_S3_ENDPOINT"),
        ({"CAPTURE_S3_SECRET_KEY": None}, "CAPTURE_S3_SECRET_KEY"),
        ({"CAPTURE_S3_ACCESS_KEY": None}, "CAPTURE_S3_ACCESS_KEY"),
        ({"CAPTURE_S3_BUCKET_JOBS": None}, "CAPTURE_S3_BUCKET_JOBS"),
        ({"CAPTURE_S3_PATH_STYLE": "yes"}, "CAPTURE_S3_PATH_STYLE"),
    ],
)
def test_config_errors_name_the_variable(over, var):
    with pytest.raises(store_s3.S3ConfigError, match=var):
        _cfg(**over)


def test_config_http_only_with_the_flag():
    cfg = _cfg(CAPTURE_S3_ENDPOINT="http://127.0.0.1:9318", CAPTURE_S3_INSECURE_HTTP="1")
    assert cfg.allow_http is True and cfg.netloc == "127.0.0.1:9318"


def test_config_neither_key_means_the_default_chain():
    cfg = _cfg(CAPTURE_S3_ACCESS_KEY=None, CAPTURE_S3_SECRET_KEY=None)
    assert cfg.access_key is None and cfg.secret_key is None


def test_config_path_style_false():
    assert _cfg(CAPTURE_S3_PATH_STYLE="false").path_style is False


# --- list / get / delete --------------------------------------------------------

def _listing(keys, **extra):
    return {"Contents": [{"Key": k} for k in keys], "IsTruncated": False, **extra}


def test_list_ids_filters_and_sorts(stubbed):
    client, stub = stubbed
    stub.add_response(
        "list_objects_v2",
        _listing([
            f"jobs/{ID2}.json", f"jobs/{ID}.json", f"jobs/.{ID}.tmp", "jobs/junk.json",
            f"jobs/sub/{ID3}.json", f"jobs/{ID.upper()}.json",
        ]),
        {"Bucket": BUCKET, "Prefix": "jobs/"},
    )
    assert store_s3.S3Jobs(client, BUCKET).list_ids() == [ID, ID2]
    stub.assert_no_pending_responses()


def test_list_ids_paginates(stubbed):
    client, stub = stubbed
    stub.add_response(
        "list_objects_v2",
        {"Contents": [{"Key": f"jobs/{ID2}.json"}], "IsTruncated": True, "NextContinuationToken": "t"},
    )
    stub.add_response("list_objects_v2", _listing([f"jobs/{ID}.json"]))
    assert store_s3.S3Jobs(client, BUCKET).list_ids() == [ID, ID2]
    stub.assert_no_pending_responses()


def test_list_ids_empty(stubbed):
    client, stub = stubbed
    stub.add_response("list_objects_v2", {"IsTruncated": False})
    assert store_s3.S3Jobs(client, BUCKET).list_ids() == []


def test_list_ids_client_error_is_a_store_error(stubbed):
    client, stub = stubbed
    stub.add_client_error("list_objects_v2", "AccessDenied")
    with pytest.raises(store_s3.StoreError, match="AccessDenied"):
        store_s3.S3Jobs(client, BUCKET).list_ids()


def test_get_returns_the_bytes(stubbed):
    client, stub = stubbed
    stub.add_response("get_object", {"Body": _body(b"hello")}, {"Bucket": BUCKET, "Key": f"jobs/{ID}.json"})
    assert store_s3.S3Jobs(client, BUCKET).get(ID) == b"hello"


@pytest.mark.parametrize("code", ["NoSuchKey", "404", "NotFound"])
def test_get_missing_is_none(stubbed, code):
    client, stub = stubbed
    stub.add_client_error("get_object", code)
    assert store_s3.S3Jobs(client, BUCKET).get(ID) is None


def test_get_reads_at_most_the_cap_plus_one(stubbed):
    client, stub = stubbed
    stub.add_response("get_object", {"Body": _body(b"x" * (spool.JOB_MAX_BYTES + 50))})
    out = store_s3.S3Jobs(client, BUCKET).get(ID)
    assert len(out) == spool.JOB_MAX_BYTES + 1
    with pytest.raises(spool.InvalidJob, match="too large"):
        spool.validate_job(out, ID)


def test_get_closes_the_body(stubbed):
    client, stub = stubbed
    body = _body(b"hello")
    stub.add_response("get_object", {"Body": body})
    store_s3.S3Jobs(client, BUCKET).get(ID)
    assert body._raw_stream.closed


def test_get_other_errors_are_store_errors(stubbed):
    client, stub = stubbed
    stub.add_client_error("get_object", "AccessDenied")
    with pytest.raises(store_s3.StoreError, match="AccessDenied"):
        store_s3.S3Jobs(client, BUCKET).get(ID)


def test_delete_success(stubbed):
    client, stub = stubbed
    stub.add_response("delete_object", {}, {"Bucket": BUCKET, "Key": f"jobs/{ID}.json"})
    assert store_s3.S3Jobs(client, BUCKET).delete(ID) is True
    stub.assert_no_pending_responses()


def test_delete_failure_is_false_and_logged(stubbed, capsys):
    client, stub = stubbed
    stub.add_client_error("delete_object", "AccessDenied")
    assert store_s3.S3Jobs(client, BUCKET).delete(ID) is False
    err = capsys.readouterr().err
    assert err.count("\n") == 1 and ID in err and "AccessDenied" in err


# --- upload ---------------------------------------------------------------------

class _Recorder:
    def __init__(self):
        self.status = 200
        self.location = None
        self.requests = []
        rec = self

        class H(BaseHTTPRequestHandler):
            def do_PUT(self):
                n = int(self.headers.get("Content-Length") or 0)
                rec.requests.append((self.command, dict(self.headers), self.rfile.read(n), self.path))
                self.send_response(rec.status)
                if rec.location:
                    self.send_header("Location", rec.location)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/obj?X-Amz-Signature=sig"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def http_server():
    rec = _Recorder()
    yield rec
    rec.close()


def _dead_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_upload_ok_sends_the_body_and_only_content_headers(http_server):
    store_s3.upload(http_server.url, b"PAYLOAD", "image/webp")
    ((method, headers, body, path),) = http_server.requests
    assert method == "PUT" and body == b"PAYLOAD" and "X-Amz-Signature=sig" in path
    names = {k.lower(): v for k, v in headers.items()}
    assert names["content-type"] == "image/webp" and names["content-length"] == "7"
    assert not [n for n in names if n.startswith("x-amz-")]


def test_upload_403_is_an_upload_error(http_server):
    http_server.status = 403
    with pytest.raises(store_s3.UploadError) as exc:
        store_s3.upload(http_server.url, b"x", "application/json")
    assert str(exc.value) == "HTTP 403" and "sig" not in str(exc.value)


def test_upload_refuses_redirects(http_server):
    http_server.status = 301
    http_server.location = http_server.url + "&again=1"
    with pytest.raises(store_s3.UploadError, match="HTTP 301"):
        store_s3.upload(http_server.url, b"x", "application/json")
    assert len(http_server.requests) == 1


def test_upload_connection_refused_hides_the_url():
    url = f"http://127.0.0.1:{_dead_port()}/obj?X-Amz-Signature=sig"
    with pytest.raises(store_s3.UploadError) as exc:
        store_s3.upload(url, b"x", "application/json", timeout_s=2)
    assert "sig" not in str(exc.value) and "127.0.0.1" not in str(exc.value)


def test_upload_ignores_proxy_environment(http_server, monkeypatch):
    dead = f"http://127.0.0.1:{_dead_port()}"
    for name in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"):
        monkeypatch.setenv(name, dead)
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    store_s3.upload(http_server.url, b"direct", "application/json")
    assert [r[2] for r in http_server.requests] == [b"direct"]


# --- claim_next_s3 / extract_store -----------------------------------------------

class _FakeJobs:
    def __init__(self, ids, bodies, undeletable=()):
        self.ids, self.bodies, self.undeletable = ids, bodies, set(undeletable)
        self.deleted = []

    def list_ids(self):
        return list(self.ids)

    def get(self, cid):
        return self.bodies.get(cid)

    def delete(self, cid):
        if cid in self.undeletable:
            return False
        self.deleted.append(cid)
        return True


def test_claim_returns_the_first_claimable_job():
    jobs = _FakeJobs([ID, ID2], {ID: b"a", ID2: b"b"})
    assert worker.claim_next_s3(jobs) == (ID, b"a")
    assert jobs.deleted == [ID]


def test_claim_skips_a_job_whose_delete_failed():
    jobs = _FakeJobs([ID, ID2], {ID: b"a", ID2: b"b"}, undeletable=[ID])
    assert worker.claim_next_s3(jobs) == (ID2, b"b")
    assert jobs.deleted == [ID2]  # ID was never claimed, so never processed


def test_claim_skips_a_job_gone_between_list_and_get():
    jobs = _FakeJobs([ID, ID2], {ID2: b"b"})
    assert worker.claim_next_s3(jobs) == (ID2, b"b")
    assert jobs.deleted == [ID2]  # nothing to delete for the vanished one


def test_claim_empty_listing_is_none():
    assert worker.claim_next_s3(_FakeJobs([], {})) is None


def test_claim_with_stubbed_client_does_get_then_delete(stubbed):
    client, stub = stubbed
    stub.add_response("list_objects_v2", _listing([f"jobs/{ID}.json"]))
    stub.add_response("get_object", {"Body": _body(b"raw")})
    stub.add_response("delete_object", {})
    assert worker.claim_next_s3(store_s3.S3Jobs(client, BUCKET)) == (ID, b"raw")
    stub.assert_no_pending_responses()


def test_extract_store():
    assert store_s3.extract_store(b"not json", NETLOC, False) is None
    assert store_s3.extract_store(b"[]", NETLOC, False) is None
    assert store_s3.extract_store(job(), NETLOC, False) is None
    assert store_s3.extract_store(s3_job(), NETLOC, False) == STORE
    assert store_s3.extract_store(s3_job(url="file:///x"), NETLOC, False) == STORE  # rest is not checked here


# --- process_s3 -------------------------------------------------------------------

@pytest.fixture
def uploads(monkeypatch):
    calls = []
    monkeypatch.setattr(
        store_s3, "upload", lambda url, data, ctype, **kw: calls.append((url, ctype, bytes(data)))
    )
    return calls


def _process(raw):
    worker.process_s3(ID, raw, netloc=NETLOC, allow_http=False)


def test_process_s3_uploads_screenshot_then_result(fake_playwright, uploads):
    _process(s3_job())
    assert [(u, c) for u, c, _ in uploads] == [(PUT_S, "image/webp"), (PUT_R, "application/json")]
    assert uploads[0][2] == b"RIFF....WEBP"
    result = json.loads(uploads[1][2])
    assert result["screenshot"]["file"] == "screenshot.webp" and result["error"] is None


def test_process_s3_screenshot_failure_still_uploads_the_result(fake_playwright, monkeypatch, capsys):
    calls = []

    def fake_upload(url, data, ctype, **kw):
        calls.append((url, ctype, bytes(data)))
        if url == PUT_S:
            raise store_s3.UploadError("HTTP 500")

    monkeypatch.setattr(store_s3, "upload", fake_upload)
    _process(s3_job())
    assert [c[0] for c in calls] == [PUT_S, PUT_R]
    result = json.loads(calls[1][2])
    assert result["screenshot"] is None and result["screenshot_omitted_reason"] == "upload_failed"
    assert result["final_url"] == "https://example.com/"
    err = capsys.readouterr().err
    assert "screenshot upload failed: HTTP 500" in err and "X-Amz" not in err


def test_process_s3_result_failure_does_not_raise(fake_playwright, monkeypatch, capsys):
    def fake_upload(url, data, ctype, **kw):
        if url == PUT_R:
            raise store_s3.UploadError("HTTP 403")

    monkeypatch.setattr(store_s3, "upload", fake_upload)
    _process(s3_job())
    err = capsys.readouterr().err
    assert "result upload failed: HTTP 403" in err and "X-Amz" not in err


def test_process_s3_invalid_job_answers_through_result_put_without_a_browser(uploads):
    _process(s3_job(url="file:///etc/passwd"))
    assert [(u, c) for u, c, _ in uploads] == [(PUT_R, "application/json")]
    assert json.loads(uploads[0][2])["error"] == "invalid_job"
    assert "playwright" not in sys.modules


def test_process_s3_bad_store_uploads_nothing(uploads, capsys):
    bad = dict(STORE, result_put=PUT_R.replace(NETLOC, "evil.example.net"))
    _process(job(store=bad))
    assert uploads == []
    assert "invalid store object" in capsys.readouterr().err


# --- main() in S3 mode ---------------------------------------------------------------

@pytest.fixture
def s3_env(monkeypatch):
    monkeypatch.setenv("CAPTURE_PROXY_URL", "http://proxy.example.test:3128")
    monkeypatch.setenv("CAPTURE_STORE", "s3")
    monkeypatch.setenv("CAPTURE_S3_ENDPOINT", "https://s3.example.com:9000")
    monkeypatch.setenv("CAPTURE_S3_BUCKET_JOBS", BUCKET)
    monkeypatch.setenv("CAPTURE_S3_ACCESS_KEY", "AKIAEXAMPLE")
    monkeypatch.setenv("CAPTURE_S3_SECRET_KEY", "secret-example")
    monkeypatch.setattr(worker, "SPOOL_DIR", "/nonexistent-spool")  # no directory check in S3 mode


def test_main_s3_claims_and_processes_one_job_then_returns_zero(s3_env, monkeypatch):
    client = store_s3.make_client(_cfg())
    calls = []
    monkeypatch.setattr(store_s3, "make_client", lambda cfg: client)
    monkeypatch.setattr(worker, "process_s3", lambda cid, raw, **kw: calls.append((cid, raw, kw)))
    with Stubber(client) as stub:
        stub.add_response("list_objects_v2", _listing([f"jobs/{ID}.json"]))
        stub.add_response("get_object", {"Body": _body(b"RAW")})
        stub.add_response("delete_object", {})
        assert worker.main() == 0
        stub.assert_no_pending_responses()
    assert calls == [(ID, b"RAW", {"netloc": "s3.example.com:9000", "allow_http": False})]


def test_main_s3_config_error_exits(s3_env, monkeypatch):
    monkeypatch.delenv("CAPTURE_S3_ENDPOINT")
    with pytest.raises(SystemExit, match="CAPTURE_S3_ENDPOINT"):
        worker.main()


def test_main_s3_listing_failure_sleeps_and_retries(s3_env, monkeypatch, capsys):
    slept = []

    def fake_sleep(s):
        slept.append(s)
        if len(slept) == 3:
            raise _Sentinel

    errors = iter(["AccessDenied", "AccessDenied", "NoSuchBucket"])

    def boom(self):
        raise store_s3.StoreError(next(errors))

    monkeypatch.setattr(store_s3.S3Jobs, "list_ids", boom)
    monkeypatch.setattr(worker.time, "sleep", fake_sleep)
    with pytest.raises(_Sentinel):
        worker.main()
    assert slept == [worker.POLL_INTERVAL_S] * 3
    err = capsys.readouterr().err
    # the same error is printed once, not once per poll; a different error is printed again
    assert err.count("listing jobs failed: AccessDenied") == 1
    assert err.count("listing jobs failed: NoSuchBucket") == 1


# --- live (real S3) -------------------------------------------------------------------

LIVE = os.environ.get("CAPTURE_S3_TEST_ENDPOINT")


def _empty_and_delete(admin, bucket):
    try:
        for page in admin.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents") or []:
                admin.delete_object(Bucket=bucket, Key=obj["Key"])
        admin.delete_bucket(Bucket=bucket)
    except Exception:  # noqa: BLE001 - best-effort cleanup
        pass


@pytest.mark.skipif(not LIVE, reason="CAPTURE_S3_TEST_ENDPOINT not set")
def test_live_claim_process_and_signature_tamper(fake_playwright, monkeypatch):
    tag = uuid.uuid4().hex[:8]
    jobs_b, res_b = f"cap-{tag}-jobs", f"cap-{tag}-results"
    admin = botocore.session.get_session().create_client(
        "s3",
        endpoint_url=LIVE,
        region_name="us-east-1",
        aws_access_key_id=os.environ["CAPTURE_S3_TEST_ACCESS_KEY"],
        aws_secret_access_key=os.environ["CAPTURE_S3_TEST_SECRET_KEY"],
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )
    try:
        admin.create_bucket(Bucket=jobs_b)
        admin.create_bucket(Bucket=res_b)

        def presign(name):
            return admin.generate_presigned_url(
                "put_object",
                Params={"Bucket": res_b, "Key": f"results/{ID}/{name}"},
                ExpiresIn=600,
                HttpMethod="PUT",
            )

        store = {"result_put": presign("result.json"), "screenshot_put": presign("screenshot.webp"), "expires": EXP}
        admin.put_object(Bucket=jobs_b, Key=f"jobs/{ID}.json", Body=job(store=store))

        monkeypatch.setenv("CAPTURE_S3_ENDPOINT", LIVE)
        monkeypatch.setenv("CAPTURE_S3_INSECURE_HTTP", "1")
        monkeypatch.setenv("CAPTURE_S3_ACCESS_KEY", os.environ["CAPTURE_S3_TEST_ACCESS_KEY"])
        monkeypatch.setenv("CAPTURE_S3_SECRET_KEY", os.environ["CAPTURE_S3_TEST_SECRET_KEY"])
        monkeypatch.setenv("CAPTURE_S3_BUCKET_JOBS", jobs_b)
        cfg = store_s3.config_from_env()
        jobs = store_s3.S3Jobs(store_s3.make_client(cfg), cfg.bucket)

        claimed = worker.claim_next_s3(jobs)
        assert claimed is not None and claimed[0] == ID
        listed = admin.list_objects_v2(Bucket=jobs_b, Prefix="jobs/")
        assert listed.get("KeyCount", 0) == 0  # the delete was the claim

        worker.process_s3(ID, claimed[1], netloc=cfg.netloc, allow_http=cfg.allow_http)
        result = json.loads(admin.get_object(Bucket=res_b, Key=f"results/{ID}/result.json")["Body"].read())
        assert result["capture_id"] == ID and result["screenshot"]["file"] == "screenshot.webp"
        shot = admin.get_object(Bucket=res_b, Key=f"results/{ID}/screenshot.webp")["Body"].read()
        assert shot == b"RIFF....WEBP"

        assert worker.claim_next_s3(jobs) is None

        url = store["result_put"]
        sig_at = url.index("X-Amz-Signature=") + len("X-Amz-Signature=")
        flipped = "0" if url[sig_at] != "0" else "1"  # still valid hex: a wrong signature, not a malformed one
        tampered = url[:sig_at] + flipped + url[sig_at + 1:]
        assert tampered != store["result_put"]
        with pytest.raises(store_s3.UploadError, match="HTTP 403"):
            store_s3.upload(tampered, b"{}", "application/json")
    finally:
        _empty_and_delete(admin, jobs_b)
        _empty_and_delete(admin, res_b)
