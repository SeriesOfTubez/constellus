"""S3 capture store (planning#318 S1b). Offline only: botocore's Stubber stands in for the
network and a fake signer stands in wherever the signature itself is not under test.
Synthetic ids only.

Run with:  backend/scripts/test.sh app/tests/test_capture_store_s3.py
"""

import io
import logging
import time
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

import botocore.session
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError
from botocore.response import StreamingBody
from botocore.stub import Stubber

from app.services import capture_store_s3 as m
from app.services.capture_store import FilesystemStore, StoreConfigError, get_store
from app.services.capture_store_s3 import S3Buckets, S3Store, SigV4Signer

ID = "11111111-1111-4111-8111-111111111111"
A, B, C, D = (f"{n}{n}{n}{n}{n}{n}{n}{n}-{n}{n}{n}{n}-4{n}{n}{n}-8{n}{n}{n}-{n * 12}" for n in "abcd")
WHEN = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
BUCKETS = S3Buckets("b-jobs", "b-results", "b-proxylog", "b-images")

_CONFIG = Config(signature_version="s3v4", s3={"addressing_style": "path"}, connect_timeout=5, read_timeout=30,
                 retries={"max_attempts": 3, "mode": "standard"})


def _client():
    return botocore.session.get_session().create_client(
        "s3", region_name="us-east-1", endpoint_url="https://store.example",
        aws_access_key_id="k", aws_secret_access_key="s", config=_CONFIG)


class _FakeSigner:
    def __init__(self):
        self.calls = []

    def presign(self, method, bucket, key, expires_in):
        self.calls.append((method, bucket, key, expires_in))
        return f"signed:{method}:{key}"

    def presign_put_if_absent(self, bucket, key, expires_in):
        self.calls.append(("PUT-IF-ABSENT", bucket, key, expires_in))
        return f"signed:PUT-IF-ABSENT:{key}"


@pytest.fixture(autouse=True)
def _fresh_probe_cache():
    m._CONDITIONAL_OK.clear()
    yield
    m._CONDITIONAL_OK.clear()


def _seed_probe():
    m._CONDITIONAL_OK.add(("https://store.example", BUCKETS.results))


def _store(client, signer=None):
    return S3Store(client, signer or _FakeSigner(), BUCKETS)


def _body(data: bytes, length: int | None = None):
    return StreamingBody(io.BytesIO(data), len(data) if length is None else length)


class _NoReadBody(StreamingBody):
    def __init__(self):
        super().__init__(io.BytesIO(b"x"), 1)
        self.read_called = False

    def read(self, amt=None):
        self.read_called = True
        raise AssertionError("the body must not be read when ContentLength exceeds the cap")


def _listing(*keys, truncated=False, token=None):
    r = {"Contents": [{"Key": k, "LastModified": WHEN} for k in keys], "IsTruncated": truncated}
    if token:
        r["NextContinuationToken"] = token
    return r


_FULL_ENV = {
    "CAPTURE_STORE": "s3", "CAPTURE_S3_ENDPOINT": "https://store.example",
    "CAPTURE_S3_ACCESS_KEY": "k", "CAPTURE_S3_SECRET_KEY": "s",
    "CAPTURE_S3_BUCKET_JOBS": "b-jobs", "CAPTURE_S3_BUCKET_RESULTS": "b-results",
    "CAPTURE_S3_BUCKET_PROXYLOG": "b-proxylog", "CAPTURE_S3_BUCKET_IMAGES": "b-images",
}
_ALL_VARS = [*_FULL_ENV, "CAPTURE_S3_REGION", "CAPTURE_S3_PATH_STYLE", "CAPTURE_S3_INSECURE_HTTP",
                                    "CAPTURE_S3_PUBLIC_ENDPOINT"]


@pytest.fixture
def env(monkeypatch):
    for v in _ALL_VARS:
        monkeypatch.delenv(v, raising=False)
    for k, v in _FULL_ENV.items():
        monkeypatch.setenv(k, v)
    m._client.cache_clear()
    yield monkeypatch
    m._client.cache_clear()


# ── dispatch and config ──────────────────────────────────────────────────────


def test_dispatch_filesystem_default_and_s3_and_unknown(env):
    env.delenv("CAPTURE_STORE")
    assert isinstance(get_store(), FilesystemStore)
    env.setenv("CAPTURE_STORE", "s3")
    assert isinstance(get_store(), S3Store)
    env.setenv("CAPTURE_STORE", "minio")
    with pytest.raises(StoreConfigError):
        get_store()
    assert isinstance(StoreConfigError(""), OSError)


def test_filesystem_job_fields_is_empty(tmp_path):
    assert FilesystemStore(str(tmp_path), str(tmp_path), str(tmp_path)).job_fields(ID, 123) == {}


def test_config_requires_all_four_buckets(env):
    env.delenv("CAPTURE_S3_BUCKET_IMAGES")
    with pytest.raises(StoreConfigError) as e:
        m.s3_config_from_env()
    assert "CAPTURE_S3_BUCKET_IMAGES" in str(e.value)


def test_config_keys_both_or_neither(env):
    env.delenv("CAPTURE_S3_SECRET_KEY")
    with pytest.raises(StoreConfigError):
        m.s3_config_from_env()
    env.delenv("CAPTURE_S3_ACCESS_KEY")
    assert m.s3_config_from_env().access_key is None
    env.setenv("CAPTURE_S3_ACCESS_KEY", "k")
    env.setenv("CAPTURE_S3_SECRET_KEY", "s")
    assert m.s3_config_from_env().access_key == "k"


def test_config_endpoint_scheme(env):
    env.setenv("CAPTURE_S3_ENDPOINT", "http://store:9000")
    with pytest.raises(StoreConfigError):
        m.s3_config_from_env()
    env.setenv("CAPTURE_S3_INSECURE_HTTP", "1")
    assert m.s3_config_from_env().endpoint == "http://store:9000"
    env.delenv("CAPTURE_S3_INSECURE_HTTP")
    env.setenv("CAPTURE_S3_ENDPOINT", "https://store.example")
    assert m.s3_config_from_env().endpoint == "https://store.example"
    for bad in ("ftp://store.example", "https://user@store.example"):
        env.setenv("CAPTURE_S3_ENDPOINT", bad)
        with pytest.raises(StoreConfigError):
            m.s3_config_from_env()
    env.delenv("CAPTURE_S3_ENDPOINT")
    assert m.s3_config_from_env().endpoint is None


def test_config_path_style(env):
    assert m.s3_config_from_env().path_style is True
    env.setenv("CAPTURE_S3_PATH_STYLE", "FALSE")
    assert m.s3_config_from_env().path_style is False
    env.setenv("CAPTURE_S3_PATH_STYLE", "maybe")
    with pytest.raises(StoreConfigError):
        m.s3_config_from_env()


def test_client_is_cached_per_config(env):
    try:
        c1 = m._client(m.s3_config_from_env())
        c2 = m._client(m.s3_config_from_env())
        assert c1 is c2
        env.setenv("CAPTURE_S3_ENDPOINT", "https://other.example")
        assert m._client(m.s3_config_from_env()) is not c1
    finally:
        m._client.cache_clear()


def test_config_public_endpoint(env):
    assert m.s3_config_from_env().public_endpoint is None
    env.setenv("CAPTURE_S3_PUBLIC_ENDPOINT", "https://store.example.test")
    assert m.s3_config_from_env().public_endpoint == "https://store.example.test"
    env.setenv("CAPTURE_S3_PUBLIC_ENDPOINT", "http://store.example.test:9000")
    with pytest.raises(StoreConfigError, match="CAPTURE_S3_PUBLIC_ENDPOINT"):
        m.s3_config_from_env()
    env.setenv("CAPTURE_S3_INSECURE_HTTP", "1")
    assert m.s3_config_from_env().public_endpoint == "http://store.example.test:9000"
    env.delenv("CAPTURE_S3_INSECURE_HTTP")
    env.setenv("CAPTURE_S3_PUBLIC_ENDPOINT", "https://user@store.example.test")
    with pytest.raises(StoreConfigError, match="CAPTURE_S3_PUBLIC_ENDPOINT"):
        m.s3_config_from_env()


def test_presign_client_selection(env):
    cfg = m.s3_config_from_env()
    assert m._presign_client(cfg) is m._client(cfg)
    env.setenv("CAPTURE_S3_PUBLIC_ENDPOINT", "https://store.example.test")
    cfg = m.s3_config_from_env()
    assert m._presign_client(cfg) is not m._client(cfg)
    assert m._presign_client(cfg).meta.endpoint_url == "https://store.example.test"
    assert m._client(cfg).meta.endpoint_url == "https://store.example"


def test_store_from_env_signs_for_the_public_endpoint(env):
    env.setenv("CAPTURE_S3_PUBLIC_ENDPOINT", "https://store.example.test")
    try:
        store = m.s3_store_from_env()
        _seed_probe()  # the probe talks to the private endpoint; presign-only here
        urls = store.job_fields(ID, int(time.time()) + 600)["store"]
        for k in ("result_put", "screenshot_put", "claim_put"):
            assert urlsplit(urls[k]).netloc == "store.example.test"
        assert store._c.meta.endpoint_url == "https://store.example"
    finally:
        m._client.cache_clear()


# ── signer ───────────────────────────────────────────────────────────────────


def test_sigv4_presign_put_and_get_shape():
    signer = SigV4Signer(_client())
    put = urlsplit(signer.presign("PUT", "b", "results/x/result.json", 600))
    q = {k: v[0] for k, v in parse_qs(put.query).items()}
    assert put.scheme == "https" and put.netloc == "store.example"
    assert put.path == "/b/results/x/result.json"
    assert q["X-Amz-Algorithm"] == "AWS4-HMAC-SHA256"
    assert q["X-Amz-Expires"] == "600"
    assert q["X-Amz-SignedHeaders"] == "host"
    assert q["X-Amz-Credential"].startswith("k/") and "/us-east-1/s3/aws4_request" in q["X-Amz-Credential"]
    get = urlsplit(signer.presign("GET", "b", "results/x/result.json", 600))
    assert parse_qs(get.query)["X-Amz-Signature"] != q["X-Amz-Signature"]


def test_job_fields_shape_and_expiry(monkeypatch):
    sig = _FakeSigner()
    store = _store(_client(), sig)
    _seed_probe()
    monkeypatch.setattr(m.time, "time", lambda: 1000.0)
    out = store.job_fields(ID, 1600)
    assert sig.calls == [
        ("PUT", "b-results", f"results/{ID}/result.json", 600),
        ("PUT", "b-results", f"results/{ID}/screenshot.webp", 600),
        ("PUT-IF-ABSENT", "b-results", f"claims/{ID}", 600),
    ]
    assert out == {"store": {
        "result_put": f"signed:PUT:results/{ID}/result.json",
        "screenshot_put": f"signed:PUT:results/{ID}/screenshot.webp",
        "claim_put": f"signed:PUT-IF-ABSENT:claims/{ID}",
        "expires": 1600,
    }}
    sig.calls.clear()
    store.job_fields(ID, 900)
    assert [c[3] for c in sig.calls] == [1, 1, 1]


def test_job_fields_presign_failure_is_oserror():
    """A botocore error while presigning must surface as OSError: request_capture only
    catches OSError, and anything else would leave the row queued until the timeout sweep."""
    from botocore.exceptions import ParamValidationError

    class _Broken:
        def presign(self, method, bucket, key, expires_in):
            raise ParamValidationError(report="bad key")

    store = _store(_client(), _Broken())
    _seed_probe()
    with pytest.raises(OSError) as info:
        store.job_fields(ID, int(m.time.time()) + 60)
    assert str(info.value) == "capture store: ParamValidationError: "


# ── jobs ─────────────────────────────────────────────────────────────────────


def test_put_job_exact_key_and_error_is_oserror():
    client = _client()
    with Stubber(client) as stub:
        stub.add_response("put_object", {}, {
            "Bucket": "b-jobs", "Key": f"jobs/{ID}.json", "Body": b'{"a":1}', "ContentType": "application/json"})
        stub.add_client_error("put_object", "AccessDenied")
        store = _store(client)
        store.put_job(ID, b'{"a":1}')
        with pytest.raises(OSError):
            store.put_job(ID, b'{"a":1}')
        stub.assert_no_pending_responses()


def test_delete_job_is_quiet_on_error(caplog):
    client = _client()
    with Stubber(client) as stub:
        stub.add_client_error("delete_object", "AccessDenied")
        with caplog.at_level(logging.WARNING):
            _store(client).delete_job(ID)
        stub.assert_no_pending_responses()
    assert any("jobs/" in r.getMessage() and "AccessDenied" in r.getMessage() for r in caplog.records)


# ── results ──────────────────────────────────────────────────────────────────


def test_list_results_requires_result_json_and_filters():
    client = _client()
    keys = [f"results/{A}/screenshot.webp", f"results/{B}/screenshot.webp", f"results/{B}/result.json",
            "results/.hidden/result.json", f"results/{C}/result.json/extra", f"results/{B}/",
            f"results/{D}/result.json"]
    with Stubber(client) as stub:
        stub.add_response("list_objects_v2", _listing(*keys), {"Bucket": "b-results", "Prefix": "results/"})
        assert _store(client).list_results() == sorted([B, D])
        stub.assert_no_pending_responses()


def test_list_results_paginates():
    client = _client()
    with Stubber(client) as stub:
        stub.add_response("list_objects_v2", _listing(f"results/{A}/result.json", truncated=True, token="t"),
                          {"Bucket": "b-results", "Prefix": "results/"})
        stub.add_response("list_objects_v2", _listing(f"results/{B}/result.json"),
                          {"Bucket": "b-results", "Prefix": "results/", "ContinuationToken": "t"})
        assert _store(client).list_results() == sorted([A, B])
        stub.assert_no_pending_responses()


def test_list_results_missing_bucket_is_empty_other_errors_raise():
    client = _client()
    with Stubber(client) as stub:
        stub.add_client_error("list_objects_v2", "NoSuchBucket")
        stub.add_client_error("list_objects_v2", "AccessDenied")
        store = _store(client)
        assert store.list_results() == []
        with pytest.raises(OSError):
            store.list_results()
        stub.assert_no_pending_responses()


def test_result_info_from_result_json_head():
    client = _client()
    with Stubber(client) as stub:
        stub.add_response("head_object", {"LastModified": WHEN},
                          {"Bucket": "b-results", "Key": f"results/{ID}/result.json"})
        stub.add_client_error("head_object", "404")
        store = _store(client)
        assert store.result_info(ID) == (WHEN.timestamp(), True)
        assert store.result_info(ID) is None
        stub.assert_no_pending_responses()


def test_remove_result_deletes_every_key_under_the_prefix():
    client = _client()
    k1, k2 = f"results/{ID}/result.json", f"results/{ID}/screenshot.webp"
    with Stubber(client) as stub:
        stub.add_response("list_objects_v2", _listing(k1, k2), {"Bucket": "b-results", "Prefix": f"results/{ID}/"})
        stub.add_response("delete_object", {}, {"Bucket": "b-results", "Key": k1})
        stub.add_response("delete_object", {}, {"Bucket": "b-results", "Key": k2})
        stub.add_client_error("list_objects_v2", "AccessDenied")
        store = _store(client)
        store.remove_result(ID)
        store.remove_result(ID)  # a listing error: no raise
        stub.assert_no_pending_responses()


def test_result_files_ok_rules():
    client = _client()
    r, s_, extra, marker = (f"results/{ID}/{n}" for n in ("result.json", "screenshot.webp", "extra", ""))
    params = {"Bucket": "b-results", "Prefix": f"results/{ID}/"}
    with Stubber(client) as stub:
        for keys in ([r, s_], [r], [r, extra], [marker, r], []):
            stub.add_response("list_objects_v2", _listing(*keys), params)
        stub.add_client_error("list_objects_v2", "AccessDenied")
        store = _store(client)
        assert [store.result_files_ok(ID) for _ in range(6)] == [True, True, False, False, False, False]
        stub.assert_no_pending_responses()


def test_read_result_file_caps():
    client = _client()
    params = {"Bucket": "b-results", "Key": f"results/{ID}/result.json"}
    spy = _NoReadBody()
    with Stubber(client) as stub:
        stub.add_response("get_object", {"Body": _body(b"0123456789"), "ContentLength": 10}, params)
        stub.add_response("get_object", {"Body": spy, "ContentLength": 11}, params)
        stub.add_response("get_object", {"Body": _body(b"x" * 20, 20), "ContentLength": 5}, params)  # lying header
        stub.add_client_error("get_object", "404")
        store = _store(client)
        assert store.read_result_file(ID, "result.json", 10) == b"0123456789"
        assert store.read_result_file(ID, "result.json", 10) is None
        assert spy.read_called is False
        assert store.read_result_file(ID, "result.json", 10) is None
        assert store.read_result_file(ID, "result.json", 10) is None
        stub.assert_no_pending_responses()


# ── proxy log ────────────────────────────────────────────────────────────────


def test_read_proxylog_truncation_and_missing():
    client = _client()
    params = {"Bucket": "b-proxylog", "Key": f"proxylog/{ID}.jsonl"}
    with Stubber(client) as stub:
        stub.add_response("get_object", {"Body": _body(b"a" * 9), "ContentLength": 9}, params)
        stub.add_response("get_object", {"Body": _body(b"a" * 10), "ContentLength": 10}, params)
        stub.add_response("get_object", {"Body": _body(b"a" * 25), "ContentLength": 25}, params)
        stub.add_client_error("get_object", "NoSuchKey")
        store = _store(client)
        assert store.read_proxylog(ID, 10) == (b"a" * 9, False)
        assert store.read_proxylog(ID, 10) == (b"a" * 10, True)
        data, truncated = store.read_proxylog(ID, 10)
        assert len(data) == 10 and truncated is True
        assert store.read_proxylog(ID, 10) is None
        stub.assert_no_pending_responses()


# ── images ───────────────────────────────────────────────────────────────────


def test_images_round_trip_and_delete_errors(caplog):
    client = _client()
    key = {"Bucket": "b-images", "Key": f"images/{ID}.webp"}
    with Stubber(client) as stub:
        stub.add_response("put_object", {}, {**key, "Body": b"img", "ContentType": "image/webp"})
        stub.add_response("get_object", {"Body": _body(b"img"), "ContentLength": 3}, key)
        stub.add_response("get_object", {"Body": _body(b"img"), "ContentLength": 3}, key)
        stub.add_response("delete_object", {}, key)
        stub.add_client_error("delete_object", "AccessDenied")
        stub.add_client_error("delete_object", "AccessDenied")
        store = _store(client)
        store.put_image(ID, b"img")
        assert store.read_image(ID, 3) == b"img"
        assert store.read_image(ID, 2) is None
        store.delete_image(ID)
        with pytest.raises(OSError):
            store.delete_image(ID)
        with caplog.at_level(logging.WARNING):
            store.delete_image_quiet(ID)
        stub.assert_no_pending_responses()
    assert any("images/" in r.getMessage() and "AccessDenied" in r.getMessage() for r in caplog.records)


def test_check_spool_and_images_head_buckets():
    client = _client()
    with Stubber(client) as stub:
        stub.add_response("head_bucket", {}, {"Bucket": "b-jobs"})
        stub.add_response("head_bucket", {}, {"Bucket": "b-results"})
        stub.add_response("head_bucket", {}, {"Bucket": "b-proxylog"})
        stub.add_client_error("head_bucket", "404")
        stub.add_response("head_bucket", {}, {"Bucket": "b-images"})
        stub.add_client_error("head_bucket", "404")
        store = _store(client)
        store.check_spool()
        with pytest.raises(OSError):
            store.check_spool()
        store.check_images()
        with pytest.raises(OSError):
            store.check_images()
        stub.assert_no_pending_responses()


# ── no leakage ───────────────────────────────────────────────────────────────


def test_no_secret_or_url_in_error_messages(env):
    client = _client()
    with Stubber(client) as stub:
        stub.add_client_error("put_object", "AccessDenied", service_message="request for https://store.example/x")
        with pytest.raises(OSError) as e:
            _store(client).put_job(ID, b"{}")
        stub.assert_no_pending_responses()
    assert str(e.value) == "capture store: ClientError: AccessDenied"
    env.setenv("CAPTURE_S3_ACCESS_KEY", "AKIATESTDISTINCT")
    env.delenv("CAPTURE_S3_BUCKET_JOBS")
    with pytest.raises(StoreConfigError) as ce:
        m.s3_config_from_env()
    assert "AKIATESTDISTINCT" not in str(ce.value)


# ── claim marker (planning#323) ──────────────────────────────────────────────


def test_sigv4_presign_put_if_absent_signs_the_if_none_match_header():
    url = urlsplit(SigV4Signer(_client()).presign_put_if_absent("b", f"claims/{ID}", 600))
    q = {k: v[0] for k, v in parse_qs(url.query).items()}
    assert url.path == f"/b/claims/{ID}"
    assert q["X-Amz-Expires"] == "600"
    assert q["X-Amz-SignedHeaders"].split(";") == ["host", "if-none-match"]


def test_claim_marker_max_age_matches_the_claim_url_lifetime():
    from app.services import page_capture as pc
    assert m.CLAIM_SKEW_S == 300
    assert m.CLAIM_MARKER_MAX_AGE_S == pc.QUEUE_TIMEOUT_MAX + pc.CREDENTIAL_RUN_MARGIN_S + m.CLAIM_SKEW_S


def _precondition_failed():
    return ClientError({"Error": {"Code": "PreconditionFailed", "Message": ""},
                        "ResponseMetadata": {"HTTPStatusCode": 412}}, "PutObject")


class _ProbeClient:
    """Fake client for the probe: `puts` is a script of per-call outcomes (None = success,
    an exception = raised). Records every put and delete."""

    def __init__(self, puts, endpoint="https://store.example"):
        self.meta = type("Meta", (), {"endpoint_url": endpoint})()
        self.script = list(puts)
        self.puts, self.deletes = [], []

    def put_object(self, **kw):
        self.puts.append(kw)
        out = self.script.pop(0) if self.script else None
        if out is not None:
            raise out
        return {}

    def delete_object(self, **kw):
        self.deletes.append(kw)
        return {}


def _conforming():
    return _ProbeClient([None, _precondition_failed()])


def test_job_fields_contains_the_claim_put_after_a_passing_probe():
    sig = _FakeSigner()
    client = _conforming()
    out = _store(client, sig).job_fields(ID, int(time.time()) + 600)
    assert out["store"]["claim_put"] == f"signed:PUT-IF-ABSENT:claims/{ID}"
    (call,) = [c for c in sig.calls if c[0] == "PUT-IF-ABSENT"]
    assert call[1:3] == ("b-results", f"claims/{ID}")
    assert len(client.puts) == 2  # the probe was reached
    assert all(p["IfNoneMatch"] == "*" and p["Bucket"] == "b-results" for p in client.puts)


def test_probe_success_is_cached_per_process(caplog):
    client = _conforming()
    store = _store(client)
    store.job_fields(ID, int(time.time()) + 600)
    store.job_fields(ID, int(time.time()) + 600)
    _store(client).job_fields(ID, int(time.time()) + 600)  # a fresh store, like get_store() builds
    assert len(client.puts) == 2
    # another endpoint is a different key and probes again
    other = _ProbeClient([None, _precondition_failed()], endpoint="https://other.example")
    _store(other).job_fields(ID, int(time.time()) + 600)
    assert len(other.puts) == 2


def test_a_store_that_ignores_the_condition_issues_no_job(caplog):
    sig = _FakeSigner()
    client = _ProbeClient([None, None])  # the second PUT succeeds: the condition was ignored
    caplog.set_level(logging.ERROR)
    with pytest.raises(OSError) as info:
        _store(client, sig).job_fields(ID, int(time.time()) + 600)
    assert "conditional writes not supported" in str(info.value)
    assert sig.calls == []  # nothing presigned
    assert len(client.puts) == 2 and len(client.deletes) == 1  # reached, and the probe key removed
    assert client.deletes[0]["Key"] == client.puts[0]["Key"] and client.deletes[0]["Key"].startswith("claims/.probe-")
    assert "does not honour conditional writes" in caplog.text
    assert not m._CONDITIONAL_OK
    # not cached: the next request probes again
    client.script = [None, None]
    with pytest.raises(OSError):
        _store(client, sig).job_fields(ID, int(time.time()) + 600)
    assert len(client.puts) == 4


def test_probe_deletes_its_key_on_success_too():
    client = _conforming()
    _store(client).ensure_conditional_writes()
    assert len(client.deletes) == 1 and client.deletes[0]["Key"] == client.puts[0]["Key"]


def test_probe_other_errors_are_oserror_and_not_cached():
    denied = ClientError({"Error": {"Code": "AccessDenied"}, "ResponseMetadata": {"HTTPStatusCode": 403}}, "PutObject")
    sig = _FakeSigner()
    for script in ([denied], [None, denied]):
        client = _ProbeClient(script)
        with pytest.raises(OSError) as info:
            _store(client, sig).job_fields(ID, int(time.time()) + 600)
        assert str(info.value) == "capture store: ClientError: AccessDenied"
        assert len(client.puts) == len(script) and len(client.deletes) == 1
        assert not m._CONDITIONAL_OK
    assert sig.calls == []


def test_probe_accepts_a_bare_412_status_without_the_code():
    bare = ClientError({"Error": {"Code": "Weird"}, "ResponseMetadata": {"HTTPStatusCode": 412}}, "PutObject")
    _store(_ProbeClient([None, bare])).ensure_conditional_writes()
    assert m._CONDITIONAL_OK


def test_sweep_claims_boundary_and_prefix():
    now = 1_000_000.0
    age = m.CLAIM_MARKER_MAX_AGE_S

    def entry(key, seconds_old):
        return {"Key": key, "LastModified": datetime.fromtimestamp(now - seconds_old, tz=timezone.utc)}

    client = _client()
    stub = Stubber(client)
    stub.add_response("list_objects_v2", {"IsTruncated": False, "Contents": [
        entry(f"claims/{A}", age + 1), entry(f"claims/{B}", age - 1), entry(f"claims/{C}", age + 5000)]},
        {"Bucket": "b-results", "Prefix": "claims/"})
    stub.add_response("delete_object", {}, {"Bucket": "b-results", "Key": f"claims/{A}"})
    stub.add_response("delete_object", {}, {"Bucket": "b-results", "Key": f"claims/{C}"})
    with stub:
        assert _store(client).sweep_claims(now_ts=now) == 2
        stub.assert_no_pending_responses()


def test_sweep_claims_list_errors_return_zero_without_raising(caplog):
    for code, expected_log in (("NoSuchBucket", False), ("InternalError", True)):
        client = _client()
        stub = Stubber(client)
        stub.add_client_error("list_objects_v2", service_error_code=code)
        caplog.clear()
        with caplog.at_level(logging.WARNING), stub:
            assert _store(client).sweep_claims() == 0
        assert ("could not list claim markers" in caplog.text) is expected_log


def test_claims_keys_do_not_disturb_the_results_views():
    client = _client()
    stub = Stubber(client)
    stub.add_response("list_objects_v2", _listing(f"results/{A}/result.json"),
                      {"Bucket": "b-results", "Prefix": "results/"})
    stub.add_response("list_objects_v2", _listing(f"results/{A}/result.json", f"results/{A}/screenshot.webp"),
                      {"Bucket": "b-results", "Prefix": f"results/{A}/"})
    with stub:
        store = _store(client)
        assert store.list_results() == [A]
        assert store.result_files_ok(A) is True
