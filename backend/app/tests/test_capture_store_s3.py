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

import botocore
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
    claim_headers = {"If-None-Match": "*"}

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
    m._google_token.cache_clear()
    m._gcs_signer.cache_clear()
    m._client.cache_clear()
    yield
    m._CONDITIONAL_OK.clear()
    m._google_token.cache_clear()
    m._gcs_signer.cache_clear()
    m._client.cache_clear()


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
                                    "CAPTURE_S3_PUBLIC_ENDPOINT",
             "CAPTURE_S3_AUTH"]


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
        "claim_headers": {"If-None-Match": "*"},
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
    # the advertised claim headers are what is actually signed
    assert [h.lower() for h in SigV4Signer.claim_headers] == ["if-none-match"]
    assert dict(SigV4Signer.claim_headers) == {"If-None-Match": "*"}


def test_claim_marker_max_age_matches_the_claim_url_lifetime():
    from app.services import page_capture as pc
    assert m.CLAIM_SKEW_S == 300
    assert m.CLAIM_MARKER_MAX_AGE_S == pc.QUEUE_TIMEOUT_MAX + pc.CREDENTIAL_RUN_MARGIN_S + m.CLAIM_SKEW_S


class _Client:
    """Fake data-plane client for the probe: records deletes only."""

    def __init__(self, endpoint="https://store.example"):
        self.meta = type("Meta", (), {"endpoint_url": endpoint})()
        self.deletes = []

    def delete_object(self, **kw):
        self.deletes.append(kw)
        return {}


class _ProbeSigner(_FakeSigner):
    def __init__(self, host="https://store.example", headers=None, fail=None):
        super().__init__()
        self.host, self.fail = host, fail
        self.claim_headers = headers or {"If-None-Match": "*"}

    def presign_put_if_absent(self, bucket, key, expires_in):
        self.calls.append(("PUT-IF-ABSENT", bucket, key, expires_in))
        if self.fail:
            raise self.fail
        return f"{self.host}/{bucket}/{key}?sig=SECRET-SIG"


class _Puts:
    """Scripted `_probe_put`: each outcome is an int status or an exception to raise."""

    def __init__(self, monkeypatch, *script):
        self.script, self.calls = list(script), []
        monkeypatch.setattr(m, "_probe_put", self)

    def __call__(self, url, headers):
        self.calls.append((url, dict(headers)))
        out = self.script.pop(0)
        if isinstance(out, Exception):
            raise out
        return out


def _probe_store(client=None, signer=None, probe_signer=None):
    return S3Store(client or _Client(), signer or _FakeSigner(), BUCKETS, probe_signer=probe_signer)


def test_job_fields_contains_the_claim_put_after_a_passing_probe(monkeypatch):
    sig, psig, client = _FakeSigner(), _ProbeSigner(), _Client()
    puts = _Puts(monkeypatch, 201, 412)
    out = _probe_store(client, sig, psig).job_fields(ID, int(time.time()) + 600)
    assert out["store"]["claim_put"] == f"signed:PUT-IF-ABSENT:claims/{ID}"
    assert out["store"]["claim_headers"] == {"If-None-Match": "*"}
    assert len(puts.calls) == 2  # the probe was reached
    (url, headers), (url2, headers2) = puts.calls
    assert url == url2 and headers == headers2 == {"If-None-Match": "*"}
    assert url.startswith("https://store.example/b-results/claims/.probe-")
    assert [c[0] for c in psig.calls] == ["PUT-IF-ABSENT"] and psig.calls[0][3] == m.PROBE_URL_TTL_S
    assert len(client.deletes) == 1 and client.deletes[0]["Key"].startswith("claims/.probe-")


def test_probe_uses_exactly_the_probe_signers_claim_headers(monkeypatch):
    puts = _Puts(monkeypatch, 200, 412)
    psig = _ProbeSigner(headers={"x-goog-if-generation-match": "0"})
    _probe_store(probe_signer=psig).ensure_conditional_writes()
    assert [h for _, h in puts.calls] == [{"x-goog-if-generation-match": "0"}] * 2


def test_probe_success_is_cached_per_process(monkeypatch):
    puts = _Puts(monkeypatch, 200, 412, 200, 412)
    client = _Client()
    store = _probe_store(client)
    store.job_fields(ID, int(time.time()) + 600)
    store.job_fields(ID, int(time.time()) + 600)
    _probe_store(client).job_fields(ID, int(time.time()) + 600)  # a fresh store, like get_store() builds
    assert len(puts.calls) == 2
    # another endpoint is a different key and probes again
    _probe_store(_Client(endpoint="https://other.example")).job_fields(ID, int(time.time()) + 600)
    assert len(puts.calls) == 4


def test_a_store_that_ignores_the_condition_issues_no_job(monkeypatch, caplog):
    sig, psig, client = _FakeSigner(), _ProbeSigner(), _Client()
    puts = _Puts(monkeypatch, 200, 200, 200, 200)  # the second PUT succeeds: the condition was ignored
    caplog.set_level(logging.ERROR)
    with pytest.raises(OSError) as info:
        _probe_store(client, sig, psig).job_fields(ID, int(time.time()) + 600)
    assert "conditional writes not supported" in str(info.value)
    assert sig.calls == []  # nothing presigned for the job
    assert len(puts.calls) == 2 and len(client.deletes) == 1  # reached, and the probe key removed
    assert "does not honour conditional writes" in caplog.text
    assert "SECRET-SIG" not in caplog.text and "https://store.example/" not in caplog.text
    assert not m._CONDITIONAL_OK
    with pytest.raises(OSError):  # not cached: the next request probes again
        _probe_store(client, sig, psig).job_fields(ID, int(time.time()) + 600)
    assert len(puts.calls) == 4


@pytest.mark.parametrize("script, expect_calls, message", [
    ([403], 1, "HTTP 403"),
    ([200, 500], 2, "HTTP 500"),
    ([200, 403], 2, "HTTP 403"),
    ([OSError("capture store: conditional-write probe: URLError")], 1, "URLError"),
    ([200, OSError("capture store: conditional-write probe: TimeoutError")], 2, "TimeoutError"),
])
def test_probe_failures_are_oserror_not_cached_and_still_delete(monkeypatch, caplog, script, expect_calls, message):
    sig, client = _FakeSigner(), _Client()
    puts = _Puts(monkeypatch, *script)
    with pytest.raises(OSError) as info:
        _probe_store(client, sig, _ProbeSigner()).job_fields(ID, int(time.time()) + 600)
    assert message in str(info.value)
    assert len(puts.calls) == expect_calls  # reached; the second call is not made after a first failure
    assert len(client.deletes) == 1
    assert not m._CONDITIONAL_OK and sig.calls == []
    assert "SECRET-SIG" not in caplog.text and "SECRET-SIG" not in str(info.value)


def test_probe_signer_failure_is_oserror_not_cached_and_makes_no_request(monkeypatch):
    client = _Client()
    puts = _Puts(monkeypatch)
    psig = _ProbeSigner(fail=OSError("capture store: signer: TransportError"))
    with pytest.raises(OSError):
        _probe_store(client, _FakeSigner(), psig).job_fields(ID, int(time.time()) + 600)
    assert [c[0] for c in psig.calls] == ["PUT-IF-ABSENT"]  # reached
    assert puts.calls == [] and not m._CONDITIONAL_OK
    assert len(client.deletes) == 1  # the delete is harmless and runs


def test_probe_put_wire_behaviour(monkeypatch):
    """The real `_probe_put` against a local socket-free opener stub: statuses, redirects, errors."""
    import urllib.error

    seen = []

    class _Resp:
        status = 201

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            return b""

    class _Opener:
        def __init__(self, outcome):
            self.outcome = outcome

        def open(self, req, timeout=None):
            seen.append((req.get_method(), req.full_url, dict(req.header_items()), req.data, timeout))
            if isinstance(self.outcome, Exception):
                raise self.outcome
            return self.outcome

    def run(outcome):
        monkeypatch.setattr(m.urllib.request, "build_opener", lambda *h: _Opener(outcome))
        return m._probe_put("https://store.example/k?sig=SECRET-SIG", {"If-None-Match": "*"})

    assert run(_Resp()) == 201
    method, url, headers, data, timeout = seen[0]
    assert method == "PUT" and data == b"" and timeout == m.PROBE_TIMEOUT_S
    assert headers["If-none-match"] == "*" and headers["Content-length"] == "0"
    err = urllib.error.HTTPError("https://store.example/k", 412, "x", {}, None)
    assert run(err) == 412
    for exc in (urllib.error.URLError("https://store.example/k?sig=SECRET-SIG"), TimeoutError("SECRET-SIG"), ValueError("SECRET-SIG")):
        with pytest.raises(OSError) as info:
            run(exc)
        assert "SECRET-SIG" not in str(info.value) and "conditional-write probe" in str(info.value)


def test_probe_put_ignores_environment_proxies(monkeypatch):
    """The probe PUT carries a signed URL: it must never go through an HTTP(S)_PROXY from the env."""
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.test:3128")
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.example.test:3128")
    real = m.urllib.request.build_opener
    handlers = []

    def spy(*h):
        handlers.extend(h)
        return real(*h)

    monkeypatch.setattr(m.urllib.request, "build_opener", spy)
    with pytest.raises(OSError):
        m._probe_put("https://store.invalid/k", {"If-None-Match": "*"})  # .invalid never resolves
    assert handlers  # reached
    proxies = [h for h in handlers if isinstance(h, m.urllib.request.ProxyHandler)]
    assert len(proxies) == 1 and proxies[0].proxies == {}
    assert any(isinstance(h, m._NoRedirect) for h in handlers)


def test_no_redirect_handler_turns_a_redirect_into_an_error():
    assert m._NoRedirect().redirect_request(None, None, 307, "", {}, "https://elsewhere.example/") is None


def test_probe_signer_uses_the_backend_endpoint_while_job_urls_use_the_public_one(env, monkeypatch):
    env.setenv("CAPTURE_S3_PUBLIC_ENDPOINT", "https://store.example.test")
    store = m.s3_store_from_env()
    puts = _Puts(monkeypatch, 200, 412)
    monkeypatch.setattr(store, "_delete_quiet", lambda *a: None)
    urls = store.job_fields(ID, int(time.time()) + 600)["store"]
    assert len(puts.calls) == 2  # reached
    assert urlsplit(puts.calls[0][0]).netloc == "store.example"
    for k in ("result_put", "screenshot_put", "claim_put"):
        assert urlsplit(urls[k]).netloc == "store.example.test"
    assert urls["claim_headers"] == {"If-None-Match": "*"}


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


# ── CAPTURE_S3_AUTH=gcs-wi (planning#322) ────────────────────────────────────

DATA_TOKEN, SIGN_TOKEN = "data-token-aaaa", "sign-token-bbbb"
SA_EMAIL = "capture@fabrikam-project.iam.gserviceaccount.com"


@pytest.fixture
def gcs_env(env):
    env.delenv("CAPTURE_S3_ACCESS_KEY")
    env.delenv("CAPTURE_S3_SECRET_KEY")
    env.setenv("CAPTURE_S3_AUTH", "gcs-wi")
    env.setenv("CAPTURE_S3_ENDPOINT", m.GCS_ENDPOINT)
    return env


class _FakeCreds:
    def __init__(self, scope, email=SA_EMAIL, valid=False):
        self.scope, self.valid, self.refreshes = scope, valid, 0
        self.token = None
        if email is not None:
            self.service_account_email = email

    def refresh(self, request):
        self.refreshes += 1
        self.valid = True
        self.token = DATA_TOKEN if self.scope == m.GCS_DATA_SCOPE else SIGN_TOKEN


@pytest.fixture
def creds(monkeypatch):
    """Replace google.auth.default; one fake credentials object per scope asked for."""
    import google.auth
    made = {}
    state = {"email": SA_EMAIL}

    def default(scopes=None, **kw):
        (scope,) = scopes
        made[scope] = _FakeCreds(scope, state["email"])
        return made[scope], "fabrikam-project"

    monkeypatch.setattr(google.auth, "default", default)
    made["state"] = state
    return made


def test_config_auth_defaults_to_sigv4_and_rejects_unknown(env):
    assert m.s3_config_from_env().auth == "sigv4"
    env.setenv("CAPTURE_S3_AUTH", " SigV4 ")
    assert m.s3_config_from_env().auth == "sigv4"
    for bad in ("gcs", "gcs_wi", "iam", "none"):
        env.setenv("CAPTURE_S3_AUTH", bad)
        with pytest.raises(StoreConfigError) as e:
            m.s3_config_from_env()
        assert "CAPTURE_S3_AUTH" in str(e.value)


def test_config_gcs_wi_happy_path(gcs_env):
    cfg = m.s3_config_from_env()
    assert cfg.auth == "gcs-wi" and cfg.endpoint == m.GCS_ENDPOINT
    assert cfg.access_key is None and cfg.secret_key is None and cfg.path_style is True
    gcs_env.setenv("CAPTURE_S3_AUTH", " GCS-WI ")
    assert m.s3_config_from_env().auth == "gcs-wi"


@pytest.mark.parametrize("var, value, named", [
    ("CAPTURE_S3_ENDPOINT", None, "CAPTURE_S3_ENDPOINT"),
    ("CAPTURE_S3_ENDPOINT", "http://storage.googleapis.com", "CAPTURE_S3_ENDPOINT"),
    ("CAPTURE_S3_ENDPOINT", "https://storage.googleapis.com/", "CAPTURE_S3_ENDPOINT"),
    ("CAPTURE_S3_ENDPOINT", "https://storage.googleapis.com:8443", "CAPTURE_S3_ENDPOINT"),
    ("CAPTURE_S3_ENDPOINT", "https://storage.googleapis.com.example.test", "CAPTURE_S3_ENDPOINT"),
    ("CAPTURE_S3_ENDPOINT", "https://u@storage.googleapis.com", "CAPTURE_S3_ENDPOINT"),
    ("CAPTURE_S3_ACCESS_KEY", "AKIATESTDISTINCT", "CAPTURE_S3_ACCESS_KEY"),
    ("CAPTURE_S3_SECRET_KEY", "SECRETTESTDISTINCT", "CAPTURE_S3_SECRET_KEY"),
    ("CAPTURE_S3_PUBLIC_ENDPOINT", "https://store.example.test", "CAPTURE_S3_PUBLIC_ENDPOINT"),
    ("CAPTURE_S3_PATH_STYLE", "false", "CAPTURE_S3_PATH_STYLE"),
    ("CAPTURE_S3_INSECURE_HTTP", "1", "CAPTURE_S3_INSECURE_HTTP"),
])
def test_config_gcs_wi_rejects(gcs_env, var, value, named):
    assert m.s3_config_from_env().auth == "gcs-wi"  # reached: the base config is valid
    if value is None:
        gcs_env.delenv(var)
    else:
        gcs_env.setenv(var, value)
    with pytest.raises(StoreConfigError) as e:
        m.s3_config_from_env()
    assert named in str(e.value)
    assert "AKIATESTDISTINCT" not in str(e.value) and "SECRETTESTDISTINCT" not in str(e.value)


def test_config_gcs_wi_rejects_both_static_keys(gcs_env):
    gcs_env.setenv("CAPTURE_S3_ACCESS_KEY", "k")
    gcs_env.setenv("CAPTURE_S3_SECRET_KEY", "s")
    with pytest.raises(StoreConfigError) as e:
        m.s3_config_from_env()
    assert "static keys are refused" in str(e.value)


def _short_circuit(client, status=200, seen=None):
    """Register AFTER the client's own hook so the pin/auth hook ran first; answer without a network."""
    from botocore.awsrequest import AWSResponse

    class _Raw:
        def stream(self, *a, **k):
            return iter(())

        def read(self, *a, **k):
            return b""

    def spy(request, **kw):
        seen.append((request.url, dict(request.headers)))
        return AWSResponse(request.url, status, {}, _Raw())

    client.meta.events.register("before-send.s3", spy)


def test_gcs_data_plane_is_unsigned_and_carries_only_the_data_bearer(gcs_env, creds):
    client = m._client(m.s3_config_from_env())
    seen = []
    _short_circuit(client, seen=seen)
    client.head_bucket(Bucket="b-jobs")
    assert len(seen) == 1  # reached the transport
    url, headers = seen[0]
    assert urlsplit(url).netloc == "storage.googleapis.com"
    assert headers["Authorization"] == "Bearer " + DATA_TOKEN
    assert "AWS4-HMAC" not in " ".join(str(v) for v in headers.values())
    assert not any(k.lower().startswith("x-amz-security") for k in headers)
    assert list(k for k in creds if k != "state") == [m.GCS_DATA_SCOPE]  # the signing scope was never asked
    assert SIGN_TOKEN not in str(headers)
    assert client.meta.endpoint_url == m.GCS_ENDPOINT


def test_gcs_token_is_refreshed_only_when_invalid_and_shared_across_clients(gcs_env, creds):
    cfg = m.s3_config_from_env()
    client = m._client(cfg)
    seen = []
    _short_circuit(client, seen=seen)
    client.head_bucket(Bucket="b-jobs")
    client.head_bucket(Bucket="b-results")
    assert creds[m.GCS_DATA_SCOPE].refreshes == 1 and len(seen) == 2
    creds[m.GCS_DATA_SCOPE].valid = False  # expired
    client.head_bucket(Bucket="b-jobs")
    assert creds[m.GCS_DATA_SCOPE].refreshes == 2
    m._client.cache_clear()  # a fresh client (get_store builds a fresh store per call) reuses the holder
    other = m._client(cfg)
    _short_circuit(other, seen=seen)
    other.head_bucket(Bucket="b-jobs")
    assert creds[m.GCS_DATA_SCOPE].refreshes == 2 and len(seen) == 4


def test_gcs_pin_handler_refuses_other_hosts_schemes_ports_without_a_header(creds):
    for url in ("https://storage.googleapis.com.example.test/b/k", "http://storage.googleapis.com/b/k",
                "https://storage.googleapis.com:444/b/k", "https://u@storage.googleapis.com/b/k",
                "https://example.test/b/k", "https://storage.googleapis.com:notaport/b/k"):
        req = type("Req", (), {"url": url, "headers": {}})()
        with pytest.raises(m._EndpointRefused):
            m._pin_and_authorize(req)
        assert "Authorization" not in req.headers, url
    assert creds == {"state": creds["state"]}  # no token was even requested
    ok = type("Req", (), {"url": "https://storage.googleapis.com:443/b/k", "headers": {}})()
    m._pin_and_authorize(ok)  # reached: the pinned host passes
    assert ok.headers["Authorization"] == "Bearer " + DATA_TOKEN


def test_gcs_redirect_to_another_host_is_refused_through_the_client(gcs_env, creds):
    client = m._client(m.s3_config_from_env())

    def redirect(request, **kw):  # runs BEFORE the pin hook, like botocore re-sending a redirect
        request.url = "https://storage.googleapis.com.example.test/b-jobs/k"

    client.meta.events.register_first("before-send.s3", redirect)
    seen = []
    _short_circuit(client, seen=seen)
    with pytest.raises(OSError) as info:
        _store(client).put_job(ID, b"{}")
    assert "_EndpointRefused" in str(info.value)
    assert seen == []  # the request never reached the transport
    assert m.GCS_DATA_SCOPE not in creds  # and no token was minted for it


def test_gcs_token_failure_surfaces_as_oserror_without_the_original_text(gcs_env, monkeypatch):
    import google.auth
    from google.auth.exceptions import TransportError

    def boom(scopes=None, **kw):
        raise TransportError("https://metadata.example.test/secret-url")

    monkeypatch.setattr(google.auth, "default", boom)
    client = m._client(m.s3_config_from_env())
    seen = []
    _short_circuit(client, seen=seen)
    with pytest.raises(OSError) as info:
        _store(client).put_job(ID, b"{}")
    assert "_TokenUnavailable" in str(info.value) and "secret-url" not in str(info.value)
    assert seen == []


@pytest.fixture
def signed(monkeypatch):
    """Record what the SDK hands to signBlob; return a fixed base64 signature."""
    from google.cloud.storage import _signing
    calls = []

    def fake(message, access_token, service_account_email, universe_domain="googleapis.com"):
        calls.append((access_token, service_account_email))
        return "c2lnbmF0dXJl"

    monkeypatch.setattr(_signing, "_sign_message", fake)
    return calls


def _q(url):
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}


def test_gcs_signer_presign_shapes_and_uses_the_signing_token_as_itself(creds, signed):
    signer = m.GcsSigner()
    for method in ("PUT", "GET"):
        url = signer.presign(method, "example-bucket", "results/x/result.json", 600)
        parts = urlsplit(url)
        assert (parts.scheme, parts.netloc, parts.path) == ("https", "storage.googleapis.com",
                                                            "/example-bucket/results/x/result.json")
        q = _q(url)
        assert q["X-Goog-Algorithm"] == "GOOG4-RSA-SHA256" and q["X-Goog-Expires"] == "600"
        assert q["X-Goog-SignedHeaders"] == "host"
        assert q["X-Goog-Credential"].startswith(SA_EMAIL + "/")
    url = signer.presign_put_if_absent("example-bucket", "claims/x", 300)
    assert urlsplit(url).path == "/example-bucket/claims/x"
    q = _q(url)
    assert q["X-Goog-Expires"] == "300"
    assert "x-goog-if-generation-match" in q["X-Goog-SignedHeaders"].split(";")
    assert signed and set(signed) == {(SIGN_TOKEN, SA_EMAIL)}  # the signing token, as the SA itself
    assert len(signed) == 3
    assert DATA_TOKEN not in str(signed) and m.GCS_DATA_SCOPE not in creds
    assert list(k for k in creds if k != "state") == [m.GCS_SIGN_SCOPE]
    assert dict(signer.claim_headers) == {"x-goog-if-generation-match": "0"}


@pytest.mark.parametrize("email", [None, "default", "no-at-sign", ""])
def test_gcs_signer_refuses_a_missing_or_placeholder_identity(creds, signed, email):
    creds["state"]["email"] = email
    with pytest.raises(OSError) as info:
        m.GcsSigner().presign("PUT", "example-bucket", "k", 60)
    assert str(info.value).startswith("capture store: signer: ")
    assert m.GCS_SIGN_SCOPE in creds  # reached: credentials were obtained and refreshed
    assert signed == []  # nothing was signed


def test_gcs_signer_errors_never_carry_the_original_message(creds, monkeypatch):
    from google.auth.exceptions import TransportError
    from google.cloud.storage import _signing

    def boom(*a, **k):
        raise TransportError("https://iamcredentials.example.test/secret-url token=abc")

    monkeypatch.setattr(_signing, "_sign_message", boom)
    for fn in (lambda: m.GcsSigner().presign("PUT", "example-bucket", "k", 60),
               lambda: m.GcsSigner().presign_put_if_absent("example-bucket", "k", 60)):
        with pytest.raises(OSError) as info:
            fn()
        assert str(info.value) == "capture store: signer: TransportError"
        assert "secret-url" not in str(info.value) and info.value.__cause__ is None


def test_job_fields_under_gcs_has_the_generation_claim_and_fails_closed(creds, signed, monkeypatch):
    client = _Client(endpoint=m.GCS_ENDPOINT)
    store = S3Store(client, m.GcsSigner(), BUCKETS)
    m._CONDITIONAL_OK.add((m.GCS_ENDPOINT, BUCKETS.results))
    out = store.job_fields(ID, int(time.time()) + 600)["store"]
    assert out["claim_headers"] == {"x-goog-if-generation-match": "0"}
    assert "x-goog-if-generation-match" in _q(out["claim_put"])["X-Goog-SignedHeaders"]
    assert urlsplit(out["result_put"]).netloc == "storage.googleapis.com"
    # fail closed when the probe fails: no job, no job URLs signed
    m._CONDITIONAL_OK.clear()
    signed.clear()
    puts = _Puts(monkeypatch, 500)
    with pytest.raises(OSError):
        store.job_fields(ID, int(time.time()) + 600)
    assert len(puts.calls) == 1 and puts.calls[0][1] == {"x-goog-if-generation-match": "0"}  # reached
    assert len(signed) == 1  # only the probe URL was signed, none of the three job URLs
    assert not m._CONDITIONAL_OK


def test_s3_store_from_env_under_gcs_wi(gcs_env, creds, signed):
    store = m.s3_store_from_env()
    assert isinstance(store._signer, m.GcsSigner) and store._probe_signer is store._signer
    assert store._c.meta.config.signature_version is botocore.UNSIGNED
    assert store._c.meta.endpoint_url == m.GCS_ENDPOINT
    assert m.s3_store_from_env()._signer is store._signer  # cached across get_store() calls
