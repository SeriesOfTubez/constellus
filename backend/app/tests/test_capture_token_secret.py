"""The token Secret publisher and its scheduler registration (planning#322 slice 2b-2).
No database, no real Google or cluster call: a fake API server over httpx.MockTransport."""

import base64
import json
import logging
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from apscheduler.schedulers.background import BackgroundScheduler

from app.services import capture_token_minter as minter
from app.services import capture_token_secret as ts
from app.services import job_runs
from app.services import scheduler
from app.services.capture_store import StoreConfigError
from app.services.capture_store_s3 import S3Buckets, S3Config
from app.services.k8s_incluster import K8sApiError

NOW = datetime(2026, 11, 2, 9, 0, 0, tzinfo=timezone.utc)
URL = "https://10.96.0.1/api/v1/namespaces/constellus/secrets/capture-store-tokens"
FAKE_TOKEN = "ya29.fake-downscoped-token"


def cfg(auth="gcs-wi", jobs="jobs-bucket", proxylog="proxylog-bucket"):
    return S3Config(
        endpoint="https://storage.googleapis.com", public_endpoint=None, region="auto", access_key=None,
        secret_key=None, path_style=True, auth=auth,
        buckets=S3Buckets(jobs=jobs, results="results-bucket", proxylog=proxylog, images="images-bucket"))


@pytest.fixture
def sa(tmp_path, monkeypatch):
    d = tmp_path / "sa"
    d.mkdir()
    (d / "token").write_text("sa-bearer-xyz\n")
    (d / "namespace").write_text("constellus\n")
    (d / "ca.crt").write_text("-----BEGIN CERTIFICATE-----\nxx\n-----END CERTIFICATE-----\n")
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
    monkeypatch.setenv("KUBERNETES_SERVICE_PORT", "443")
    monkeypatch.delenv("CAPTURE_TOKEN_SECRET", raising=False)
    return str(d)


class FakeApi:
    def __init__(self, data=None, get_status=200, patch_status=200, rv="42"):
        self.data, self.get_status, self.patch_status, self.rv = data, get_status, patch_status, rv
        self.requests = []

    def handler(self, request):
        self.requests.append(request)
        if request.method == "GET":
            if self.get_status != 200:
                return httpx.Response(self.get_status, json={"kind": "Status"})
            body = {"kind": "Secret", "metadata": {"name": "x", "resourceVersion": self.rv}}
            if self.data is not None:
                body["data"] = self.data
            return httpx.Response(200, json=body)
        return httpx.Response(self.patch_status, json={})

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self.handler))

    @property
    def patches(self):
        return [r for r in self.requests if r.method == "PATCH"]


def published(consumer, *, expires_in, bucket_cfg=None, token="old-token"):
    b = minter.boundaries(bucket_cfg or cfg())[consumer]
    doc = {"token": token, "expires_at": (NOW + timedelta(seconds=expires_in)).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "boundary": minter.fingerprint(b)}
    return base64.b64encode(json.dumps(doc).encode()).decode()


class Calls:
    """Fake make_source / mint recording what was reached."""

    def __init__(self, ttl=3600, fail=(), source_fails=False, token=FAKE_TOKEN):
        self.sources, self.minted = 0, []
        self.ttl, self.fail, self.source_fails, self.token = ttl, set(fail), source_fails, token

    def make_source(self):
        self.sources += 1
        if self.source_fails:
            raise minter.MintError("source: RuntimeError")
        return "SRC"

    def mint(self, source, b):
        assert source == "SRC"
        self.minted.append(b.consumer)
        if b.consumer in self.fail:
            raise minter.MintError(f"mint {b.consumer}: RuntimeError")
        ttl = self.ttl[b.consumer] if isinstance(self.ttl, dict) else self.ttl
        return minter.Minted(token=self.token, expires_at=NOW + timedelta(seconds=ttl))


def run(api, calls, sa, **kw):
    kw.setdefault("refresh_below_s", 1800)
    return ts.publish_tokens(cfg(), now=NOW, client=api.client(), sa_dir=sa,
                             make_source=calls.make_source, mint=calls.mint, **kw)


def decode(patch, key):
    body = json.loads(patch.content)["data"][key]
    return json.loads(base64.b64decode(body))


def test_empty_secret_publishes_both_with_one_patch(sa):
    api, calls = FakeApi(), Calls()
    out = run(api, calls, sa)
    assert out == {"worker": "published", "proxy": "published"}
    assert [r.method for r in api.requests] == ["GET", "PATCH"]
    assert str(api.requests[0].url) == URL and api.requests[0].headers["Authorization"] == "Bearer sa-bearer-xyz"
    p = api.patches[0]
    assert p.headers["Content-Type"] == "application/merge-patch+json"
    body = json.loads(p.content)
    assert body["metadata"] == {"resourceVersion": "42"}
    assert set(body["data"]) == {"worker.json", "proxy.json"}
    assert calls.sources == 1 and sorted(calls.minted) == ["proxy", "worker"]
    b = minter.boundaries(cfg())
    for consumer, key in (("worker", "worker.json"), ("proxy", "proxy.json")):
        doc = decode(p, key)
        assert doc == {"token": FAKE_TOKEN, "expires_at": "2026-11-02T10:00:00Z", "boundary": minter.fingerprint(b[consumer])}


def test_both_fresh_builds_no_source_and_does_not_patch(sa):
    api = FakeApi(data={"worker.json": published("worker", expires_in=3000), "proxy.json": published("proxy", expires_in=3000)})
    calls = Calls()
    out = run(api, calls, sa)
    assert out == {"worker": "fresh", "proxy": "fresh"}
    assert [r.method for r in api.requests] == ["GET"]  # the Secret WAS read
    assert calls.sources == 0 and calls.minted == []


def test_only_the_consumer_under_30_minutes_is_remade(sa):
    api = FakeApi(data={"worker.json": published("worker", expires_in=3000), "proxy.json": published("proxy", expires_in=1700)})
    calls = Calls()
    out = run(api, calls, sa)
    assert out == {"worker": "fresh", "proxy": "published"}
    assert calls.minted == ["proxy"] and calls.sources == 1
    assert list(json.loads(api.patches[0].content)["data"]) == ["proxy.json"]


def test_exactly_30_minutes_left_is_still_fresh(sa):
    api = FakeApi(data={"worker.json": published("worker", expires_in=1800), "proxy.json": published("proxy", expires_in=1800)})
    assert run(api, Calls(), sa) == {"worker": "fresh", "proxy": "fresh"}


def test_boundary_mismatch_triggers_a_remint(sa):
    other = cfg(jobs="other-jobs-bucket")
    api = FakeApi(data={"worker.json": published("worker", expires_in=3500, bucket_cfg=other),
                        "proxy.json": published("proxy", expires_in=3500)})
    calls = Calls()
    out = run(api, calls, sa)
    assert out == {"worker": "published", "proxy": "fresh"}
    assert calls.minted == ["worker"]
    assert list(json.loads(api.patches[0].content)["data"]) == ["worker.json"]


def test_minted_under_floor_is_not_published(sa, caplog):
    caplog.set_level(logging.INFO)
    api = FakeApi(data={"proxy.json": published("proxy", expires_in=3000)})
    calls = Calls(ttl={"worker": 500, "proxy": 3600})
    out = run(api, calls, sa)
    assert out == {"worker": "refused_floor", "proxy": "fresh"}
    assert calls.minted == ["worker"]  # the mint WAS reached
    assert api.patches == []
    errs = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errs) == 1 and "worker" in errs[0].getMessage() and "500" in errs[0].getMessage()


def test_one_refused_floor_does_not_block_the_other(sa):
    api = FakeApi()
    calls = Calls(ttl={"worker": 599, "proxy": 3600})
    out = run(api, calls, sa)
    assert out == {"worker": "refused_floor", "proxy": "published"}
    assert list(json.loads(api.patches[0].content)["data"]) == ["proxy.json"]


def test_exactly_floor_is_published(sa):
    api, calls = FakeApi(), Calls(ttl=600)
    assert run(api, calls, sa) == {"worker": "published", "proxy": "published"}


def test_one_failing_mint_does_not_block_the_other(sa, caplog):
    api, calls = FakeApi(), Calls(fail={"worker"})
    out = run(api, calls, sa)
    assert out == {"worker": "mint_failed", "proxy": "published"}
    assert sorted(calls.minted) == ["proxy", "worker"]
    assert list(json.loads(api.patches[0].content)["data"]) == ["proxy.json"]
    assert "mint failed for worker: MintError" in caplog.text


def test_source_failure_means_no_patch_and_both_mint_failed(sa, caplog):
    api, calls = FakeApi(), Calls(source_fails=True)
    out = run(api, calls, sa)
    assert out == {"worker": "mint_failed", "proxy": "mint_failed"}
    assert calls.sources == 1 and calls.minted == []
    assert [r.method for r in api.requests] == ["GET"]
    assert any(r.levelno == logging.ERROR and "MintError" in r.getMessage() for r in caplog.records)


def test_missing_secret_raises_logs_and_does_not_patch(sa, caplog):
    api, calls = FakeApi(get_status=404), Calls()
    with pytest.raises(ts.PublishTargetMissing):
        run(api, calls, sa)
    assert [r.method for r in api.requests] == ["GET"]
    assert calls.sources == 0
    assert any(r.levelno == logging.ERROR and "pre-create" in r.getMessage() for r in caplog.records)


def test_publish_target_missing_is_a_k8s_api_error():
    assert issubclass(ts.PublishTargetMissing, K8sApiError)


def test_conflict_on_patch_does_not_raise(sa, caplog):
    caplog.set_level(logging.INFO)
    api, calls = FakeApi(patch_status=409), Calls()
    out = run(api, calls, sa)
    assert [r.method for r in api.requests] == ["GET", "PATCH"]  # the PATCH was reached
    assert out == {"worker": "conflict", "proxy": "conflict"}
    assert not any(r.levelno >= logging.ERROR for r in caplog.records)
    assert "changed under us" in caplog.text


def test_get_500_raises(sa):
    api, calls = FakeApi(get_status=500), Calls()
    with pytest.raises(K8sApiError, match="HTTP 500"):
        run(api, calls, sa)
    assert [r.method for r in api.requests] == ["GET"]


def test_patch_500_raises(sa):
    api, calls = FakeApi(patch_status=500), Calls()
    with pytest.raises(K8sApiError, match="HTTP 500"):
        run(api, calls, sa)
    assert [r.method for r in api.requests] == ["GET", "PATCH"]


@pytest.mark.parametrize("bad", [
    "!!!not-base64!!!",
    base64.b64encode(b"not json").decode(),
    base64.b64encode(json.dumps({"token": "t", "expires_at": 12345, "boundary": "x"}).encode()).decode(),
    base64.b64encode(json.dumps({"token": "t", "expires_at": "garbage", "boundary": "x"}).encode()).decode(),
    base64.b64encode(json.dumps(["a"]).encode()).decode(),
    base64.b64encode(json.dumps({"token": 1, "expires_at": "2026-11-02T12:00:00Z", "boundary": "x"}).encode()).decode(),
    12345,
])
def test_malformed_existing_value_needs_a_mint(sa, bad):
    api = FakeApi(data={"worker.json": bad, "proxy.json": published("proxy", expires_in=3000)})
    calls = Calls()
    out = run(api, calls, sa)
    assert out == {"worker": "published", "proxy": "fresh"}
    assert calls.minted == ["worker"]


def test_expiry_without_an_offset_is_malformed(sa):
    naive = json.loads(base64.b64decode(published("worker", expires_in=3000)))
    assert naive["expires_at"].endswith("Z")  # reached: otherwise valid, correct boundary
    naive["expires_at"] = naive["expires_at"][:-1]
    api = FakeApi(data={"worker.json": base64.b64encode(json.dumps(naive).encode()).decode(),
                        "proxy.json": published("proxy", expires_in=3000)})
    calls = Calls()
    assert run(api, calls, sa) == {"worker": "published", "proxy": "fresh"}
    assert calls.minted == ["worker"]


def test_secret_name_override_and_validation(sa, monkeypatch):
    monkeypatch.setenv("CAPTURE_TOKEN_SECRET", "my-tokens")
    api = FakeApi(data={"worker.json": published("worker", expires_in=3000), "proxy.json": published("proxy", expires_in=3000)})
    run(api, Calls(), sa)
    assert api.requests[0].url.path.endswith("/secrets/my-tokens")
    monkeypatch.setenv("CAPTURE_TOKEN_SECRET", "Bad_Name")
    api2 = FakeApi()
    with pytest.raises(K8sApiError):
        run(api2, Calls(), sa)
    assert api2.requests == []


def test_bad_bucket_refuses_before_any_request(sa):
    api = FakeApi()
    with pytest.raises(StoreConfigError):
        ts.publish_tokens(cfg(jobs="bad'bucket"), refresh_below_s=1800, now=NOW, client=api.client(), sa_dir=sa,
                          make_source=Calls().make_source, mint=Calls().mint)
    assert api.requests == []


# ── nothing secret in logs or exceptions ────────────────────────────────────


def _all_text(caplog, excs):
    parts = [r.getMessage() + " " + repr(r.args) + " " + (r.exc_text or "") for r in caplog.records]
    for e in excs:
        while e is not None:
            parts.append(str(e) + repr(e))
            e = e.__cause__ or e.__context__
    return "\n".join(parts)


def test_token_never_appears_in_logs_or_exceptions(sa, caplog):
    caplog.set_level(logging.DEBUG)
    b64 = base64.b64encode(FAKE_TOKEN.encode()).decode()
    excs = []
    scenarios = [
        (FakeApi(), Calls()),                                   # happy path
        (FakeApi(patch_status=409), Calls()),                   # conflict
        (FakeApi(patch_status=500), Calls()),                   # PATCH failure
        (FakeApi(), Calls(ttl=100)),                            # refused floor
        (FakeApi(), Calls(fail={"worker"})),                    # a mint failing
        (FakeApi(), Calls(source_fails=True)),                  # source failing
        (FakeApi(get_status=404), Calls()),
    ]
    reached_patch = 0
    for api, calls in scenarios:
        try:
            run(api, calls, sa)
        except Exception as e:
            excs.append(e)
        reached_patch += len(api.patches)
    assert reached_patch >= 3  # happy, conflict and PATCH-failure all got to the PATCH
    assert len(caplog.records) >= 6
    text = _all_text(caplog, excs)
    for secret in (FAKE_TOKEN, b64, "sa-bearer-xyz"):
        assert secret not in text


# ── tick logs and re-raises ────────────────────────────────────────────────────────


@pytest.mark.parametrize("exc", [K8sApiError("GET Secret x: HTTP 500"), RuntimeError("boom"), StoreConfigError("cfg")])
def test_tick_logs_and_reraises(monkeypatch, caplog, exc):
    calls = []

    def boom(c, **kw):
        calls.append(c)
        raise exc

    monkeypatch.setenv("CAPTURE_S3_AUTH", "sigv4")
    for k, v in (("CAPTURE_S3_BUCKET_JOBS", "jobs-bucket"), ("CAPTURE_S3_BUCKET_RESULTS", "results-bucket"),
                 ("CAPTURE_S3_BUCKET_PROXYLOG", "proxylog-bucket"), ("CAPTURE_S3_BUCKET_IMAGES", "images-bucket")):
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(ts, "publish_tokens", boom)
    monkeypatch.setattr(ts, "_refresh_below_s", lambda: 1800)
    with pytest.raises(type(exc)):
        ts.tick()
    assert len(calls) == 1  # publish WAS reached
    assert any(r.levelno == logging.ERROR for r in caplog.records)


def test_tick_logs_the_k8s_message_but_nothing_for_other_errors(monkeypatch, caplog):
    def boom(c, **kw):
        raise RuntimeError(f"secret {FAKE_TOKEN}")

    monkeypatch.setattr(ts, "publish_tokens", boom)
    monkeypatch.setattr(ts, "_refresh_below_s", lambda: 1800)
    monkeypatch.setattr("app.services.capture_store_s3.s3_config_from_env", lambda: cfg())
    with pytest.raises(RuntimeError):
        ts.tick()
    assert "RuntimeError" in caplog.text and FAKE_TOKEN not in caplog.text


def test_tick_passes_the_setting_through(monkeypatch):
    seen = []
    c = cfg()
    monkeypatch.setattr("app.services.capture_store_s3.s3_config_from_env", lambda: c)
    monkeypatch.setattr(ts, "_refresh_below_s", lambda: 2222)
    monkeypatch.setattr(ts, "publish_tokens", lambda config, **kw: seen.append((config, kw)) or {"worker": "fresh", "proxy": "fresh"})
    assert ts.tick() == {"worker": "fresh", "proxy": "fresh"}
    assert seen == [(c, {"refresh_below_s": 2222})]  # publish WAS reached, with the setting's value


def test_refresh_below_s_is_required_keyword_only(sa):
    with pytest.raises(TypeError):
        ts.publish_tokens(cfg(), now=NOW, client=FakeApi().client(), sa_dir=sa)


def test_the_argument_is_the_threshold_in_both_directions(sa):
    data = {"worker.json": published("worker", expires_in=1200), "proxy.json": published("proxy", expires_in=1200)}
    out = run(FakeApi(data=data), Calls(), sa, refresh_below_s=1800)
    assert out == {"worker": "published", "proxy": "published"}
    out = run(FakeApi(data=data), Calls(), sa, refresh_below_s=900)
    assert out == {"worker": "fresh", "proxy": "fresh"}


def test_remaining_equal_to_the_threshold_is_fresh(sa):
    data = {"worker.json": published("worker", expires_in=1200), "proxy.json": published("proxy", expires_in=1200)}
    assert run(FakeApi(data=data), Calls(), sa, refresh_below_s=1200) == {"worker": "fresh", "proxy": "fresh"}
    assert run(FakeApi(data=data), Calls(), sa, refresh_below_s=1201) == {"worker": "published", "proxy": "published"}


# ── scheduler registration ───────────────────────────────────────────────────


@pytest.fixture
def sched(monkeypatch):
    s = BackgroundScheduler(timezone="UTC")  # never started
    monkeypatch.setattr(scheduler, "_scheduler", s)
    for k in ("CAPTURE_S3_AUTH", "CAPTURE_STORE"):
        monkeypatch.delenv(k, raising=False)
    for k, v in (("CAPTURE_S3_BUCKET_JOBS", "jobs-bucket"), ("CAPTURE_S3_BUCKET_RESULTS", "results-bucket"),
                 ("CAPTURE_S3_BUCKET_PROXYLOG", "proxylog-bucket"), ("CAPTURE_S3_BUCKET_IMAGES", "images-bucket")):
        monkeypatch.setenv(k, v)
    return s


def _gcs_env(monkeypatch):
    monkeypatch.setenv("CAPTURE_STORE", "s3")
    monkeypatch.setenv("CAPTURE_S3_AUTH", "gcs-wi")
    monkeypatch.setenv("CAPTURE_S3_ENDPOINT", "https://storage.googleapis.com")
    monkeypatch.setenv("CAPTURE_S3_PATH_STYLE", "true")


def test_registered_for_s3_gcs_wi(sched, monkeypatch):
    _gcs_env(monkeypatch)
    scheduler._register_capture_tokens()
    job = sched.get_job("capture_tokens")
    assert job is not None and job.func is scheduler._run_capture_tokens
    assert job.trigger.interval == job_runs.CADENCE["capture_tokens"].every
    assert job.coalesce is True and job.max_instances == 1


def test_not_registered_for_sigv4(sched, monkeypatch):
    monkeypatch.setenv("CAPTURE_STORE", "s3")
    monkeypatch.setenv("CAPTURE_S3_AUTH", "sigv4")
    monkeypatch.setenv("CAPTURE_S3_ENDPOINT", "http://rustfs.example.invalid")
    monkeypatch.setenv("CAPTURE_S3_INSECURE_HTTP", "1")
    from app.services.capture_store_s3 import s3_config_from_env
    assert s3_config_from_env().auth == "sigv4"  # the gcs-wi check WAS reachable
    scheduler._register_capture_tokens()
    assert sched.get_job("capture_tokens") is None


def test_not_registered_for_filesystem(sched, monkeypatch):
    _gcs_env(monkeypatch)
    monkeypatch.setenv("CAPTURE_STORE", "filesystem")  # gcs-wi vars alone must not register
    scheduler._register_capture_tokens()
    assert sched.get_job("capture_tokens") is None


def test_invalid_store_config_is_not_registered(sched, monkeypatch, caplog):
    _gcs_env(monkeypatch)
    monkeypatch.setenv("CAPTURE_S3_ENDPOINT", "https://storage.googleapis.com/")  # gcs-wi refuses the slash
    scheduler._register_capture_tokens()
    assert sched.get_job("capture_tokens") is None
    assert any(r.levelno == logging.ERROR and "not scheduled" in r.getMessage() for r in caplog.records)
