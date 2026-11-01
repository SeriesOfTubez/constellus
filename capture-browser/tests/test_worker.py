"""The filesystem worker loop (planning#318 S1c keeps it byte-for-byte)."""

import os

import pytest

from capture import worker

ID = "0190a1b2-c3d4-7e5f-8a6b-1234567890ab"


class _Sentinel(Exception):
    pass


def _spool(root):
    for d in ("jobs", "claimed", "results"):
        (root / d).mkdir()


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("CAPTURE_PROXY_URL", "http://proxy.example.test:3128")
    monkeypatch.delenv("CAPTURE_STORE", raising=False)
    monkeypatch.setattr(worker, "SPOOL_DIR", str(tmp_path))
    monkeypatch.setattr(worker, "_make_undumpable", lambda: None)  # never the real prctl in the test process
    return tmp_path


def test_main_requires_the_proxy_url(env, monkeypatch):
    monkeypatch.delenv("CAPTURE_PROXY_URL")
    with pytest.raises(SystemExit):
        worker.main()


def test_unknown_store_mode_fails_before_the_directory_check(env, monkeypatch):
    monkeypatch.setenv("CAPTURE_STORE", "minio")
    monkeypatch.setattr(worker, "SPOOL_DIR", str(env / "missing"))
    with pytest.raises(SystemExit) as exc:
        worker.main()
    assert "CAPTURE_STORE" in str(exc.value)  # not the "spool directories missing" message


def test_one_job_is_claimed_processed_and_main_returns_zero(env, monkeypatch):
    _spool(env)
    (env / "jobs" / f"{ID}.json").write_bytes(b"{}")
    calls = []

    def fake_process(cid, claimed_path, results_dir):
        calls.append((cid, claimed_path, results_dir))
        assert os.path.exists(claimed_path)  # still claimed while processing
        (env / "results" / cid).mkdir()

    monkeypatch.setattr(worker, "process", fake_process)
    assert worker.main() == 0
    assert calls == [(ID, str(env / "claimed" / f"{ID}.json"), str(env / "results"))]
    assert os.listdir(env / "claimed") == []
    assert os.listdir(env / "jobs") == []


def test_idle_sleeps_for_the_poll_interval(env, monkeypatch):
    _spool(env)
    slept = []

    def fake_sleep(s):
        slept.append(s)
        raise _Sentinel

    monkeypatch.setattr(worker.time, "sleep", fake_sleep)
    with pytest.raises(_Sentinel):
        worker.main()
    assert slept == [worker.POLL_INTERVAL_S]


def test_drop_store_env_removes_only_the_store_variables(monkeypatch):
    for k in ("CAPTURE_S3_SECRET_KEY", "CAPTURE_S3_ACCESS_KEY", "CAPTURE_S3_ENDPOINT"):
        monkeypatch.setenv(k, "x")
    monkeypatch.setenv("CAPTURE_PROXY_URL", "http://proxy.example.test:3128")
    worker._drop_store_env()
    assert not [k for k in os.environ if k.startswith("CAPTURE_S3_")]
    assert os.environ["CAPTURE_PROXY_URL"] == "http://proxy.example.test:3128"


def test_main_s3_drops_the_store_env_after_config_and_before_claiming(env, monkeypatch):
    monkeypatch.setenv("CAPTURE_STORE", "s3")
    monkeypatch.setenv("CAPTURE_S3_SECRET_KEY", "secret")
    monkeypatch.setattr(worker, "_make_undumpable", lambda: None)
    cfg_saw = []

    class _Cfg:
        bucket, netloc, allow_http = "b", "n", False

    def fake_config():
        cfg_saw.append(os.environ.get("CAPTURE_S3_SECRET_KEY"))
        return _Cfg()

    seen = []

    def fake_claim(jobs, **kw):
        seen.append(os.environ.get("CAPTURE_S3_SECRET_KEY"))
        raise _Sentinel

    monkeypatch.setattr(worker.store_s3, "config_from_env", fake_config)
    monkeypatch.setattr(worker.store_s3, "make_client", lambda cfg: object())
    monkeypatch.setattr(worker.store_s3, "S3Jobs", lambda client, bucket: object())
    monkeypatch.setattr(worker, "claim_next_s3", fake_claim)
    with pytest.raises(_Sentinel):
        worker.main()
    assert cfg_saw == ["secret"]  # config was read while the secret was still there
    assert seen == [None]  # claim was reached, and the secret was already gone


def test_main_makes_the_process_undumpable_before_reading_config(env, monkeypatch):
    monkeypatch.setenv("CAPTURE_STORE", "s3")
    events = []
    monkeypatch.setattr(worker, "_make_undumpable", lambda: events.append("undumpable"))

    def fake_config():
        events.append("config")
        raise _Sentinel

    monkeypatch.setattr(worker.store_s3, "config_from_env", fake_config)
    with pytest.raises(_Sentinel):
        worker.main()
    assert events == ["undumpable", "config"]


def test_undumpable_fails_closed_when_prctl_fails(monkeypatch):
    class _Libc:
        def prctl(self, *a):
            return -1

    monkeypatch.setattr(worker.sys, "platform", "linux")
    monkeypatch.setattr(worker.ctypes, "CDLL", lambda *a, **k: _Libc())
    with pytest.raises(SystemExit) as exc:
        worker._make_undumpable()
    assert "PR_SET_DUMPABLE" in str(exc.value)


def test_undumpable_sets_pr_set_dumpable_zero_on_linux(monkeypatch):
    calls = []

    class _Libc:
        def prctl(self, *a):
            calls.append(a)
            return 0

    monkeypatch.setattr(worker.sys, "platform", "linux")
    monkeypatch.setattr(worker.ctypes, "CDLL", lambda *a, **k: _Libc())
    worker._make_undumpable()
    assert calls[0][:2] == (4, 0)


def test_undumpable_is_skipped_off_linux(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("prctl must not be reached off Linux")

    monkeypatch.setattr(worker.sys, "platform", "darwin")
    monkeypatch.setattr(worker.ctypes, "CDLL", boom)
    worker._make_undumpable()
