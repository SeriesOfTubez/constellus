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
