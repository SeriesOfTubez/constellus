"""S3 per-capture log sink (planning#318 S1c). Offline via botocore Stubber;
one live test against a local S3 (skipped without CAPTURE_S3_TEST_ENDPOINT)."""

import asyncio
import json
import os
import secrets
from unittest.mock import MagicMock

import pytest
from botocore.stub import Stubber

import log_s3
import proxy as proxy_mod

A = "11111111-2222-4333-8444-555555555555"
B = "66666666-7777-4888-9999-000000000000"
BUCKET = "proxylog-test"
CT = "application/x-ndjson"


def _cfg(**kw):
    base = dict(
        endpoint="https://s3.example.test",
        region="us-east-1",
        access_key="AKIAFAKEFAKEFAKE",
        secret_key="fake-secret",
        path_style=True,
        bucket=BUCKET,
    )
    base.update(kw)
    return log_s3.S3LogConfig(**base)


def _client():
    return log_s3.make_client(_cfg())


def _line(rec):
    return json.dumps(rec, separators=(",", ":")).encode() + b"\n"


def _rec(cid, n=0):
    return {"capture_id": cid, "host": f"h{n}.example.test", "n": n}


def _expect_put(stub, cid, body):
    stub.add_response(
        "put_object",
        {},
        {"Bucket": BUCKET, "Key": f"proxylog/{cid}.jsonl", "Body": body, "ContentType": CT},
    )


def _run(coro):
    return asyncio.run(coro)


# ── constants and config ─────────────────────────────────────────────────────


def test_constants_match_the_proxy():
    assert log_s3.LOG_MAX_BYTES == proxy_mod.LOG_FILE_MAX_BYTES
    assert log_s3.BUFFER_TTL_S == proxy_mod.MAX_CREDENTIAL_TTL_S


GOOD_ENV = {"CAPTURE_S3_ENDPOINT": "https://s3.example.test", "CAPTURE_S3_BUCKET_PROXYLOG": "b"}


def test_config_defaults():
    cfg = log_s3.config_from_env(GOOD_ENV)
    assert (cfg.region, cfg.path_style, cfg.access_key, cfg.secret_key, cfg.bucket) == (
        "us-east-1",
        True,
        None,
        None,
        "b",
    )


@pytest.mark.parametrize(
    "patch, var",
    [
        ({"CAPTURE_S3_ENDPOINT": ""}, "CAPTURE_S3_ENDPOINT"),
        ({"CAPTURE_S3_ENDPOINT": "http://s3.example.test"}, "CAPTURE_S3_ENDPOINT"),
        ({"CAPTURE_S3_ENDPOINT": "https://u:p@s3.example.test"}, "CAPTURE_S3_ENDPOINT"),
        ({"CAPTURE_S3_ENDPOINT": "https://"}, "CAPTURE_S3_ENDPOINT"),
        ({"CAPTURE_S3_ACCESS_KEY": "a"}, "CAPTURE_S3_ACCESS_KEY"),
        ({"CAPTURE_S3_SECRET_KEY": "s"}, "CAPTURE_S3_ACCESS_KEY"),
        ({"CAPTURE_S3_BUCKET_PROXYLOG": ""}, "CAPTURE_S3_BUCKET_PROXYLOG"),
        ({"CAPTURE_S3_PATH_STYLE": "yes"}, "CAPTURE_S3_PATH_STYLE"),
    ],
)
def test_config_rejects_and_names_the_variable(patch, var):
    with pytest.raises(log_s3.S3ConfigError, match=var):
        log_s3.config_from_env({**GOOD_ENV, **patch})


def test_config_http_only_with_the_insecure_flag():
    env = {**GOOD_ENV, "CAPTURE_S3_ENDPOINT": "http://127.0.0.1:9000"}
    with pytest.raises(log_s3.S3ConfigError):
        log_s3.config_from_env(env)
    cfg = log_s3.config_from_env({**env, "CAPTURE_S3_INSECURE_HTTP": "1"})
    assert cfg.endpoint == "http://127.0.0.1:9000"


def test_config_keys_and_path_style_false():
    cfg = log_s3.config_from_env(
        {
            **GOOD_ENV,
            "CAPTURE_S3_ACCESS_KEY": "a",
            "CAPTURE_S3_SECRET_KEY": "s",
            "CAPTURE_S3_PATH_STYLE": "false",
            "CAPTURE_S3_REGION": "eu-west-1",
        }
    )
    assert (cfg.access_key, cfg.secret_key, cfg.path_style, cfg.region) == (
        "a",
        "s",
        False,
        "eu-west-1",
    )


# ── sink ─────────────────────────────────────────────────────────────────────


def test_debounce_coalesces_into_one_put_with_both_lines():
    client = _client()
    r1, r2 = _rec(A, 1), _rec(A, 2)

    async def go(stub):
        sink = log_s3.S3LogSink(client, BUCKET, debounce_s=0.05)
        sink.add(r1)
        sink.add(r2)
        assert sink.pending() == 1
        await asyncio.sleep(0.2)
        assert sink.pending() == 0

    with Stubber(client) as stub:
        _expect_put(stub, A, _line(r1) + _line(r2))
        _run(go(stub))
        stub.assert_no_pending_responses()


def test_debounce_makes_exactly_one_put_for_records_inside_the_window():
    """Counted with a mock: a Stubber's 'unexpected call' error is swallowed by the sink
    (a failed PUT never raises), so it cannot prove there was no second PUT."""
    client = MagicMock()
    r1, r2 = _rec(A, 1), _rec(A, 2)

    async def go():
        sink = log_s3.S3LogSink(client, BUCKET, debounce_s=0.1)
        sink.add(r1)
        await asyncio.sleep(0.02)  # the loop runs; a sink without a debounce would PUT here
        assert client.put_object.call_count == 0  # nothing before the window closes
        sink.add(r2)
        await asyncio.sleep(0.3)
        assert sink.pending() == 0

    _run(go())
    assert client.put_object.call_count == 1
    assert client.put_object.call_args.kwargs["Body"] == _line(r1) + _line(r2)


def test_unexpected_put_exception_never_escapes_and_is_retried(capsys):
    client = MagicMock()
    client.put_object.side_effect = [RuntimeError("boom"), None]
    r1, r2 = _rec(A, 1), _rec(A, 2)

    async def go():
        sink = log_s3.S3LogSink(client, BUCKET, debounce_s=0.05)
        sink.add(r1)
        await asyncio.sleep(0.2)
        assert sink.pending() == 1  # the failed PUT left the buffer dirty
        sink.add(r2)
        await asyncio.sleep(0.2)
        assert sink.pending() == 0

    _run(go())
    assert client.put_object.call_count == 2
    assert client.put_object.call_args.kwargs["Body"] == _line(r1) + _line(r2)
    err = capsys.readouterr().err
    assert "proxy log upload failed for" in err and "RuntimeError" in err


@pytest.mark.parametrize("cid", ["../x", "AAAAAAAA-2222-4333-8444-555555555555", None, 5, ""])
def test_non_canonical_id_is_ignored(cid):
    client = _client()

    async def go():
        sink = log_s3.S3LogSink(client, BUCKET, debounce_s=0.05)
        sink.add({"capture_id": cid})
        sink.add({})
        await asyncio.sleep(0.15)
        assert sink._buffers == {}

    with Stubber(client) as stub:  # no responses queued: any PUT would error
        _run(go())
        stub.assert_no_pending_responses()


def test_byte_cap_flushes_at_once_and_ignores_later_records():
    client = _client()
    r1, r2 = _rec(A, 1), _rec(A, 2)
    cap = len(_line(r1)) + len(_line(r2)) - 1  # r2 would cross it

    async def go():
        sink = log_s3.S3LogSink(client, BUCKET, debounce_s=30, max_bytes=cap)
        sink.add(r1)
        sink.add(r2)  # crosses: not appended, immediate PUT of r1 only
        await asyncio.sleep(0.15)  # far below the 30 s debounce
        assert sink.pending() == 0
        sink.add(_rec(A, 3))  # ignored: no new PUT
        await asyncio.sleep(0.1)
        assert sink.pending() == 0

    with Stubber(client) as stub:
        _expect_put(stub, A, _line(r1))
        _run(go())
        stub.assert_no_pending_responses()


def test_put_failure_is_logged_by_code_and_retried_with_everything(capsys):
    client = _client()
    r1, r2 = _rec(A, 1), _rec(A, 2)

    async def go():
        sink = log_s3.S3LogSink(client, BUCKET, debounce_s=0.05)
        sink.add(r1)
        await asyncio.sleep(0.2)
        assert sink.pending() == 1
        sink.add(r2)
        await asyncio.sleep(0.2)
        assert sink.pending() == 0

    with Stubber(client) as stub:
        stub.add_client_error("put_object", "AccessDenied")
        _expect_put(stub, A, _line(r1) + _line(r2))
        _run(go())
        stub.assert_no_pending_responses()
    err = capsys.readouterr().err
    assert A in err and "AccessDenied" in err
    assert err.count("upload failed") == 1


def test_close_flushes_a_pending_buffer_at_once():
    client = _client()
    r1 = _rec(A, 1)

    async def go():
        sink = log_s3.S3LogSink(client, BUCKET, debounce_s=30)
        sink.add(r1)
        assert sink.pending() == 1
        await sink.close()
        assert sink.pending() == 0

    with Stubber(client) as stub:
        _expect_put(stub, A, _line(r1))
        _run(go())
        stub.assert_no_pending_responses()


def test_buffer_cap_sends_the_overflow_id_to_stdout_only(capsys):
    client = _client()
    r1 = _rec(A, 1)

    async def go():
        sink = log_s3.S3LogSink(client, BUCKET, debounce_s=0.05, max_buffers=1)
        sink.add(r1)
        sink.add(_rec(B, 1))
        sink.add(_rec(B, 2))
        assert list(sink._buffers) == [A]
        await sink.close()

    with Stubber(client) as stub:
        _expect_put(stub, A, _line(r1))
        _run(go())
        stub.assert_no_pending_responses()
    err = capsys.readouterr().err
    assert err.count(f"{B} goes to stdout only") == 1


def test_idle_buffers_are_evicted_after_the_ttl():
    client = _client()
    now = [100.0]
    r1 = _rec(A, 1)

    async def go():
        sink = log_s3.S3LogSink(
            client, BUCKET, debounce_s=0.05, ttl_s=10, clock=lambda: now[0]
        )
        sink.add(r1)
        await asyncio.sleep(0.2)
        assert A in sink._buffers
        now[0] += 11
        sink.add(_rec(B, 1))
        assert A not in sink._buffers and B in sink._buffers
        await sink.close()

    with Stubber(client) as stub:
        _expect_put(stub, A, _line(r1))
        _expect_put(stub, B, _line(_rec(B, 1)))
        _run(go())
        stub.assert_no_pending_responses()


def test_no_running_loop_puts_synchronously():
    client = _client()
    r1 = _rec(A, 1)
    sink = log_s3.S3LogSink(client, BUCKET)
    with Stubber(client) as stub:
        _expect_put(stub, A, _line(r1))
        sink.add(r1)
        stub.assert_no_pending_responses()
    assert sink.pending() == 0


def test_only_put_object_is_ever_called():
    client = MagicMock()

    async def go():
        sink = log_s3.S3LogSink(client, BUCKET, debounce_s=0.05)
        sink.add(_rec(A, 1))
        sink.add(_rec(B, 1))
        await asyncio.sleep(0.2)
        sink.add(_rec(A, 2))
        await sink.close()

    _run(go())
    called = {c[0] for c in client.method_calls}
    assert called == {"put_object"}
    assert client.put_object.call_count >= 3


def test_make_s3_log_writes_stdout_and_the_sink(capsys):
    sink = MagicMock()
    rec = _rec(A, 1)
    proxy_mod.make_s3_log(sink)(rec)
    sink.add.assert_called_once_with(rec)
    assert json.loads(capsys.readouterr().out.strip()) == rec


# ── live (local S3) ──────────────────────────────────────────────────────────

LIVE = os.environ.get("CAPTURE_S3_TEST_ENDPOINT")


@pytest.mark.skipif(not LIVE, reason="CAPTURE_S3_TEST_ENDPOINT not set")
def test_live_two_records_land_as_one_object():
    cfg = log_s3.config_from_env(
        {
            "CAPTURE_S3_ENDPOINT": LIVE,
            "CAPTURE_S3_INSECURE_HTTP": "1",
            "CAPTURE_S3_ACCESS_KEY": os.environ["CAPTURE_S3_TEST_ACCESS_KEY"],
            "CAPTURE_S3_SECRET_KEY": os.environ["CAPTURE_S3_TEST_SECRET_KEY"],
            "CAPTURE_S3_BUCKET_PROXYLOG": f"cap-{secrets.token_hex(4)}-proxylog",
        }
    )
    admin = log_s3.make_client(cfg)
    admin.create_bucket(Bucket=cfg.bucket)
    try:
        r1, r2 = _rec(A, 1), _rec(A, 2)

        async def go():
            sink = log_s3.S3LogSink(log_s3.make_client(cfg), cfg.bucket, debounce_s=0.05)
            sink.add(r1)
            sink.add(r2)
            await sink.close()
            assert sink.pending() == 0

        _run(go())
        body = admin.get_object(Bucket=cfg.bucket, Key=f"proxylog/{A}.jsonl")["Body"].read()
        assert body == _line(r1) + _line(r2)
    finally:
        for page in admin.get_paginator("list_objects_v2").paginate(Bucket=cfg.bucket):
            for obj in page.get("Contents", []):
                admin.delete_object(Bucket=cfg.bucket, Key=obj["Key"])
        admin.delete_bucket(Bucket=cfg.bucket)
