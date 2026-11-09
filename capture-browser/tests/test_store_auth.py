"""capture.store_auth: the keyless GCS access file, the pinning hook and the unsigned client.

Duplicated byte-for-byte in capture-proxy (see test_store_auth_parity.py). No network: a second
before-send handler captures the request and answers a canned response."""

import json
import os
import time
from datetime import datetime, timezone

import pytest
from botocore.awsrequest import AWSResponse
from botocore.exceptions import BotoCoreError

from capture import store_auth as sa

TOK = "tok-AAAA.BBBB_cccc~1234"
TOK2 = "tok-NEW.ZZZZ_yyyy~9999"
NOW = 1_800_000_000.0


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _body(token=TOK, expires=NOW + 3600, boundary="ab" * 32, **over):
    d = {"token": token, "expires_at": _iso(expires) if isinstance(expires, (int, float)) else expires,
         "boundary": boundary}
    d.update(over)
    return json.dumps(d)


def _write(path, text):
    path.write_text(text)
    return path


def _af(path, clock=lambda: NOW):
    return sa.AccessFile(str(path), who="test-who", clock=clock)


@pytest.fixture(autouse=True)
def _no_token_in_stderr(capsys):
    yield
    err = capsys.readouterr().err
    assert TOK not in err and TOK2 not in err


# --- AccessFile ------------------------------------------------------------------

def test_ok(tmp_path):
    assert _af(_write(tmp_path / "w.json", _body())).bearer() == TOK


def test_missing(tmp_path, capsys):
    with pytest.raises(sa.AccessUnavailable):
        _af(tmp_path / "nope.json").bearer()
    assert capsys.readouterr().err == "test-who: store access file: missing\n"


@pytest.mark.parametrize("text", [
    "{not json", "[]", "null", json.dumps({"token": TOK}),
    _body(token="has space"), _body(token="a\r\nb"), _body(token=""), _body(token="x" * 8193),
    _body(token=5), _body(token="tök"),
    _body(expires="2030-01-01T00:00:00.123Z"), _body(expires="2030-01-01T00:00:00+00:00"),
    _body(expires="2030-13-45T00:00:00Z"), _body(expires=None),
    _body(boundary=5), _body(boundary="b" * 129),
])
def test_invalid(tmp_path, text, capsys):
    p = _write(tmp_path / "w.json", text)
    with pytest.raises(sa.AccessUnavailable):
        _af(p).bearer()
    assert capsys.readouterr().err == "test-who: store access file: invalid\n"  # the parse path was REACHED


def test_boundary_required_but_extra_keys_ignored(tmp_path):
    p = _write(tmp_path / "w.json", json.dumps({"token": TOK, "expires_at": _iso(NOW + 99)}))
    with pytest.raises(sa.AccessUnavailable):
        _af(p).bearer()
    p = _write(tmp_path / "w2.json", _body(extra="x"))
    assert _af(p).bearer() == TOK


def test_too_large_and_not_regular_are_unreadable(tmp_path, capsys):
    big = _write(tmp_path / "big.json", _body() + " " * sa.ACCESS_FILE_MAX_BYTES)
    with pytest.raises(sa.AccessUnavailable):
        _af(big).bearer()
    with pytest.raises(sa.AccessUnavailable):
        _af(tmp_path).bearer()  # a directory
    assert capsys.readouterr().err.count("store access file: unreadable") == 2


def test_fifo_is_unreadable_not_read(tmp_path, capsys):
    # A FIFO opens (O_NONBLOCK) and reads as empty, so only the regular-file check makes this
    # "unreadable" rather than "invalid".
    fifo = tmp_path / "w.json"
    os.mkfifo(fifo)
    with pytest.raises(sa.AccessUnavailable):
        _af(fifo).bearer()
    assert capsys.readouterr().err == "test-who: store access file: unreadable\n"


def test_expiry_slack_boundary(tmp_path, capsys):
    exp = NOW + 1000
    p = _write(tmp_path / "w.json", _body(expires=exp))
    assert _af(p, clock=lambda: exp - 31).bearer() == TOK
    with pytest.raises(sa.AccessUnavailable):
        _af(p, clock=lambda: exp - 30).bearer()
    assert "store access file: expired" in capsys.readouterr().err


def test_expiry_is_checked_on_every_call_without_rereading(tmp_path):
    t = [NOW]
    p = _write(tmp_path / "w.json", _body(expires=NOW + 100))
    af = _af(p, clock=lambda: t[0])
    assert af.bearer() == TOK
    t[0] = NOW + 100  # the SAME unchanged file is now expired
    with pytest.raises(sa.AccessUnavailable):
        af.bearer()


def _kubelet(root, name, token):
    """<root>/worker.json -> ..data/worker.json ; ..data -> <timestamped dir>."""
    d = root / name
    d.mkdir()
    (d / "worker.json").write_text(_body(token=token))
    return d


def test_kubelet_atomic_swap_returns_the_new_token_and_follows_symlinks(tmp_path):
    d1 = _kubelet(tmp_path, "..2026_a", TOK)
    d2 = _kubelet(tmp_path, "..2026_b", TOK2)
    os.symlink(d1.name, tmp_path / "..data")
    os.symlink("..data/worker.json", tmp_path / "worker.json")
    af = _af(tmp_path / "worker.json")
    assert af.bearer() == TOK
    tmp_link = tmp_path / "..data_tmp"
    os.symlink(d2.name, tmp_link)
    os.replace(tmp_link, tmp_path / "..data")
    assert af.bearer() == TOK2


def test_unchanged_file_is_not_reopened(tmp_path, monkeypatch):
    p = _write(tmp_path / "w.json", _body())
    af = _af(p)
    opens = []
    real = os.open
    monkeypatch.setattr(sa.os, "open", lambda *a, **k: (opens.append(a), real(*a, **k))[1])
    for _ in range(5):
        assert af.bearer() == TOK
    assert len(opens) == 1
    p.write_text(_body(token=TOK2))  # a changed file IS reopened (size is the same, mtime/inode differ)
    os.utime(p, ns=(1, 1))
    assert af.bearer() == TOK2
    assert len(opens) == 2


def test_one_log_line_per_state_change(tmp_path, capsys):
    p = tmp_path / "w.json"
    af = _af(p)
    _write(p, _body())
    af.bearer()
    af.bearer()
    p.unlink()
    for _ in range(3):
        with pytest.raises(sa.AccessUnavailable):
            af.bearer()
    _write(p, _body())
    af.bearer()
    lines = capsys.readouterr().err.splitlines()
    assert lines == ["test-who: store access file: ok", "test-who: store access file: missing",
                     "test-who: store access file: ok"]


def test_access_unavailable_is_a_botocore_error():
    assert issubclass(sa.AccessUnavailable, BotoCoreError) and issubclass(sa.EndpointRefused, BotoCoreError)


# --- hook ------------------------------------------------------------------------

class _Req:
    def __init__(self, url):
        self.url, self.headers = url, {}


class _Spy:
    def __init__(self, token=TOK, exc=None):
        self.calls, self.token, self.exc = 0, token, exc

    def bearer(self):
        self.calls += 1
        if self.exc:
            raise self.exc
        return self.token


@pytest.mark.parametrize("url", [
    "http://storage.googleapis.com/b/k",
    "https://evil.example.test/b/k",
    "https://storage.googleapis.com.evil.test/b/k",
    "https://storage.googleapis.com:8443/b/k",
    "https://user@storage.googleapis.com/b/k",
    "https://user:pw@storage.googleapis.com/b/k",
    "https://storage.googleapis.com:notaport/b/k",
])
def test_hook_refuses_before_reading_the_file(url):
    spy, req = _Spy(), _Req(url)
    with pytest.raises(sa.EndpointRefused):
        sa.make_hook(spy)(req)
    assert spy.calls == 0 and req.headers == {}


def test_hook_sets_bearer_on_the_pinned_endpoint():
    spy, req = _Spy(), _Req("https://storage.googleapis.com:443/b/k")
    sa.make_hook(spy)(req)
    assert req.headers["Authorization"] == "Bearer " + TOK and spy.calls == 1


def test_hook_maps_any_other_failure_to_access_unavailable():
    req = _Req("https://storage.googleapis.com/b/k")
    with pytest.raises(sa.AccessUnavailable):
        sa.make_hook(_Spy(exc=RuntimeError("secret-text")))(req)
    assert "Authorization" not in req.headers


# --- client, no network ------------------------------------------------------------

def _short_circuit(client, seen):
    class _Raw:
        def stream(self, *a, **k):
            return iter(())

        def read(self, *a, **k):
            return b""

    def spy(request, **kw):
        seen.append((request.url, dict(request.headers)))
        return AWSResponse(request.url, 200, {}, _Raw())

    client.meta.events.register("before-send.s3", spy)


def test_client_is_unsigned_bearer_and_rereads_the_file_per_request(tmp_path):
    p = _write(tmp_path / "w.json", _body())
    client = sa.make_gcs_client("us-east-1", _af(p))
    seen = []
    _short_circuit(client, seen)
    client.head_bucket(Bucket="b-results")
    assert len(seen) == 1  # reached the transport
    url, headers = seen[0]
    assert url.startswith("https://storage.googleapis.com/b-results")
    assert headers["Authorization"] == "Bearer " + TOK
    assert "AWS4-HMAC-SHA256" not in " ".join(str(v) for v in headers.values())
    assert not any(k.lower() == "x-amz-date" for k in headers)
    p.write_text(_body(token=TOK2))
    os.utime(p, ns=(2, 2))
    client.head_bucket(Bucket="b-results")
    assert len(seen) == 2 and seen[1][1]["Authorization"] == "Bearer " + TOK2


def test_client_refuses_a_redirect_to_another_host_before_any_header(tmp_path):
    client = sa.make_gcs_client("us-east-1", _af(_write(tmp_path / "w.json", _body())))

    def redirect(request, **kw):
        request.url = "https://storage.googleapis.com.example.test/b/k"

    client.meta.events.register_first("before-send.s3", redirect)
    seen = []
    _short_circuit(client, seen)
    with pytest.raises(sa.EndpointRefused):
        client.head_bucket(Bucket="b")
    assert seen == []


def test_client_with_a_missing_file_fails_the_request(tmp_path):
    client = sa.make_gcs_client("us-east-1", _af(tmp_path / "nope.json"))
    seen = []
    _short_circuit(client, seen)
    with pytest.raises(sa.AccessUnavailable):
        client.head_bucket(Bucket="b")
    assert seen == []


# --- auth_from_env -----------------------------------------------------------------

GOOD = {"CAPTURE_S3_AUTH": "gcs-wi", "CAPTURE_S3_TOKEN_FILE": "/var/run/store/worker.json"}


def _auth(env=None, **over):
    kw = dict(endpoint=sa.GCS_ENDPOINT, path_style=True, allow_http=False, has_keys=False)
    kw.update(over)
    return sa.auth_from_env(GOOD if env is None else env, **kw)


def test_auth_defaults_to_sigv4():
    assert sa.auth_from_env({}, endpoint="https://s3.example.com", path_style=True, allow_http=False,
                            has_keys=True) == ("sigv4", None)
    assert sa.auth_from_env({"CAPTURE_S3_AUTH": "  "}, endpoint="x", path_style=False, allow_http=True,
                            has_keys=False) == ("sigv4", None)


def test_auth_gcs_wi_ok():
    assert _auth() == ("gcs-wi", "/var/run/store/worker.json")
    assert _auth({**GOOD, "CAPTURE_S3_AUTH": " GCS-WI "})[0] == "gcs-wi"


@pytest.mark.parametrize("env,over,named", [
    ({"CAPTURE_S3_AUTH": "iam"}, {}, "CAPTURE_S3_AUTH"),
    (None, {"endpoint": "https://storage.googleapis.com/"}, "CAPTURE_S3_ENDPOINT"),
    (None, {"endpoint": "https://s3.example.com"}, "CAPTURE_S3_ENDPOINT"),
    (None, {"has_keys": True}, "CAPTURE_S3_ACCESS_KEY"),
    (None, {"path_style": False}, "CAPTURE_S3_PATH_STYLE"),
    (None, {"allow_http": True}, "CAPTURE_S3_INSECURE_HTTP"),
    ({"CAPTURE_S3_AUTH": "gcs-wi"}, {}, "CAPTURE_S3_TOKEN_FILE"),
    ({"CAPTURE_S3_AUTH": "gcs-wi", "CAPTURE_S3_TOKEN_FILE": "rel/w.json"}, {}, "CAPTURE_S3_TOKEN_FILE"),
    ({"CAPTURE_S3_TOKEN_FILE": "/x/w.json"}, {}, "CAPTURE_S3_TOKEN_FILE"),  # sigv4 + token file
])
def test_auth_refusals_name_the_variable_and_echo_no_value(env, over, named):
    with pytest.raises(sa.AuthConfigError) as e:
        _auth(env, **over)
    assert named in str(e.value) and "/x/w.json" not in str(e.value) and "rel/w.json" not in str(e.value)
