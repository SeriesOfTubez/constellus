"""Real in-process tests for capture-proxy (planning#280 S5b-1).

The proxy listens on 127.0.0.1:<ephemeral>; upstreams are real asyncio servers on
127.0.0.1. Hostnames are synthetic (`*.example`). The test double for the
blocklist blocks the REAL list except 127.0.0.1, so a local upstream is
reachable while every private/metadata address stays refused.

Every case asserts the log line as well as the response, and every deny asserts
the upstream saw ZERO connections (the path was reached AND stopped).
"""

import asyncio
import base64
import contextlib
import inspect
import ipaddress
import json
import socket

import pytest

import ip_blocklist
import proxy as proxy_mod
from proxy import ALLOWED_PORTS, Proxy, build_proxy_from_env, default_resolver, serve

TOKEN = "s3cret-token"
CID = "cap_1"


def _test_blocked(ip) -> bool:
    return False if str(ip) == "127.0.0.1" else ip_blocklist.is_blocked(ip)


_NAMES = {
    "allowed.example": ["127.0.0.1"],
    "private.example": ["10.0.0.5"],
    "mixed.example": ["10.0.0.5", "127.0.0.1"],
    "meta.example": ["169.254.169.254"],
    "v6meta.example": ["64:ff9b::a9fe:a9fe"],
}


async def _resolver(host: str, port: int) -> list[str]:
    if host not in _NAMES:
        raise socket.gaierror(socket.EAI_NONAME, "no such host")
    return list(_NAMES[host])


def auth(cid=CID, token=TOKEN) -> bytes:
    b64 = base64.b64encode(f"{cid}:{token}".encode()).decode()
    return f"Proxy-Authorization: Basic {b64}\r\n".encode()


def run(coro):
    async def guarded():
        return await asyncio.wait_for(coro, 30)

    return asyncio.run(guarded())


class Upstream:
    """Real TCP server on 127.0.0.1. mode 'echo' or 'http'."""

    def __init__(self, mode: str):
        self.mode = mode
        self.connections = 0
        self.requests: list[bytes] = []
        self.server: asyncio.Server | None = None
        self.port = 0

    async def __aenter__(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc):
        self.server.close()
        await self.server.wait_closed()

    async def _handle(self, reader, writer):
        self.connections += 1
        try:
            if self.mode == "echo":
                while data := await reader.read(65536):
                    writer.write(data)
                    await writer.drain()
            else:
                raw = await reader.readuntil(b"\r\n\r\n")
                lower = raw.lower()
                if b"content-length:" in lower:
                    n = int(lower.split(b"content-length:")[1].split(b"\r\n")[0])
                    raw += await reader.readexactly(n)
                elif b"transfer-encoding: chunked" in lower:
                    raw += await reader.readuntil(b"\r\n0\r\n\r\n")
                self.requests.append(raw)
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
                )
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()


@contextlib.asynccontextmanager
async def running(**kw):
    logs: list[dict] = []
    kw.setdefault("is_blocked", _test_blocked)
    kw.setdefault("resolver", _resolver)
    proxy = Proxy(token=TOKEN, log=logs.append, **kw)
    server = await serve(proxy, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        yield proxy, port, logs
    finally:
        server.close()
        await asyncio.wait_for(server.wait_closed(), 5)


async def exchange(port: int, payload: bytes) -> bytes:
    """Send `payload`, read until the proxy closes the connection."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(payload)
    await writer.drain()
    data = await asyncio.wait_for(reader.read(), 10)
    writer.close()
    return data


def status(resp: bytes) -> int:
    return int(resp.split(b" ", 2)[1])


def header(resp: bytes, name: str) -> str | None:
    for line in resp.split(b"\r\n\r\n")[0].split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        if k.strip().lower() == name.lower().encode():
            return v.strip().decode()
    return None


async def wait_for_logs(logs: list, n: int = 1):
    for _ in range(200):
        if len(logs) >= n:
            return
        await asyncio.sleep(0.025)
    raise AssertionError(f"expected {n} log lines, got {logs}")


def connect_req(host: str, port: int, extra: bytes = b"") -> bytes:
    return f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n".encode() + extra + b"\r\n"


def get_req(url: str, extra: bytes = b"", method: str = "GET", tail: bytes = b"") -> bytes:
    authority = url.split("/")[2]
    return (
        f"{method} {url} HTTP/1.1\r\nHost: {authority}\r\n".encode() + extra + b"\r\n" + tail
    )


# ── auth ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "extra",
    [
        b"",
        auth(token="wrong"),
        auth(cid="bad id!"),
        auth(cid="x" * 65),
        auth(cid=""),
        b"Proxy-Authorization: Basic !!!notbase64!!!\r\n",
        b"Proxy-Authorization: Bearer abc\r\n",
    ],
    ids=["none", "wrong_token", "bad_charset", "too_long", "empty_id", "bad_b64", "bearer"],
)
@pytest.mark.parametrize("shape", ["connect", "http"])
def test_auth_failure_is_407_and_upstream_untouched(extra, shape):
    async def go():
        async with Upstream("echo") as up:
            async with running(allowed_ports=frozenset({up.port})) as (_p, port, logs):
                if shape == "connect":
                    payload = connect_req("allowed.example", up.port, extra)
                else:
                    payload = get_req(f"http://allowed.example:{up.port}/", extra)
                resp = await exchange(port, payload)
                await wait_for_logs(logs)
                assert status(resp) == 407
                assert header(resp, "Proxy-Authenticate") == 'Basic realm="capture"'
                assert len(logs) == 1
                assert logs[0]["decision"] == "deny" and logs[0]["reason"] == "auth"
                assert logs[0]["capture_id"] is None
                assert logs[0]["pinned_ip"] is None
                assert up.connections == 0

    run(go())


# ── CONNECT ───────────────────────────────────────────────────────────────────


def test_connect_splices_both_ways_and_logs_allow():
    async def go():
        async with Upstream("echo") as up:
            async with running(allowed_ports=frozenset({up.port})) as (_p, port, logs):
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(connect_req("allowed.example", up.port, auth()))
                await writer.drain()
                head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
                assert head.startswith(b"HTTP/1.1 200 Connection Established")
                writer.write(b"hello tunnel")
                await writer.drain()
                assert await asyncio.wait_for(reader.readexactly(12), 5) == b"hello tunnel"
                writer.close()
                await wait_for_logs(logs)
                assert up.connections == 1
                (line,) = logs
                assert line["decision"] == "allow" and line["reason"] is None
                assert line["capture_id"] == CID
                assert (line["method"], line["scheme"]) == ("CONNECT", "connect")
                assert (line["host"], line["port"]) == ("allowed.example", up.port)
                assert line["pinned_ip"] == "127.0.0.1"
                assert line["resolved"] == ["127.0.0.1"]
                assert line["bytes_up"] == 12 and line["bytes_down"] == 12
                assert line["duration_ms"] >= 0 and line["ts"].endswith("+00:00")

    run(go())


# ── absolute-form HTTP ────────────────────────────────────────────────────────


def test_absolute_form_get_is_rewritten_to_origin_form():
    async def go():
        async with Upstream("http") as up:
            async with running(allowed_ports=frozenset({up.port})) as (_p, port, logs):
                extra = (
                    auth()
                    + b"Proxy-Connection: keep-alive\r\nKeep-Alive: 5\r\n"
                    + b"Connection: keep-alive, X-Hop\r\nX-Hop: 1\r\nX-Custom: yes\r\n"
                )
                resp = await exchange(port, get_req(f"http://allowed.example:{up.port}/p?q=1", extra))
                await wait_for_logs(logs)
                assert resp.endswith(b"hello") and status(resp) == 200
                (raw,) = up.requests
                lines = raw.split(b"\r\n")
                assert lines[0] == b"GET /p?q=1 HTTP/1.1"
                lowered = [ln.lower() for ln in lines]
                assert f"host: allowed.example:{up.port}".encode() in lowered
                assert b"connection: close" in lowered
                assert b"x-custom: yes" in lowered
                for banned in (b"proxy-", b"keep-alive", b"x-hop", b"connection: keep-alive"):
                    assert not any(ln.startswith(banned) for ln in lowered), banned
                assert sum(ln.startswith(b"host:") for ln in lowered) == 1
                (line,) = logs
                assert line["decision"] == "allow" and line["scheme"] == "http"
                assert line["method"] == "GET" and line["capture_id"] == CID
                assert line["pinned_ip"] == "127.0.0.1"
                assert line["bytes_down"] == len(resp) and line["bytes_up"] == len(raw)

    run(go())


def test_post_with_content_length_body_arrives_intact():
    async def go():
        async with Upstream("http") as up:
            async with running(allowed_ports=frozenset({up.port})) as (_p, port, logs):
                body = b"a=1&b=two"
                extra = auth() + f"Content-Length: {len(body)}\r\n".encode()
                payload = get_req(f"http://allowed.example:{up.port}/submit", extra, "POST", body)
                resp = await exchange(port, payload)
                await wait_for_logs(logs)
                assert status(resp) == 200
                (raw,) = up.requests
                assert raw.startswith(b"POST /submit HTTP/1.1\r\n")
                assert raw.endswith(b"\r\n\r\n" + body)
                assert b"content-length: 9" in raw.lower()
                assert logs[0]["decision"] == "allow" and logs[0]["method"] == "POST"

    run(go())


def test_post_with_chunked_body_arrives_intact():
    async def go():
        async with Upstream("http") as up:
            async with running(allowed_ports=frozenset({up.port})) as (_p, port, logs):
                extra = auth() + b"Transfer-Encoding: chunked\r\n"
                tail = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
                payload = get_req(f"http://allowed.example:{up.port}/c", extra, "POST", tail)
                resp = await exchange(port, payload)
                await wait_for_logs(logs)
                assert status(resp) == 200
                (raw,) = up.requests
                head, _, body = raw.partition(b"\r\n\r\n")
                assert b"transfer-encoding: chunked" in head.lower()
                # decode the chunked body the upstream received
                out, rest = b"", body
                while True:
                    size_s, _, rest = rest.partition(b"\r\n")
                    size = int(size_s, 16)
                    if size == 0:
                        break
                    out, rest = out + rest[:size], rest[size + 2 :]
                assert out == b"hello world"
                assert logs[0]["decision"] == "allow"

    run(go())


# ── blocked destinations ──────────────────────────────────────────────────────

_DENIED = [
    ("private.example", "all_blocked"),
    ("meta.example", "all_blocked"),
    ("v6meta.example", "all_blocked"),
    ("10.0.0.1", "blocked_literal"),
    ("[::ffff:10.0.0.1]", "blocked_literal"),
    ("169.254.169.254", "blocked_literal"),
    ("[64:ff9b::a9fe:a9fe]", "blocked_literal"),
]


@pytest.mark.parametrize("shape", ["connect", "http"])
@pytest.mark.parametrize("host,reason", _DENIED)
def test_blocked_destinations_are_403_and_never_connected(host, reason, shape):
    async def go():
        async with Upstream("echo") as up:
            async with running(allowed_ports=frozenset({up.port})) as (_p, port, logs):
                if shape == "connect":
                    payload = connect_req(host, up.port, auth())
                else:
                    payload = get_req(f"http://{host}:{up.port}/", auth())
                resp = await exchange(port, payload)
                await wait_for_logs(logs)
                assert status(resp) == 403
                assert header(resp, "X-Capture-Proxy-Reason") == reason
                (line,) = logs
                assert line["decision"] == "deny" and line["reason"] == reason
                assert line["capture_id"] == CID and line["pinned_ip"] is None
                assert line["bytes_up"] == 0 and line["bytes_down"] == 0
                assert up.connections == 0

    run(go())


def test_blocked_denies_are_not_a_vacuous_blocklist():
    """Positive control: the same harness, same upstream, an allowed name DOES
    connect. Without this a broken fixture would make every deny test pass."""

    async def go():
        async with Upstream("http") as up:
            async with running(allowed_ports=frozenset({up.port})) as (_p, port, logs):
                resp = await exchange(port, get_req(f"http://allowed.example:{up.port}/", auth()))
                await wait_for_logs(logs)
                assert status(resp) == 200 and up.connections == 1

    run(go())


def test_mixed_answer_is_pinned_to_the_unblocked_address():
    async def go():
        async with Upstream("http") as up:
            async with running(allowed_ports=frozenset({up.port})) as (_p, port, logs):
                resp = await exchange(port, get_req(f"http://mixed.example:{up.port}/", auth()))
                await wait_for_logs(logs)
                assert status(resp) == 200 and up.connections == 1
                (line,) = logs
                assert line["pinned_ip"] == "127.0.0.1"
                assert line["resolved"] == ["10.0.0.5", "127.0.0.1"]

    run(go())


def test_dns_rebind_shape_resolves_once_and_uses_the_first_answer():
    calls = []

    async def rebinding(host: str, port: int) -> list[str]:
        calls.append(host)
        return ["127.0.0.1"] if len(calls) == 1 else ["10.0.0.5"]

    async def go():
        async with Upstream("http") as up:
            async with running(
                allowed_ports=frozenset({up.port}), resolver=rebinding
            ) as (_p, port, logs):
                resp = await exchange(port, get_req(f"http://rebind.example:{up.port}/", auth()))
                await wait_for_logs(logs)
                assert status(resp) == 200
                assert len(calls) == 1, calls
                assert up.connections == 1
                assert logs[0]["pinned_ip"] == "127.0.0.1"
                assert logs[0]["resolved"] == ["127.0.0.1"]

    run(go())


def test_unresolvable_and_malformed_hosts_are_denied():
    async def go():
        async with Upstream("echo") as up:
            async with running(allowed_ports=frozenset({up.port})) as (_p, port, logs):
                r1 = await exchange(port, connect_req("nosuch.example", up.port, auth()))
                r2 = await exchange(port, connect_req("bad_host!.example", up.port, auth()))
                r3 = await exchange(port, connect_req("xn--é.example", up.port, auth()))
                await wait_for_logs(logs, 3)
                reasons = sorted(entry["reason"] for entry in logs)
                assert up.connections == 0
                assert reasons.count("dns_failed") == 1
                assert reasons.count("bad_host") + reasons.count("bad_request") == 2

    run(go())


# ── ports ─────────────────────────────────────────────────────────────────────


def test_disallowed_port_is_403_with_the_default_allowed_ports():
    async def go():
        async with Upstream("echo") as up:
            async with running() as (proxy, port, logs):  # default allowed_ports
                assert proxy.allowed_ports is ALLOWED_PORTS
                resp = await exchange(port, connect_req("allowed.example", up.port, auth()))
                await wait_for_logs(logs)
                assert status(resp) == 403
                assert logs[0]["decision"] == "deny" and logs[0]["reason"] == "port"
                assert logs[0]["port"] == up.port
                assert up.connections == 0

    run(go())


# ── bad requests ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "payload",
    [
        b"GET /path HTTP/1.1\r\nHost: allowed.example\r\n" + auth() + b"\r\n",
        b"GET https://allowed.example/ HTTP/1.1\r\nHost: allowed.example\r\n" + auth() + b"\r\n",
        b"GET http://user@allowed.example/ HTTP/1.1\r\nHost: allowed.example\r\n" + auth() + b"\r\n",
        b"CONNECT allowed.example HTTP/1.1\r\nHost: allowed.example\r\n" + auth() + b"\r\n",
        b"NOT AN HTTP REQUEST\r\n\r\n",
        b"GET http://allowed.example/ HTTP/1.1\r\n" + auth() + b"\r\n",  # no Host
    ],
    ids=["origin_form", "https_absolute", "userinfo", "connect_no_port", "garbage", "no_host"],
)
def test_bad_requests_are_400(payload):
    async def go():
        async with Upstream("echo") as up:
            async with running(allowed_ports=frozenset({up.port})) as (_p, port, logs):
                resp = await exchange(port, payload)
                await wait_for_logs(logs)
                assert status(resp) == 400
                assert len(logs) == 1
                assert logs[0]["decision"] == "deny" and logs[0]["reason"] == "bad_request"
                assert up.connections == 0

    run(go())


def test_oversized_head_is_400():
    async def go():
        async with running() as (_p, port, logs):
            resp = await exchange(
                port, b"GET http://allowed.example/ HTTP/1.1\r\nX: " + b"a" * 20000 + b"\r\n\r\n"
            )
            await wait_for_logs(logs)
            assert status(resp) == 400
            assert logs[0]["reason"] == "bad_request"

    run(go())


# ── upstream failure ──────────────────────────────────────────────────────────


def test_connect_failure_is_502_error_connect_failed():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    dead_port = s.getsockname()[1]
    s.close()  # nothing listens here now

    async def go():
        async with running(allowed_ports=frozenset({dead_port})) as (_p, port, logs):
            resp = await exchange(port, connect_req("allowed.example", dead_port, auth()))
            await wait_for_logs(logs)
            assert status(resp) == 502
            (line,) = logs
            assert line["decision"] == "error" and line["reason"] == "connect_failed"
            assert line["pinned_ip"] is None and line["resolved"] == ["127.0.0.1"]

    run(go())


# ── limits ────────────────────────────────────────────────────────────────────


def test_capacity_second_client_gets_503():
    async def go():
        async with Upstream("echo") as up:
            async with running(
                allowed_ports=frozenset({up.port}), max_connections=1
            ) as (proxy, port, logs):
                r1, w1 = await asyncio.open_connection("127.0.0.1", port)  # holds the slot
                for _ in range(200):
                    if proxy._active == 1:
                        break
                    await asyncio.sleep(0.025)
                assert proxy._active == 1
                resp = await exchange(port, connect_req("allowed.example", up.port, auth()))
                await wait_for_logs(logs)
                assert status(resp) == 503
                assert logs[0]["decision"] == "deny" and logs[0]["reason"] == "capacity"
                assert up.connections == 0
                w1.close()
                for _ in range(200):
                    if proxy._active == 0:
                        break
                    await asyncio.sleep(0.025)
                assert proxy._active == 0
                assert len(logs) == 1  # the bare idle connection logged nothing

    run(go())


def test_idle_tunnel_is_closed_and_logs_once():
    async def go():
        async with Upstream("echo") as up:
            async with running(
                allowed_ports=frozenset({up.port}), idle_timeout_s=0.4
            ) as (_p, port, logs):
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(connect_req("allowed.example", up.port, auth()))
                await reader.readuntil(b"\r\n\r\n")
                writer.write(b"ping")
                assert await asyncio.wait_for(reader.readexactly(4), 5) == b"ping"
                rest = await asyncio.wait_for(reader.read(), 5)  # EOF only if proxy closed us
                assert rest == b""
                await wait_for_logs(logs)
                await asyncio.sleep(0.2)
                assert len(logs) == 1
                (line,) = logs
                assert line["decision"] == "allow" and line["reason"] is None
                assert line["bytes_up"] == 4 and line["bytes_down"] == 4
                assert line["duration_ms"] >= 300
                writer.close()

    run(go())


# ── production defaults / startup ─────────────────────────────────────────────


def test_production_defaults_are_the_real_blocklist_and_ports():
    params = inspect.signature(Proxy.__init__).parameters
    assert params["is_blocked"].default is ip_blocklist.is_blocked
    assert params["allowed_ports"].default is ALLOWED_PORTS
    assert params["resolver"].default is default_resolver
    shipped = build_proxy_from_env({"CAPTURE_PROXY_TOKEN": "t"})
    assert shipped.is_blocked is ip_blocklist.is_blocked
    assert shipped.allowed_ports is ALLOWED_PORTS
    assert shipped.resolver is default_resolver
    assert ALLOWED_PORTS == frozenset({80, 443})


def test_ip_blocklist_import_is_the_vendored_module_not_a_shadow():
    assert proxy_mod.ip_blocklist is ip_blocklist
    assert ip_blocklist.is_blocked(ipaddress.ip_address("169.254.169.254")) is True


@pytest.mark.parametrize("env", [{}, {"CAPTURE_PROXY_TOKEN": ""}])
def test_missing_token_refuses_to_start(env):
    with pytest.raises(SystemExit) as exc:
        build_proxy_from_env(env)
    assert "CAPTURE_PROXY_TOKEN" in str(exc.value)


def test_proxy_class_rejects_empty_token():
    with pytest.raises(ValueError):
        Proxy(token="")


def test_default_log_is_one_json_line_on_stdout(capsys):
    proxy_mod.emit_stdout({"a": 1})
    out = capsys.readouterr().out
    assert out.endswith("\n") and json.loads(out) == {"a": 1}
