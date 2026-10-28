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
import os
import socket

import pytest

import ip_blocklist
import proxy as proxy_mod
from proxy import ALLOWED_PORTS, Proxy, build_proxy_from_env, default_resolver, serve

KEY = "k" * 32
CID = "00000000-0000-4000-8000-000000000001"


def _test_blocked(ip) -> bool:
    return False if str(ip) == "127.0.0.1" else ip_blocklist.is_blocked(ip)


_NAMES = {
    "allowed.example": ["127.0.0.1"],
    "private.example": ["10.0.0.5"],
    "mixed.example": ["10.0.0.5", "127.0.0.1"],
    "meta.example": ["169.254.169.254"],
    "v6meta.example": ["64:ff9b::a9fe:a9fe"],
    "web.archive.org": ["127.0.0.1"],
    "WEB.ARCHIVE.ORG": ["127.0.0.1"],
}


async def _resolver(host: str, port: int) -> list[str]:
    if host not in _NAMES:
        raise socket.gaierror(socket.EAI_NONAME, "no such host")
    return list(_NAMES[host])


NOW = 1_900_000_000  # the fixed clock every Proxy in this file runs on
EXP = NOW + 600
MAX_TTL = proxy_mod.MAX_CREDENTIAL_TTL_S


def _clock() -> float:
    return float(NOW)


def auth(cid=CID, mode="live", token=None, user=None, exp=EXP) -> bytes:
    """Proxy-Authorization header. The token is derived from KEY (via the proxy's
    own derive_token) unless overridden; `user` replaces `<cid>|<mode>|<exp>`
    wholesale."""
    if token is None:
        token = proxy_mod.derive_token(KEY.encode(), cid, mode, exp)
    if user is None:
        user = f"{cid}|{mode}|{exp}"
    b64 = base64.b64encode(f"{user}:{token}".encode()).decode()
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
    kw.setdefault("clock", _clock)
    proxy = Proxy(key=KEY, log=logs.append, **kw)
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


_OTHER_CID = "00000000-0000-4000-8000-000000000002"
_UPPER_CID = "ABCDEF01-AAAA-4AAA-8AAA-AAAAAAAAAAAA"  # contains letters, so .upper() differs
_LIVE_TOK = proxy_mod.derive_token(KEY.encode(), CID, "live", EXP)
_ARCH_TOK = proxy_mod.derive_token(KEY.encode(), CID, "archive", EXP)


def _tok(cid, mode="live", exp=EXP):
    return proxy_mod.derive_token(KEY.encode(), cid, mode, exp)


def test_token_derivation_matches_contract_v3_vectors():
    """Hard-coded vectors from the wire contract, against the proxy's own
    derive_token (the function _authenticate uses)."""
    key = b"k" * 32
    cid = "00000000-0000-4000-8000-000000000001"
    assert proxy_mod.derive_token(key, cid, "live", 2000000000) == (
        "fd4cc753d722f5681637818178f5319706eb2b66b6c19cc182666f4d6e9e1382"
    )
    assert proxy_mod.derive_token(key, cid, "archive", 2000000000) == (
        "ec9eb6417283118f7de8b8013f57c6b86582311497a3921e31bca75ca696ea9a"
    )


def test_authenticate_accepts_valid_and_returns_cid_and_mode():
    import h11

    p = Proxy(key=KEY, clock=_clock)
    for mode in ("live", "archive"):
        hdr = auth(mode=mode).split(b": ", 1)[1].strip()
        req = h11.Request(
            method="CONNECT",
            target="a.example:443",
            headers=[("Host", "a.example:443"), ("Proxy-Authorization", hdr)],
        )
        assert p._authenticate(req) == (CID, mode)


@pytest.mark.parametrize(
    "extra",
    [
        b"",
        auth(token="wrong" * 13),
        auth(mode="archive", token=_LIVE_TOK),  # mode swap: live token as archive
        auth(mode="live", token=_ARCH_TOK),
        auth(token=_tok(_OTHER_CID)),
        auth(token=_LIVE_TOK.upper()),
        auth(token=proxy_mod.derive_token(b"z" * 32, CID, "live", EXP)),  # wrong key
        auth(token=_LIVE_TOK[:-1]),
        auth(token=_LIVE_TOK + "0"),
        auth(token=""),
        auth(user=CID, token=_LIVE_TOK),  # mode missing
        auth(user=f"{CID}|admin|{EXP}"),
        auth(user=f"{CID}||{EXP}"),
        auth(user=f"{CID}|LIVE|{EXP}"),
        auth(user=f"|live|{EXP}"),
        auth(user=f"{_UPPER_CID}|live|{EXP}", token=_tok(_UPPER_CID)),
        auth(user=f"{CID.replace('-', '')}|live|{EXP}", token=_tok(CID.replace("-", ""))),
        auth(user="cap_1|live|" + str(EXP), token=_tok("cap_1")),
        auth(exp=NOW - 1),
        auth(exp=NOW + MAX_TTL + 1),
        auth(exp="0123456789"),
        auth(exp="0"),
        auth(exp="-5"),
        auth(exp="+1900000600"),
        auth(exp="1" * 13),
        auth(exp="12ab"),
        auth(exp=""),
        auth(user=f"{CID}|live", token=_tok(CID)),  # old 2-part form
        auth(user=f"{CID}|live|{EXP}|x"),
        auth(token=_tok(CID, "live", EXP + 1)),  # MAC'd for a different exp
        b"Proxy-Authorization: Basic !!!notbase64!!!\r\n",
        b"Proxy-Authorization: Bearer abc\r\n",
    ],
    ids=[
        "none", "wrong_token", "mode_swap_live_as_archive", "mode_swap_archive_as_live",
        "other_capture_id", "uppercase_hex", "wrong_key", "truncated", "extended",
        "empty_token", "mode_missing", "unknown_mode", "empty_mode", "mode_wrong_case",
        "empty_id", "uppercase_uuid", "dashless_uuid", "cap_1_id",
        "expired", "too_far_future", "exp_leading_zero", "exp_zero", "exp_negative",
        "exp_plus_sign", "exp_13_digits", "exp_non_digit", "exp_empty",
        "two_parts", "four_parts", "exp_tampered", "bad_b64", "bearer",
    ],
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
                assert logs[0]["capture_id"] is None and logs[0]["mode"] is None
                assert logs[0]["pinned_ip"] is None
                assert up.connections == 0

    run(go())


@pytest.mark.parametrize("exp", [NOW, NOW + MAX_TTL, NOW + 1])
def test_exp_window_edges_are_allowed(exp):
    """Positive control for the expiry cases: the inclusive edges authenticate."""
    import h11

    p = Proxy(key=KEY, clock=_clock)
    hdr = auth(exp=exp).split(b": ", 1)[1].strip()
    req = h11.Request(
        method="CONNECT",
        target="a.example:443",
        headers=[("Host", "a.example:443"), ("Proxy-Authorization", hdr)],
    )
    assert p._authenticate(req) == (CID, "live")


def test_exp_window_follows_the_injected_clock():
    import h11

    hdr = auth().split(b": ", 1)[1].strip()
    req = h11.Request(
        method="CONNECT",
        target="a.example:443",
        headers=[("Host", "a.example:443"), ("Proxy-Authorization", hdr)],
    )
    assert Proxy(key=KEY, clock=lambda: EXP)._authenticate(req) == (CID, "live")
    assert Proxy(key=KEY, clock=lambda: EXP + 1)._authenticate(req) is None
    assert Proxy(key=KEY, clock=lambda: EXP + 0.9)._authenticate(req) == (CID, "live")


@pytest.mark.parametrize("exp_s", ["0" + str(EXP), "+" + str(EXP), " " + str(EXP)])
def test_correctly_macd_noncanonical_exp_is_still_407(exp_s):
    """The MAC is valid for the presented exp string, and its integer value is
    inside the window, so only the exp FORM check can refuse it."""

    async def go():
        async with Upstream("echo") as up:
            async with running(allowed_ports=frozenset({up.port})) as (_p, port, logs):
                resp = await exchange(port, connect_req("allowed.example", up.port, auth(exp=exp_s)))
                await wait_for_logs(logs)
                assert status(resp) == 407 and logs[0]["reason"] == "auth"
                assert up.connections == 0

    run(go())


def test_correctly_macd_unknown_mode_is_still_407():
    """A token that IS a valid MAC for a mode outside MODES (the key holder never
    mints one, but the proxy must not rely on that) fails auth, upstream untouched."""

    async def go():
        async with Upstream("echo") as up:
            async with running(allowed_ports=frozenset({up.port})) as (_p, port, logs):
                resp = await exchange(port, connect_req("allowed.example", up.port, auth(mode="admin")))
                await wait_for_logs(logs)
                assert status(resp) == 407 and logs[0]["reason"] == "auth"
                assert up.connections == 0

    run(go())


def test_a_mode_without_a_policy_is_denied_not_treated_as_live(monkeypatch):
    """Deny by default: if MODES ever grows without a policy in _serve, that mode
    authenticates but reaches nothing (403 reason mode), never the live policy."""
    monkeypatch.setattr(proxy_mod, "MODES", ("live", "archive", "future"))

    async def go():
        async with Upstream("echo") as up:
            async with running(allowed_ports=frozenset({up.port})) as (_p, port, logs):
                resp = await exchange(port, connect_req("allowed.example", up.port, auth(mode="future")))
                await wait_for_logs(logs)
                assert logs[0]["mode"] == "future"  # precondition: auth passed
                assert status(resp) == 403 and logs[0]["reason"] == "mode"
                assert up.connections == 0

    run(go())


def test_valid_credentials_authenticate_in_both_modes():
    """Positive control for the 407 matrix: the same harness with a valid header
    gets past auth (live reaches the upstream; archive to this non-archive host
    is 403 archive_host, not 407) and the log carries the mode."""

    async def go():
        for mode in ("live", "archive"):
            async with Upstream("echo") as up:
                async with running(allowed_ports=frozenset({up.port})) as (_p, port, logs):
                    reader, writer = await asyncio.open_connection("127.0.0.1", port)
                    writer.write(
                        connect_req("allowed.example", up.port, auth(mode=mode))
                    )
                    await writer.drain()
                    head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
                    writer.close()
                    await wait_for_logs(logs)
                    assert logs[0]["mode"] == mode and logs[0]["capture_id"] == CID
                    if mode == "live":
                        assert status(head) == 200 and up.connections == 1
                    else:
                        assert status(head) == 403 and up.connections == 0

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
    shipped = build_proxy_from_env({"CAPTURE_PROXY_KEY": KEY})
    assert shipped.is_blocked is ip_blocklist.is_blocked
    assert shipped.allowed_ports is ALLOWED_PORTS
    assert shipped.resolver is default_resolver
    assert ALLOWED_PORTS == frozenset({80, 443})


def test_ip_blocklist_import_is_the_vendored_module_not_a_shadow():
    assert proxy_mod.ip_blocklist is ip_blocklist
    assert ip_blocklist.is_blocked(ipaddress.ip_address("169.254.169.254")) is True


@pytest.mark.parametrize(
    "env",
    [
        {},
        {"CAPTURE_PROXY_KEY": ""},
        {"CAPTURE_PROXY_KEY": "k" * 31},
        {"CAPTURE_PROXY_KEY": " " * 40},
        {"CAPTURE_PROXY_KEY": " " + "k" * 30 + " "},  # 32 chars, 30 after strip
        {"CAPTURE_PROXY_TOKEN": "t" * 40},  # the removed shared token: no fallback
    ],
    ids=["missing", "empty", "31_chars", "whitespace_only", "short_after_strip", "old_token_only"],
)
def test_missing_or_short_key_refuses_to_start(env):
    with pytest.raises(SystemExit) as exc:
        build_proxy_from_env(env)
    assert "CAPTURE_PROXY_KEY" in str(exc.value)


def test_key_is_stripped_from_env():
    shipped = build_proxy_from_env({"CAPTURE_PROXY_KEY": f"  {KEY}\n"})
    assert shipped._key == KEY.encode()


@pytest.mark.parametrize("key", ["", "short", "k" * 31])
def test_proxy_class_rejects_short_key(key):
    with pytest.raises(ValueError):
        Proxy(key=key)


def test_no_reference_to_the_removed_shared_token_in_the_proxy():
    assert "CAPTURE_PROXY_TOKEN" not in inspect.getsource(proxy_mod)


def test_default_log_is_one_json_line_on_stdout(capsys):
    proxy_mod.emit_stdout({"a": 1})
    out = capsys.readouterr().out
    assert out.endswith("\n") and json.loads(out) == {"a": 1}


# ── per-capture proxy log file (capture-spool.md "Proxy log") ────────────────

GOOD_ID = "0190a1b2-c3d4-7e5f-8a6b-1234567890ab"


def _rec(cid):
    return {"capture_id": cid, "decision": "allow", "host": "example.com"}


def _stdout_hosts(capsys) -> list:
    """The `host` of every JSON log line printed to stdout (exact, not substring)."""
    return [json.loads(line)["host"] for line in capsys.readouterr().out.splitlines() if line.strip()]


@pytest.mark.parametrize(
    "cid",
    [
        "../x",
        GOOD_ID.upper(),
        "a/b",
        GOOD_ID + "0",  # 37 chars
        GOOD_ID.replace("-", ""),  # 32 hex, uuid() accepts but not canonical
        "cap_1",
        None,
    ],
)
def test_proxy_log_file_refuses_non_canonical_ids(tmp_path, capsys, cid):
    logdir = tmp_path / "log"
    logdir.mkdir()
    proxy_mod.make_log(str(logdir))(_rec(cid))
    assert list(logdir.iterdir()) == []
    assert list(tmp_path.iterdir()) == [logdir]  # nothing escaped the dir
    assert '"decision":"allow"' in capsys.readouterr().out  # path reached; stdout kept


def test_proxy_log_file_written_for_canonical_uuid(tmp_path, capsys):
    log = proxy_mod.make_log(str(tmp_path))
    log(_rec(GOOD_ID))
    log(_rec(GOOD_ID))
    f = tmp_path / f"{GOOD_ID}.jsonl"
    lines = f.read_text().splitlines()
    assert [json.loads(x)["host"] for x in lines] == ["example.com"] * 2
    assert len(capsys.readouterr().out.splitlines()) == 2


def test_proxy_log_file_does_not_follow_a_planted_symlink(tmp_path, capsys):
    logdir = tmp_path / "log"
    logdir.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("untouched")
    (logdir / f"{GOOD_ID}.jsonl").symlink_to(victim)
    assert proxy_mod.append_capture_log(str(logdir), _rec(GOOD_ID)) is False
    proxy_mod.make_log(str(logdir))(_rec(GOOD_ID))
    assert victim.read_text() == "untouched"
    assert _stdout_hosts(capsys) == ["example.com"]  # stdout still got the line


def test_proxy_log_file_respects_the_size_cap(tmp_path, capsys):
    f = tmp_path / f"{GOOD_ID}.jsonl"
    assert proxy_mod.append_capture_log(str(tmp_path), _rec(GOOD_ID)) is True
    with open(f, "ab") as fh:
        fh.truncate(proxy_mod.LOG_FILE_MAX_BYTES)
    before = f.stat().st_size
    proxy_mod.make_log(str(tmp_path))(_rec(GOOD_ID))
    assert f.stat().st_size == before
    assert _stdout_hosts(capsys) == ["example.com"]


def test_proxy_log_file_oserror_never_raises(tmp_path, capsys):
    missing = tmp_path / "nope"  # directory does not exist -> open raises ENOENT
    proxy_mod.make_log(str(missing))(_rec(GOOD_ID))  # must not raise
    assert not missing.exists()
    assert _stdout_hosts(capsys) == ["example.com"]


def test_proxy_log_file_write_error_never_raises(tmp_path, monkeypatch, capsys):
    def boom(fd, data):
        raise OSError(28, "no space")

    monkeypatch.setattr(proxy_mod.os, "write", boom)
    proxy_mod.make_log(str(tmp_path))(_rec(GOOD_ID))
    assert _stdout_hosts(capsys) == ["example.com"]


def test_build_proxy_from_env_uses_file_log_only_when_dir_set(tmp_path, capsys):
    plain = build_proxy_from_env({"CAPTURE_PROXY_KEY": KEY})
    assert plain._log is proxy_mod.emit_stdout
    p = build_proxy_from_env(
        {"CAPTURE_PROXY_KEY": KEY, "CAPTURE_PROXY_LOG_DIR": str(tmp_path)}
    )
    p._log(_rec(GOOD_ID))
    assert (tmp_path / f"{GOOD_ID}.jsonl").exists()
    assert _stdout_hosts(capsys) == ["example.com"]


# ── limits file (planning#317) ────────────────────────────────────────────────

DEFAULTS = proxy_mod.Limits(10, 30, 256)


def _doc(**kw) -> bytes:
    base = {"connect_timeout_s": 10, "idle_timeout_s": 30, "max_connections": 256, "version": 1}
    base.update(kw)
    return json.dumps(base).encode()


def _write_limits(path, **kw):
    """tmp + rename, as the backend does, so each write is a new inode."""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(_doc(**kw) + b"\n")
    os.replace(tmp, path)


def test_parse_limits_valid():
    got = proxy_mod.parse_limits(_doc(connect_timeout_s=7, idle_timeout_s=99, max_connections=5), DEFAULTS)
    assert got == proxy_mod.Limits(7, 99, 5)


@pytest.mark.parametrize(
    "field,value,expected",
    [
        ("connect_timeout_s", 0, 1),
        ("connect_timeout_s", 61, 60),
        ("idle_timeout_s", 1, 5),
        ("idle_timeout_s", 601, 600),
        ("max_connections", -3, 1),
        ("max_connections", 5000, 1024),
    ],
)
def test_parse_limits_clamps_each_field(field, value, expected):
    got = proxy_mod.parse_limits(_doc(**{field: value}), DEFAULTS)
    assert getattr(got, field) == expected
    for other in ("connect_timeout_s", "idle_timeout_s", "max_connections"):
        if other != field:
            assert getattr(got, other) == getattr(DEFAULTS, other)


@pytest.mark.parametrize("bad", [True, 1.5, "7", None, [1]])
@pytest.mark.parametrize("field", ["connect_timeout_s", "idle_timeout_s", "max_connections"])
def test_parse_limits_wrong_type_falls_back_per_field(field, bad):
    other = proxy_mod.Limits(10, 30, 256)
    doc = {"connect_timeout_s": 3, "idle_timeout_s": 40, "max_connections": 9, "version": 1}
    doc[field] = bad
    got = proxy_mod.parse_limits(json.dumps(doc).encode(), other)
    assert getattr(got, field) == getattr(other, field)
    for name, v in (("connect_timeout_s", 3), ("idle_timeout_s", 40), ("max_connections", 9)):
        if name != field:
            assert getattr(got, name) == v


def test_parse_limits_missing_field_uses_default():
    got = proxy_mod.parse_limits(b'{"version":1,"max_connections":4}', DEFAULTS)
    assert got == proxy_mod.Limits(10, 30, 4)


@pytest.mark.parametrize(
    "data",
    [b"not json", b"[1,2]", b"3", b'"x"', b"null", _doc(version=2), b'{"max_connections":4}',
     _doc(version=True), b"\xff\xfe{}", b""],
)
def test_parse_limits_bad_document_is_defaults(data):
    assert proxy_mod.parse_limits(data, DEFAULTS) == DEFAULTS


def test_limits_source_missing_file_is_defaults(tmp_path):
    src = proxy_mod.LimitsSource(str(tmp_path / "nope.json"), DEFAULTS)
    assert src.current() == DEFAULTS
    assert src.current() == DEFAULTS


def test_limits_source_picks_up_write_and_rename_replace(tmp_path):
    path = tmp_path / "proxy_limits.json"
    src = proxy_mod.LimitsSource(str(path), DEFAULTS)
    assert src.current() == DEFAULTS
    _write_limits(path, max_connections=3)
    assert src.current().max_connections == 3
    _write_limits(path, max_connections=4)  # same size, new inode
    assert src.current().max_connections == 4


def test_limits_source_does_not_reread_an_unchanged_file(tmp_path, monkeypatch):
    path = tmp_path / "proxy_limits.json"
    _write_limits(path, max_connections=3)
    opened = []
    real_open = os.open

    def spy(p, *a, **kw):
        opened.append(p)
        return real_open(p, *a, **kw)

    monkeypatch.setattr(proxy_mod.os, "open", spy)
    src = proxy_mod.LimitsSource(str(path), DEFAULTS)
    assert src.current().max_connections == 3
    assert len(opened) == 1  # the first call DID read (non-vacuous)
    for _ in range(5):
        assert src.current().max_connections == 3
    assert len(opened) == 1  # unchanged key: no read
    _write_limits(path, max_connections=4)
    assert src.current().max_connections == 4
    assert len(opened) == 2


def test_limits_source_retries_a_file_that_failed_to_read(tmp_path, monkeypatch):
    """A transient read failure (stat key unchanged) must not pin the defaults."""
    path = tmp_path / "proxy_limits.json"
    _write_limits(path, max_connections=3)
    real_open = os.open
    attempts = []

    def flaky(p, *a, **kw):
        attempts.append(p)
        if len(attempts) == 1:
            raise PermissionError(13, "transient")
        return real_open(p, *a, **kw)

    monkeypatch.setattr(proxy_mod.os, "open", flaky)
    src = proxy_mod.LimitsSource(str(path), DEFAULTS)
    assert src.current() == DEFAULTS
    assert len(attempts) == 1  # the read WAS attempted (non-vacuous)
    assert src.current().max_connections == 3  # same stat key, retried


def test_limits_source_symlink_is_defaults(tmp_path):
    real = tmp_path / "real.json"
    real.write_bytes(_doc(max_connections=3))
    link = tmp_path / "proxy_limits.json"
    link.symlink_to(real)
    assert proxy_mod.LimitsSource(str(link), DEFAULTS).current() == DEFAULTS


def test_limits_source_oversize_file_is_defaults(tmp_path):
    path = tmp_path / "proxy_limits.json"
    pad = " " * proxy_mod.LIMITS_FILE_MAX_BYTES
    path.write_bytes(_doc(max_connections=3) + pad.encode())
    assert proxy_mod.LimitsSource(str(path), DEFAULTS).current() == DEFAULTS


def test_limits_source_fifo_is_defaults_without_hanging(tmp_path):
    path = tmp_path / "proxy_limits.json"
    os.mkfifo(path)
    assert run(asyncio.to_thread(proxy_mod.LimitsSource(str(path), DEFAULTS).current)) == DEFAULTS


def test_limits_source_directory_never_raises(tmp_path):
    assert proxy_mod.LimitsSource(str(tmp_path), DEFAULTS).current() == DEFAULTS


def test_limits_source_logs_a_change_once_to_stderr(tmp_path, capsys):
    path = tmp_path / "proxy_limits.json"
    src = proxy_mod.LimitsSource(str(path), DEFAULTS)
    src.current()
    src.current()
    first = capsys.readouterr()
    assert first.out == ""
    assert first.err.count("limits source=default") == 1
    _write_limits(path, max_connections=3)
    src.current()
    src.current()
    second = capsys.readouterr()
    assert second.out == ""
    assert second.err.count("source=file") == 1 and "max_connections=3" in second.err
    # same effective values from a rewritten file: not a change, no line
    _write_limits(path, max_connections=3)
    src.current()
    assert capsys.readouterr().err == ""


async def _wait_active(proxy, n):
    for _ in range(200):
        if proxy._active == n:
            return
        await asyncio.sleep(0.025)
    assert proxy._active == n


def test_handle_capacity_follows_the_limits_file_without_restart(tmp_path):
    path = tmp_path / "proxy_limits.json"
    _write_limits(path, max_connections=1)
    src = proxy_mod.LimitsSource(str(path), DEFAULTS)

    async def go():
        async with Upstream("echo") as up:
            async with running(allowed_ports=frozenset({up.port}), limits=src) as (proxy, port, logs):
                r1, w1 = await asyncio.open_connection("127.0.0.1", port)
                await _wait_active(proxy, 1)
                resp = await exchange(port, connect_req("allowed.example", up.port, auth()))
                assert status(resp) == 503
                await wait_for_logs(logs)
                assert logs[0]["reason"] == "capacity"
                _write_limits(path, max_connections=2)
                r2, w2 = await asyncio.open_connection("127.0.0.1", port)
                w2.write(connect_req("allowed.example", up.port, auth()))
                head = await asyncio.wait_for(r2.readuntil(b"\r\n\r\n"), 5)
                assert head.startswith(b"HTTP/1.1 200")
                assert up.connections == 1
                w1.close()
                w2.close()

    run(go())


def test_handle_idle_timeout_comes_from_the_limits_file(tmp_path):
    path = tmp_path / "proxy_limits.json"
    # idle_timeout_s is clamped to >= 5 by parse_limits, so use the floor.
    _write_limits(path, idle_timeout_s=5)
    src = proxy_mod.LimitsSource(str(path), proxy_mod.Limits(10, 600, 256))

    async def go():
        async with Upstream("echo") as up:
            async with running(allowed_ports=frozenset({up.port}), limits=src) as (_p, port, logs):
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(connect_req("allowed.example", up.port, auth()))
                await reader.readuntil(b"\r\n\r\n")
                t0 = asyncio.get_running_loop().time()
                rest = await asyncio.wait_for(reader.read(), 15)
                assert rest == b""
                assert 4 <= asyncio.get_running_loop().time() - t0 < 12
                writer.close()

    run(go())


def test_in_flight_connection_keeps_its_starting_limits(tmp_path):
    path = tmp_path / "proxy_limits.json"
    _write_limits(path, idle_timeout_s=5)
    src = proxy_mod.LimitsSource(str(path), proxy_mod.Limits(10, 600, 256))

    async def go():
        async with Upstream("echo") as up:
            async with running(allowed_ports=frozenset({up.port}), limits=src) as (_p, port, logs):
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(connect_req("allowed.example", up.port, auth()))
                await reader.readuntil(b"\r\n\r\n")  # admitted under idle=5
                _write_limits(path, idle_timeout_s=600)  # raised after it started
                t0 = asyncio.get_running_loop().time()
                rest = await asyncio.wait_for(reader.read(), 15)
                assert rest == b""  # still closed at ~5s, not 600s
                assert asyncio.get_running_loop().time() - t0 < 12
                writer.close()

    run(go())


def test_build_proxy_from_env_wires_a_limits_source(tmp_path):
    p = tmp_path / "x.json"
    shipped = build_proxy_from_env({"CAPTURE_PROXY_KEY": KEY, "CAPTURE_LIMITS_FILE": str(p)})
    assert isinstance(shipped._limits_source, proxy_mod.LimitsSource)
    assert shipped._limits_source.path == str(p)
    assert shipped._limits_source.defaults == proxy_mod.Limits(
        proxy_mod.CONNECT_TIMEOUT_S, proxy_mod.IDLE_TIMEOUT_S, proxy_mod.MAX_CONNECTIONS
    )
    default = build_proxy_from_env({"CAPTURE_PROXY_KEY": KEY})
    assert default._limits_source.path == "/capture_config/proxy_limits.json"


# ── archive mode ──────────────────────────────────────────────────────────────
# The real ARCHIVE_PORT is 443, which a test upstream cannot bind. End-to-end
# tests therefore monkeypatch proxy_mod.ARCHIVE_PORT (read at call time by
# archive_allowed) and allowed_ports to the upstream's port; the host rules under
# test are the real ones. archive_allowed is also tested purely at real 443.


@pytest.mark.parametrize(
    "scheme,host,port,expected",
    [
        ("connect", "web.archive.org", 443, True),
        ("connect", "WEB.ARCHIVE.ORG", 443, True),
        ("http", "web.archive.org", 443, False),
        ("http", "web.archive.org", 80, False),
        ("connect", "web.archive.org", 80, False),
        ("connect", "web.archive.org", 8443, False),
        ("connect", "web.archive.org.", 443, False),
        ("connect", "web.archive.org.evil.test", 443, False),
        ("connect", "xweb.archive.org", 443, False),
        ("connect", "archive.org", 443, False),
        ("connect", "example.com", 443, False),
        ("connect", "1.2.3.4", 443, False),
        ("connect", "[::1]", 443, False),
        ("connect", "[2001:db8::1]", 443, False),
        ("connect", "", 443, False),
    ],
)
def test_archive_allowed_predicate(scheme, host, port, expected):
    assert proxy_mod.archive_allowed(scheme, host, port) is expected


def test_archive_literals_are_the_contract_values():
    assert proxy_mod.MODES == ("live", "archive")
    assert proxy_mod.ARCHIVE_HOSTS == frozenset({"web.archive.org"})
    assert proxy_mod.ARCHIVE_PORT == 443


def test_archive_connect_to_the_archive_host_reaches_decide_and_splices(monkeypatch):
    async def go():
        async with Upstream("echo") as up:
            monkeypatch.setattr(proxy_mod, "ARCHIVE_PORT", up.port)
            async with running(allowed_ports=frozenset({up.port})) as (_p, port, logs):
                for host in ("web.archive.org", "WEB.ARCHIVE.ORG"):
                    reader, writer = await asyncio.open_connection("127.0.0.1", port)
                    writer.write(connect_req(host, up.port, auth(mode="archive")))
                    await writer.drain()
                    head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
                    assert head.startswith(b"HTTP/1.1 200 Connection Established")
                    writer.write(b"hi")
                    await writer.drain()
                    assert await asyncio.wait_for(reader.readexactly(2), 5) == b"hi"
                    writer.close()
                await wait_for_logs(logs, 2)
                assert up.connections == 2
                for line in logs:
                    assert line["decision"] == "allow" and line["mode"] == "archive"
                    assert line["capture_id"] == CID and line["pinned_ip"] == "127.0.0.1"

    run(go())


_ARCHIVE_DENIED = [
    ("connect", "allowed.example", "other_host"),
    ("connect", "web.archive.org.evil.test", "suffix_tail"),
    ("connect", "xweb.archive.org", "prefix"),
    ("connect", "web.archive.org.", "trailing_dot"),
    ("connect", "127.0.0.1", "ip_literal"),
    ("connect", "[::1]", "ipv6_literal"),
    ("connect", "[::ffff:127.0.0.1]", "ipv6_mapped_literal"),
    ("http", "web.archive.org", "plain_http"),
]


@pytest.mark.parametrize(
    "shape,host", [(a, b) for a, b, _ in _ARCHIVE_DENIED], ids=[c for _, _, c in _ARCHIVE_DENIED]
)
def test_archive_mode_denies_everything_but_the_archive_host(shape, host, monkeypatch):
    async def go():
        async with Upstream("echo") as up:
            monkeypatch.setattr(proxy_mod, "ARCHIVE_PORT", up.port)
            async with running(allowed_ports=frozenset({up.port})) as (_p, port, logs):
                if shape == "connect":
                    payload = connect_req(host, up.port, auth(mode="archive"))
                else:
                    payload = get_req(f"http://{host}:{up.port}/", auth(mode="archive"))
                resp = await exchange(port, payload)
                await wait_for_logs(logs)
                assert status(resp) == 403
                assert header(resp, "X-Capture-Proxy-Reason") == "archive_host"
                (line,) = logs
                assert line["decision"] == "deny" and line["reason"] == "archive_host"
                assert line["mode"] == "archive" and line["capture_id"] == CID
                assert line["pinned_ip"] is None and line["resolved"] == []
                assert up.connections == 0

    run(go())


def test_archive_connect_on_a_non_archive_port_is_denied(monkeypatch):
    async def go():
        async with Upstream("echo") as up:
            monkeypatch.setattr(proxy_mod, "ARCHIVE_PORT", up.port + 1)
            async with running(allowed_ports=frozenset({up.port})) as (_p, port, logs):
                resp = await exchange(
                    port, connect_req("web.archive.org", up.port, auth(mode="archive"))
                )
                await wait_for_logs(logs)
                assert status(resp) == 403
                assert logs[0]["reason"] == "archive_host" and up.connections == 0

    run(go())


@pytest.mark.parametrize("shape", ["connect", "http"])
def test_live_mode_to_the_same_non_archive_host_is_allowed(shape, monkeypatch):
    """Precondition for the deny matrix above: identical harness and request,
    only the mode differs, and live reaches the upstream."""

    async def go():
        async with Upstream("echo" if shape == "connect" else "http") as up:
            monkeypatch.setattr(proxy_mod, "ARCHIVE_PORT", up.port)
            async with running(allowed_ports=frozenset({up.port})) as (_p, port, logs):
                if shape == "connect":
                    reader, writer = await asyncio.open_connection("127.0.0.1", port)
                    writer.write(connect_req("allowed.example", up.port, auth(mode="live")))
                    await writer.drain()
                    head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
                    assert head.startswith(b"HTTP/1.1 200")
                    writer.close()
                else:
                    resp = await exchange(
                        port, get_req(f"http://allowed.example:{up.port}/", auth(mode="live"))
                    )
                    assert status(resp) == 200
                await wait_for_logs(logs)
                assert logs[0]["decision"] == "allow" and logs[0]["mode"] == "live"
                assert up.connections == 1

    run(go())


def test_archive_allowed_request_still_goes_through_the_blocklist(monkeypatch):
    """decide() runs after the archive policy: an archive host that resolved to a
    private address is still refused (DNS pinning + blocklist unchanged)."""

    async def go():
        async with Upstream("echo") as up:
            monkeypatch.setattr(proxy_mod, "ARCHIVE_PORT", up.port)

            async def resolver(host, port):
                return ["10.0.0.5"]

            async with running(
                allowed_ports=frozenset({up.port}), resolver=resolver
            ) as (_p, port, logs):
                resp = await exchange(
                    port, connect_req("web.archive.org", up.port, auth(mode="archive"))
                )
                await wait_for_logs(logs)
                assert status(resp) == 403
                assert logs[0]["reason"] == "all_blocked" and up.connections == 0

    run(go())
