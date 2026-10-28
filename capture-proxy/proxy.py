"""capture-proxy — the egress security boundary for headless page capture.

(planning#280 S5b-1)

A headless Chromium (a separate container on an `internal: true` Docker network
with NO route out) can reach the world only through this proxy. This process is
therefore the boundary, and it does four things the browser must never be
trusted to do:

  1. Authenticate every request (`Proxy-Authorization: Basic capture_id:token`).
  2. Resolve every requested host ITSELF and refuse blocked / private /
     link-local / metadata addresses, using the repo's `ip_blocklist` (the third
     byte-identical copy; `tests/test_blocklist_parity.py` is the drift alarm).
  3. PIN the upstream connection to an address it validated. It never resolves a
     host twice for one request, so a DNS-rebind answer cannot swap a public
     address for an internal one between check and use.
  4. Log every request as one JSON line on stdout, denials and auth failures
     included — the log is data, not diagnostics.

No TLS interception: HTTPS is a plain CONNECT tunnel and the browser does TLS end
to end. No caching, no keep-alive (exactly one request per client connection), no
upstream proxy, no control endpoint.

Stdlib + h11 only.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import hmac
import ipaddress
import json
import os
import re
import signal
import socket
import sys
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit

import h11

import ip_blocklist

# ── Limits ────────────────────────────────────────────────────────────────────
# First slice: module constants, pending promotion to admin settings
# (planning#317). ALLOWED_PORTS is deliberately NOT in that list: it is
# a guard, not a tunable, and stays a constant.
CONNECT_TIMEOUT_S = 10
IDLE_TIMEOUT_S = 30  # no bytes in either direction for this long -> close
MAX_CONNECTIONS = 256  # concurrent client connections; beyond -> 503
MAX_HEAD_BYTES = 16 * 1024  # request head cap (h11 max_incomplete_event_size)

ALLOWED_PORTS = frozenset({80, 443})

_CAPTURE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_HOP_BY_HOP = frozenset(
    {b"connection", b"keep-alive", b"te", b"trailer", b"upgrade", b"proxy-connection"}
)

Resolver = Callable[[str, int], Awaitable[list[str]]]


# ── Decision ──────────────────────────────────────────────────────────────────


@dataclass
class Decision:
    allowed: bool
    reason: str | None = None
    candidates: list[str] = field(default_factory=list)  # connectable, in order
    resolved: list[str] = field(default_factory=list)  # everything DNS returned


async def default_resolver(host: str, port: int) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(
        host, port, type=socket.SOCK_STREAM
    )
    return [info[4][0] for info in infos]


def _valid_hostname(host: str) -> str | None:
    """Return the lowercased hostname if it is plain ASCII LDH, else None."""
    if not host.isascii():
        return None
    host = host.lower()
    if host.endswith("."):
        host = host[:-1]
    if not host or len(host) > 253:
        return None
    for label in host.split("."):
        if not _LABEL_RE.match(label):
            return None
    return host


async def decide(
    host: str,
    port: int,
    *,
    is_blocked: Callable[[ipaddress.IPv4Address | ipaddress.IPv6Address], bool],
    resolver: Resolver,
    allowed_ports: frozenset[int],
    resolve_timeout_s: float = CONNECT_TIMEOUT_S,
) -> Decision:
    """Decide whether (host, port) may be connected to, and to which addresses.

    Pure apart from the injected `resolver`. Called exactly once per request."""
    if port not in allowed_ports:
        return Decision(False, "port")

    bare = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        literal = ipaddress.ip_address(bare)
    except ValueError:
        literal = None
    if literal is not None:
        if is_blocked(literal):
            return Decision(False, "blocked_literal", resolved=[str(literal)])
        return Decision(True, None, [str(literal)], [str(literal)])

    name = _valid_hostname(bare)
    if name is None:
        return Decision(False, "bad_host")
    try:
        resolved = await asyncio.wait_for(resolver(name, port), resolve_timeout_s)
    except (OSError, asyncio.TimeoutError):  # socket.gaierror is an OSError
        return Decision(False, "dns_failed")
    if not resolved:
        return Decision(False, "dns_failed")

    candidates: list[str] = []
    for addr in resolved:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue  # never a candidate: we cannot classify it
        text = str(ip)
        if not is_blocked(ip) and text not in candidates:
            candidates.append(text)
    if not candidates:
        return Decision(False, "all_blocked", resolved=list(resolved))
    return Decision(True, None, candidates, list(resolved))


# ── Logging ───────────────────────────────────────────────────────────────────


def emit_stdout(record: dict) -> None:
    """One JSON object per line on stdout, flushed. Nothing else is written to
    stdout; diagnostics go to stderr."""
    print(json.dumps(record, separators=(",", ":")), flush=True)


LOG_FILE_MAX_BYTES = 4 * 1024 * 1024  # per-capture proxy log cap (capture-spool.md)


def _canonical_uuid(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 36:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False


def append_capture_log(log_dir: str, record: dict) -> bool:
    """Append `record` to `<log_dir>/<capture_id>.jsonl`. Returns True if written.

    Only for a canonical lowercase-UUID capture_id (it becomes a path component),
    never follows a symlink at the target (O_NOFOLLOW), skips once the file is
    at the cap, and swallows every OSError: the stdout log is the fallback and
    the proxy must never crash because the spool volume misbehaves."""
    capture_id = record.get("capture_id")
    if not _canonical_uuid(capture_id):
        return False
    path = os.path.join(log_dir, f"{capture_id}.jsonl")
    line = (json.dumps(record, separators=(",", ":")) + "\n").encode()
    try:
        fd = os.open(
            path,
            os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o660,
        )
    except OSError:
        return False
    try:
        if os.fstat(fd).st_size >= LOG_FILE_MAX_BYTES:
            return False
        os.write(fd, line)
        return True
    except OSError:
        return False
    finally:
        os.close(fd)


def make_log(log_dir: str | None) -> Callable[[dict], None]:
    """stdout always; additionally the per-capture file when `log_dir` is set."""
    if not log_dir:
        return emit_stdout

    def log(record: dict) -> None:
        emit_stdout(record)
        append_capture_log(log_dir, record)

    return log


class _Rec:
    """Accumulates the fields of one request; emitted once, when it ends."""

    def __init__(self) -> None:
        self.start = time.monotonic()
        self.capture_id: str | None = None
        self.method: str | None = None
        self.scheme: str | None = None
        self.host: str | None = None
        self.port: int | None = None
        self.resolved: list[str] = []
        self.pinned_ip: str | None = None
        self.decision = "deny"
        self.reason: str | None = None
        self.bytes_up = 0
        self.bytes_down = 0
        self.emit = True  # False: nothing was ever received, so no request exists

    def as_dict(self) -> dict:
        return {
            "ts": datetime.now(timezone.utc).isoformat(),
            "capture_id": self.capture_id,
            "method": self.method,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "resolved": self.resolved,
            "pinned_ip": self.pinned_ip,
            "decision": self.decision,
            "reason": self.reason,
            "bytes_up": self.bytes_up,
            "bytes_down": self.bytes_down,
            "duration_ms": int((time.monotonic() - self.start) * 1000),
        }


class _BadRequest(Exception):
    pass


@dataclass
class _Target:
    scheme: str  # connect | http
    host: str
    port: int
    origin: bytes = b"/"  # origin-form request target (http only)
    authority: bytes = b""  # Host header value (http only)


def _split_authority(text: str) -> tuple[str, int]:
    """Parse `host:port` / `[v6]:port` (CONNECT target). Port is required."""
    if text.startswith("["):
        end = text.find("]")
        if end == -1 or text[end + 1 : end + 2] != ":":
            raise _BadRequest("authority")
        host, port_s = text[: end + 1], text[end + 2 :]
    else:
        host, sep, port_s = text.rpartition(":")
        if not sep or not host or ":" in host:
            raise _BadRequest("authority")
    if not port_s.isascii() or not port_s.isdigit() or not 0 < int(port_s) < 65536:
        raise _BadRequest("port")
    return host, int(port_s)


def _parse_target(request: h11.Request) -> _Target:
    try:
        target = request.target.decode("ascii")
    except UnicodeDecodeError:
        raise _BadRequest("non-ascii target") from None
    method = request.method.upper()
    if method == b"CONNECT":
        host, port = _split_authority(target)
        return _Target("connect", host, port)
    if not target[:7].lower() == "http://":
        raise _BadRequest("not absolute-form http")
    try:
        parts = urlsplit(target)
        host, port = parts.hostname, parts.port
    except ValueError:
        raise _BadRequest("bad url") from None
    if not host or "@" in parts.netloc:
        raise _BadRequest("bad authority")
    origin = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    return _Target(
        "http",
        host,
        port if port is not None else 80,
        origin.encode("ascii"),
        parts.netloc.encode("ascii"),
    )


# ── Proxy ─────────────────────────────────────────────────────────────────────


class Proxy:
    def __init__(
        self,
        *,
        token: str,
        # Production defaults. Tests override these; tests/test_proxy.py asserts
        # that what ships is literally ip_blocklist.is_blocked / ALLOWED_PORTS.
        is_blocked=ip_blocklist.is_blocked,
        resolver: Resolver = default_resolver,
        allowed_ports: frozenset[int] = ALLOWED_PORTS,
        max_connections: int = MAX_CONNECTIONS,
        idle_timeout_s: float = IDLE_TIMEOUT_S,
        connect_timeout_s: float = CONNECT_TIMEOUT_S,
        log: Callable[[dict], None] = emit_stdout,
    ) -> None:
        if not token:
            raise ValueError("token must be non-empty")
        self._token = token.encode()
        self.is_blocked = is_blocked
        self.resolver = resolver
        self.allowed_ports = allowed_ports
        self.max_connections = max_connections
        self.idle_timeout_s = idle_timeout_s
        self.connect_timeout_s = connect_timeout_s
        self._log = log
        self._active = 0

    async def decide(self, host: str, port: int) -> Decision:
        return await decide(
            host,
            port,
            is_blocked=self.is_blocked,
            resolver=self.resolver,
            allowed_ports=self.allowed_ports,
            resolve_timeout_s=self.connect_timeout_s,
        )

    # -- auth ------------------------------------------------------------------

    def _authenticate(self, request: h11.Request) -> str | None:
        """Return the capture_id if the request is authenticated, else None."""
        header = None
        for name, value in request.headers:
            if name == b"proxy-authorization":
                header = value
                break
        capture_id, token = "", b""
        ok = False
        if header is not None:
            scheme, _, b64 = header.decode("latin-1").partition(" ")
            if scheme.lower() == "basic":
                try:
                    raw = base64.b64decode(b64.strip(), validate=True)
                    cid, sep, tok = raw.partition(b":")
                    capture_id, token = cid.decode("ascii"), tok
                    ok = bool(sep)
                except (binascii.Error, UnicodeDecodeError):
                    ok = False
        token_ok = hmac.compare_digest(token, self._token)
        if ok and token_ok and _CAPTURE_ID_RE.match(capture_id):
            return capture_id
        return None

    # -- connection handler ------------------------------------------------------

    async def handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        rec = _Rec()
        if self._active >= self.max_connections:
            rec.reason = "capacity"
            await self._respond(reader, writer, 503, "Service Unavailable", rec.reason)
            self._log(rec.as_dict())
            await _close(writer)
            return
        self._active += 1
        try:
            await self._serve(reader, writer, rec)
        except Exception as exc:
            print(f"capture-proxy: internal error: {exc!r}", file=sys.stderr, flush=True)
            if rec.decision == "deny" and rec.reason is None:
                rec.decision, rec.reason = "error", "internal"
        finally:
            self._active -= 1
            if rec.emit:
                self._log(rec.as_dict())
            await _close(writer)

    async def _read_head(
        self, reader: asyncio.StreamReader, conn: h11.Connection, rec: _Rec
    ) -> h11.Request:
        got_bytes = False
        while True:
            try:
                event = conn.next_event()
            except h11.ProtocolError:
                raise _BadRequest("protocol") from None
            if event is h11.NEED_DATA:
                try:
                    data = await asyncio.wait_for(reader.read(65536), self.idle_timeout_s)
                except asyncio.TimeoutError:
                    data = b""
                if not data:
                    if not got_bytes:
                        rec.emit = False  # a bare TCP probe is not a request
                    raise _BadRequest("incomplete")
                got_bytes = True
                conn.receive_data(data)
            elif isinstance(event, h11.Request):
                return event
            else:
                raise _BadRequest("unexpected event")

    async def _serve(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, rec: _Rec
    ) -> None:
        conn = h11.Connection(h11.SERVER, max_incomplete_event_size=MAX_HEAD_BYTES)
        try:
            request = await self._read_head(reader, conn, rec)
        except _BadRequest:
            rec.reason = "bad_request"
            if rec.emit:
                await self._respond(reader, writer, 400, "Bad Request", rec.reason)
            return

        rec.method = request.method.decode("ascii", "replace")
        try:
            target: _Target | None = _parse_target(request)
        except _BadRequest:
            target = None
        if target is not None:
            rec.scheme, rec.host, rec.port = target.scheme, target.host.strip("[]"), target.port

        capture_id = self._authenticate(request)
        if capture_id is None:
            rec.reason = "auth"
            await self._respond(
                reader,
                writer,
                407,
                "Proxy Authentication Required",
                rec.reason,
                [(b"Proxy-Authenticate", b'Basic realm="capture"')],
            )
            return
        rec.capture_id = capture_id

        if target is None:
            rec.reason = "bad_request"
            await self._respond(reader, writer, 400, "Bad Request", rec.reason)
            return

        decision = await self.decide(target.host, target.port)
        rec.resolved = decision.resolved
        if not decision.allowed:
            rec.reason = decision.reason
            await self._respond(reader, writer, 403, "Forbidden", rec.reason or "denied")
            return

        # Pin: first candidate that connects. Never resolve again.
        upstream = None
        for ip in decision.candidates:
            try:
                upstream = await asyncio.wait_for(
                    asyncio.open_connection(ip, target.port), self.connect_timeout_s
                )
            except (OSError, asyncio.TimeoutError):
                continue
            rec.pinned_ip = ip
            break
        if upstream is None:
            rec.decision, rec.reason = "error", "connect_failed"
            await self._respond(reader, writer, 502, "Bad Gateway", rec.reason)
            return

        up_reader, up_writer = upstream
        rec.decision = "allow"
        try:
            if target.scheme == "connect":
                await self._tunnel(reader, writer, up_reader, up_writer, conn, rec)
            else:
                await self._forward(reader, writer, up_reader, up_writer, conn, request, target, rec)
        except (OSError, h11.ProtocolError):
            pass  # peer reset mid-flight: the request was allowed; bytes are logged
        finally:
            await _close(up_writer)

    # -- CONNECT -----------------------------------------------------------------

    async def _tunnel(self, reader, writer, up_reader, up_writer, conn, rec: _Rec) -> None:
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        leftover, _closed = conn.trailing_data
        if leftover:
            up_writer.write(leftover)
            rec.bytes_up += len(leftover)
            await up_writer.drain()

        last = time.monotonic()

        async def pump(src, dst, up: bool) -> None:
            nonlocal last
            while True:
                data = await src.read(65536)
                if not data:
                    return
                last = time.monotonic()
                dst.write(data)
                await dst.drain()
                if up:
                    rec.bytes_up += len(data)
                else:
                    rec.bytes_down += len(data)

        tasks = {
            asyncio.ensure_future(pump(reader, up_writer, True)),
            asyncio.ensure_future(pump(up_reader, writer, False)),
        }
        try:
            while True:
                remaining = last + self.idle_timeout_s - time.monotonic()
                if remaining <= 0:
                    break
                done, _pending = await asyncio.wait(
                    tasks, timeout=remaining, return_when=asyncio.FIRST_COMPLETED
                )
                if done:
                    break
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    # -- absolute-form HTTP --------------------------------------------------------

    async def _forward(
        self, reader, writer, up_reader, up_writer, conn, request, target: _Target, rec: _Rec
    ) -> None:
        listed = set()
        for name, value in request.headers:
            if name == b"connection":
                listed.update(t.strip().lower() for t in value.split(b",") if t.strip())
        head = [request.method + b" " + target.origin + b" HTTP/1.1"]
        for name, value in request.headers:
            if (
                name in _HOP_BY_HOP
                or name in listed
                or name.startswith(b"proxy-")
                or name == b"host"
            ):
                continue
            head.append(name + b": " + value)
        head.append(b"Host: " + target.authority)
        head.append(b"Connection: close")
        blob = b"\r\n".join(head) + b"\r\n\r\n"
        up_writer.write(blob)
        rec.bytes_up += len(blob)

        chunked = any(
            n == b"transfer-encoding" and b"chunked" in v.lower() for n, v in request.headers
        )
        while True:
            event = conn.next_event()
            if event is h11.NEED_DATA:
                try:
                    data = await asyncio.wait_for(reader.read(65536), self.idle_timeout_s)
                except asyncio.TimeoutError:
                    return
                if not data:
                    return  # client went away mid-request
                conn.receive_data(data)
            elif isinstance(event, h11.Data):
                payload = bytes(event.data)
                out = (b"%x\r\n" % len(payload)) + payload + b"\r\n" if chunked else payload
                up_writer.write(out)
                rec.bytes_up += len(out)
                await up_writer.drain()
            elif isinstance(event, h11.EndOfMessage):
                if chunked:
                    up_writer.write(b"0\r\n\r\n")
                    rec.bytes_up += 5
                await up_writer.drain()
                break
            else:
                return

        while True:
            try:
                data = await asyncio.wait_for(up_reader.read(65536), self.idle_timeout_s)
            except asyncio.TimeoutError:
                return
            if not data:
                return
            writer.write(data)
            rec.bytes_down += len(data)
            await writer.drain()

    # -- responses -----------------------------------------------------------------

    async def _respond(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        status: int,
        phrase: str,
        reason: str,
        extra: list[tuple[bytes, bytes]] | None = None,
    ) -> None:
        body = f"capture-proxy: {reason}\n".encode()
        lines = [
            f"HTTP/1.1 {status} {phrase}".encode(),
            b"Content-Type: text/plain",
            b"Content-Length: " + str(len(body)).encode(),
            b"Connection: close",
            b"X-Capture-Proxy-Reason: " + reason.encode(),
        ]
        lines += [n + b": " + v for n, v in (extra or [])]
        with contextlib.suppress(OSError, asyncio.TimeoutError):
            writer.write(b"\r\n".join(lines) + b"\r\n\r\n" + body)
            await writer.drain()
            # Half-close, then swallow whatever the client was still sending
            # (briefly, bounded). Closing with unread input makes the kernel
            # send RST, which can destroy the response before the client reads it.
            writer.write_eof()
            await asyncio.wait_for(_discard(reader), 1)


async def _discard(reader: asyncio.StreamReader, limit: int = 1 << 20) -> None:
    seen = 0
    while seen < limit:
        data = await reader.read(65536)
        if not data:
            return
        seen += len(data)


async def _close(writer: asyncio.StreamWriter) -> None:
    with contextlib.suppress(OSError, asyncio.TimeoutError):
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), 5)


# ── Startup ───────────────────────────────────────────────────────────────────


def build_proxy_from_env(env=os.environ) -> Proxy:
    """Fail closed: no token, no proxy."""
    token = env.get("CAPTURE_PROXY_TOKEN", "")
    if not token:
        raise SystemExit(
            "capture-proxy: CAPTURE_PROXY_TOKEN is unset or empty; refusing to start"
        )
    return Proxy(token=token, log=make_log(env.get("CAPTURE_PROXY_LOG_DIR")))


async def serve(proxy: Proxy, host: str, port: int) -> asyncio.Server:
    return await asyncio.start_server(proxy.handle, host, port)


async def _main() -> None:
    proxy = build_proxy_from_env()
    port = int(os.environ.get("CAPTURE_PROXY_PORT", "3128"))
    server = await serve(proxy, "0.0.0.0", port)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    print(f"capture-proxy: listening on :{port}", file=sys.stderr, flush=True)
    async with server:
        await stop.wait()


if __name__ == "__main__":
    asyncio.run(_main())
