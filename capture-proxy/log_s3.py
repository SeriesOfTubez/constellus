"""S3 mode of the capture proxy's per-capture log (planning#318 S1c).

S3 has no append, so each capture's records are buffered in memory and the
whole object `proxylog/<capture_id>.jsonl` is PUT (overwrite) about one second
after the last record, immediately when the byte cap is reached, and on
shutdown. The proxy's key is PUT-only on the proxylog bucket: this module calls
`put_object` and nothing else. Nothing here may raise into the proxy: a failed
PUT is logged (error code only, never credentials or the response body) and
retried at the next record or at shutdown. stdout always has every record.

Does not import `proxy`; `proxy` imports this lazily so filesystem mode never
loads botocore.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
import uuid
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import botocore.session
from botocore.config import Config
from botocore.exceptions import ClientError

LOG_MAX_BYTES = 4 * 1024 * 1024  # == proxy.LOG_FILE_MAX_BYTES (a test asserts)
DEBOUNCE_S = 1.0
MAX_BUFFERS = 16
BUFFER_TTL_S = 3900  # == proxy.MAX_CREDENTIAL_TTL_S (a test asserts)
KEY_PREFIX = "proxylog/"
_WARNED_MAX = 256


class S3ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class S3LogConfig:
    endpoint: str
    region: str
    access_key: str | None
    secret_key: str | None
    path_style: bool
    bucket: str


def config_from_env(env=os.environ) -> S3LogConfig:
    endpoint = (env.get("CAPTURE_S3_ENDPOINT") or "").strip()
    if not endpoint:
        raise S3ConfigError("CAPTURE_S3_ENDPOINT is required when CAPTURE_STORE=s3")
    parts = urlsplit(endpoint)
    insecure = env.get("CAPTURE_S3_INSECURE_HTTP") == "1"
    if parts.scheme != "https" and not (parts.scheme == "http" and insecure):
        raise S3ConfigError(
            "CAPTURE_S3_ENDPOINT must be an https URL (http only with CAPTURE_S3_INSECURE_HTTP=1)"
        )
    if not parts.netloc or "@" in parts.netloc:
        raise S3ConfigError("CAPTURE_S3_ENDPOINT must have a host and no embedded credentials")
    access = env.get("CAPTURE_S3_ACCESS_KEY") or None
    secret = env.get("CAPTURE_S3_SECRET_KEY") or None
    if (access is None) != (secret is None):
        raise S3ConfigError(
            "CAPTURE_S3_ACCESS_KEY and CAPTURE_S3_SECRET_KEY must be set together or not at all"
        )
    ps = env.get("CAPTURE_S3_PATH_STYLE", "true")
    if ps not in ("true", "false"):
        raise S3ConfigError("CAPTURE_S3_PATH_STYLE must be true or false")
    bucket = (env.get("CAPTURE_S3_BUCKET_PROXYLOG") or "").strip()
    if not bucket:
        raise S3ConfigError("CAPTURE_S3_BUCKET_PROXYLOG is required when CAPTURE_STORE=s3")
    return S3LogConfig(
        endpoint=endpoint,
        region=env.get("CAPTURE_S3_REGION") or "us-east-1",
        access_key=access,
        secret_key=secret,
        path_style=ps == "true",
        bucket=bucket,
    )


def make_client(cfg: S3LogConfig):
    return botocore.session.get_session().create_client(
        "s3",
        endpoint_url=cfg.endpoint,
        region_name=cfg.region,
        aws_access_key_id=cfg.access_key,
        aws_secret_access_key=cfg.secret_key,
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "path" if cfg.path_style else "virtual"},
            connect_timeout=5,
            read_timeout=30,
            retries={"mode": "standard", "max_attempts": 3},
        ),
    )


def canonical_uuid(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 36:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False


@dataclass
class _Buffer:
    lines: list[bytes] = field(default_factory=list)
    size: int = 0
    full: bool = False
    dirty: bool = False
    last: float = 0.0
    handle: asyncio.TimerHandle | None = None
    task: asyncio.Task | None = None


def _err(msg: str) -> None:
    try:
        print(f"capture-proxy: {msg}", file=sys.stderr, flush=True)
    except Exception:  # noqa: BLE001 - logging must never raise into the proxy
        pass


class S3LogSink:
    def __init__(
        self,
        client,
        bucket: str,
        *,
        debounce_s: float = DEBOUNCE_S,
        max_bytes: int = LOG_MAX_BYTES,
        max_buffers: int = MAX_BUFFERS,
        ttl_s: float = BUFFER_TTL_S,
        clock=time.monotonic,
    ) -> None:
        self._c = client
        self._bucket = bucket
        self._debounce_s = debounce_s
        self._max_bytes = max_bytes
        self._max_buffers = max_buffers
        self._ttl_s = ttl_s
        self._clock = clock
        self._buffers: dict[str, _Buffer] = {}
        self._warned: set[str] = set()

    def add(self, record: dict) -> None:
        try:
            self._add(record)
        except Exception as exc:  # noqa: BLE001 - never raise into the proxy
            _err(f"proxy log sink error: {type(exc).__name__}")

    def _add(self, record: dict) -> None:
        cid = record.get("capture_id")
        if not canonical_uuid(cid):
            return
        now = self._clock()
        self._evict(now)
        buf = self._buffers.get(cid)
        if buf is None:
            if len(self._buffers) >= self._max_buffers:
                if cid not in self._warned:
                    if len(self._warned) >= _WARNED_MAX:
                        self._warned.clear()
                    self._warned.add(cid)
                    _err(f"proxy log buffers full; {cid} goes to stdout only")
                return
            buf = self._buffers[cid] = _Buffer()
        line = json.dumps(record, separators=(",", ":")).encode() + b"\n"
        buf.last = now
        if buf.full:
            return
        if buf.size + len(line) > self._max_bytes:
            buf.full = True
            if buf.dirty:
                self._schedule(cid, immediate=True)
            return
        buf.lines.append(line)
        buf.size += len(line)
        buf.dirty = True
        self._schedule(cid, immediate=False)

    def _schedule(self, cid: str, immediate: bool) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            self._flush_sync(cid)
            return
        buf = self._buffers[cid]
        if immediate:
            if buf.handle is not None:
                buf.handle.cancel()
                buf.handle = None
            self._start(cid)
        elif buf.handle is None:
            buf.handle = loop.call_later(self._debounce_s, self._start, cid)

    def _start(self, cid: str) -> None:
        buf = self._buffers.get(cid)
        if buf is None:
            return
        buf.handle = None
        if buf.task is None or buf.task.done():
            buf.task = asyncio.get_running_loop().create_task(self._flush(cid))

    async def _flush(self, cid: str) -> None:
        buf = self._buffers.get(cid)
        if buf is None:
            return
        loop = asyncio.get_running_loop()
        while buf.dirty:
            buf.dirty = False
            body = b"".join(buf.lines)
            ok = await loop.run_in_executor(None, self._put, cid, body)
            if not ok:
                buf.dirty = True  # retried on the next add() or close()
                break

    def _put(self, cid: str, body: bytes) -> bool:
        try:
            self._c.put_object(
                Bucket=self._bucket,
                Key=f"{KEY_PREFIX}{cid}.jsonl",
                Body=body,
                ContentType="application/x-ndjson",
            )
            return True
        except Exception as exc:  # noqa: BLE001 - a failed PUT must never kill the flush task
            code = None
            if isinstance(exc, ClientError):
                code = exc.response.get("Error", {}).get("Code")
            _err(f"proxy log upload failed for {cid}: {code or type(exc).__name__}")
            return False

    def _flush_sync(self, cid: str) -> None:
        buf = self._buffers[cid]
        buf.dirty = False
        if not self._put(cid, b"".join(buf.lines)):
            buf.dirty = True

    def _evict(self, now: float) -> None:
        for cid in [
            c
            for c, b in self._buffers.items()
            if now - b.last > self._ttl_s and (b.task is None or b.task.done())
        ]:
            buf = self._buffers.pop(cid)
            if buf.handle is not None:
                buf.handle.cancel()
            if buf.dirty:
                _err(f"proxy log for {cid} never uploaded; dropped (stdout has it)")

    async def close(self) -> None:
        for buf in self._buffers.values():
            if buf.handle is not None:
                buf.handle.cancel()
                buf.handle = None
        for cid, buf in list(self._buffers.items()):
            try:
                if buf.task is not None and not buf.task.done():
                    await buf.task
                if buf.dirty:
                    await self._flush(cid)
            except Exception as exc:  # noqa: BLE001 - shutdown must finish
                _err(f"proxy log flush at shutdown failed for {cid}: {type(exc).__name__}")

    def pending(self) -> int:
        return sum(1 for b in self._buffers.values() if b.dirty)
