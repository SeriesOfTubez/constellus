"""Keyless GCS access for the capture worker and the capture proxy (planning#322 2b-3).

THIS FILE EXISTS TWICE, byte for byte: `capture-browser/capture/store_auth.py` and
`capture-proxy/store_auth.py` (separate Docker build contexts cannot share a file).
`tests/test_store_auth_parity.py`, identical in both suites, fails on any drift.
It imports nothing from either package: stdlib + botocore only.

In `CAPTURE_S3_AUTH=gcs-wi` mode the pod talks to https://storage.googleapis.com with an
UNSIGNED botocore client and an `Authorization: Bearer` header added by a before-send
hook. The bearer comes from a small JSON file the backend publishes (a Kubernetes Secret
mounted as a directory). The file is stat'ed on EVERY request and re-read only when it
changed; its expiry is checked on every request. A missing, expired or unreadable file
fails THAT request; it never falls back to keys, env or the metadata server.
"""

from __future__ import annotations

import json
import os
import re
import stat as _stat
import sys
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

import botocore
import botocore.session
from botocore.config import Config
from botocore.exceptions import BotoCoreError

GCS_ENDPOINT = "https://storage.googleapis.com"
GCS_HOST = "storage.googleapis.com"
AUTH_MODES = ("sigv4", "gcs-wi")
ACCESS_FILE_MAX_BYTES = 16384
EXPIRY_SLACK_S = 30  # a request must not start on a credential about to die in flight
_TOKEN_MAX = 8192
_BOUNDARY_MAX = 128
_EXPIRES_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class AuthConfigError(ValueError):
    """A CAPTURE_S3_* auth variable is missing or malformed (the message names it, never a value)."""


class EndpointRefused(BotoCoreError):
    fmt = "capture store: request refused: not the pinned GCS endpoint"


class AccessUnavailable(BotoCoreError):
    fmt = "capture store: no usable store access file"


def auth_from_env(env, *, endpoint: str, path_style: bool, allow_http: bool,
                  has_keys: bool) -> tuple[str, str | None]:
    """(mode, access_file_path). Mirrors the backend's gcs-wi refusals."""
    mode = (env.get("CAPTURE_S3_AUTH") or "sigv4").strip().lower() or "sigv4"
    if mode not in AUTH_MODES:
        raise AuthConfigError("CAPTURE_S3_AUTH must be sigv4 or gcs-wi")
    path = env.get("CAPTURE_S3_TOKEN_FILE") or ""
    if mode == "sigv4":
        if path:
            raise AuthConfigError("CAPTURE_S3_TOKEN_FILE must be unset unless CAPTURE_S3_AUTH=gcs-wi")
        return "sigv4", None
    if endpoint != GCS_ENDPOINT:
        raise AuthConfigError(f"CAPTURE_S3_ENDPOINT must be exactly {GCS_ENDPOINT} when CAPTURE_S3_AUTH=gcs-wi")
    if has_keys:
        raise AuthConfigError(
            "CAPTURE_S3_ACCESS_KEY / CAPTURE_S3_SECRET_KEY must be unset when CAPTURE_S3_AUTH=gcs-wi")
    if not path_style:
        raise AuthConfigError("CAPTURE_S3_PATH_STYLE must be true when CAPTURE_S3_AUTH=gcs-wi")
    if allow_http:
        raise AuthConfigError("CAPTURE_S3_INSECURE_HTTP must not be 1 when CAPTURE_S3_AUTH=gcs-wi")
    if not path:
        raise AuthConfigError("CAPTURE_S3_TOKEN_FILE is required when CAPTURE_S3_AUTH=gcs-wi")
    if not os.path.isabs(path):
        raise AuthConfigError("CAPTURE_S3_TOKEN_FILE must be an absolute path")
    return "gcs-wi", path


def _parse(raw: bytes) -> tuple[str, float]:
    """(bearer, expires_epoch) or ValueError. Never carries the content in its message."""
    try:
        obj = json.loads(raw)
    except (ValueError, RecursionError):
        raise ValueError("json") from None
    if not isinstance(obj, dict):
        raise ValueError("shape")
    bearer, expires, boundary = obj.get("token"), obj.get("expires_at"), obj.get("boundary")
    if (
        not isinstance(bearer, str)
        or not 1 <= len(bearer) <= _TOKEN_MAX
        or any(not 0x21 <= ord(ch) <= 0x7E for ch in bearer)  # no space/CR/LF: header injection
    ):
        raise ValueError("shape")
    if not isinstance(expires, str) or not _EXPIRES_RE.match(expires):
        raise ValueError("shape")
    if not isinstance(boundary, str) or len(boundary) > _BOUNDARY_MAX:
        raise ValueError("shape")
    try:
        when = datetime.strptime(expires, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise ValueError("shape") from None
    return bearer, when.timestamp()


class AccessFile:
    """The backend-published access file. Thread-safe; `stat` follows symlinks (kubelet mounts)."""

    def __init__(self, path: str, *, who: str, clock=time.time):
        self._path, self._who, self._clock = path, who, clock
        self._lock = threading.Lock()
        self._key: tuple | None = None
        self._cached: tuple[str, float] | None = None
        self._logged: str | None = None

    def _state(self) -> tuple[str, str | None]:
        try:
            st = os.stat(self._path)
            key = (st.st_ino, st.st_mtime_ns, st.st_size)
            if self._cached is None or key != self._key:
                fd = os.open(self._path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
                try:
                    fst = os.fstat(fd)
                    if not _stat.S_ISREG(fst.st_mode):
                        return "unreadable", None
                    raw = os.read(fd, ACCESS_FILE_MAX_BYTES + 1)
                finally:
                    os.close(fd)
                if len(raw) > ACCESS_FILE_MAX_BYTES:
                    return "unreadable", None
                try:
                    parsed = _parse(raw)
                except ValueError:
                    self._key = self._cached = None
                    return "invalid", None
                self._key, self._cached = (fst.st_ino, fst.st_mtime_ns, fst.st_size), parsed
        except FileNotFoundError:
            return "missing", None
        except OSError:
            return "unreadable", None
        assert self._cached is not None
        bearer, expires = self._cached
        if self._clock() >= expires - EXPIRY_SLACK_S:
            return "expired", None
        return "ok", bearer

    def bearer(self) -> str:
        with self._lock:
            state, value = self._state()
            if state != self._logged:
                self._logged = state
                print(f"{self._who}: store access file: {state}", file=sys.stderr, flush=True)
        if value is None:
            raise AccessUnavailable() from None
        return value


def make_hook(source: AccessFile):
    def _pin_and_authorize(request, **_kwargs):
        try:
            parts = urlsplit(request.url)
            port = parts.port
        except ValueError:
            raise EndpointRefused() from None
        if (
            parts.scheme != "https"
            or parts.hostname != GCS_HOST
            or port not in (None, 443)
            or parts.username
            or parts.password
        ):
            raise EndpointRefused()
        try:
            bearer = source.bearer()
        except AccessUnavailable:
            raise
        except Exception:  # never carry its text
            raise AccessUnavailable() from None
        request.headers["Authorization"] = "Bearer " + bearer

    return _pin_and_authorize


def make_gcs_client(region: str, source: AccessFile):
    client = botocore.session.get_session().create_client(
        "s3", region_name=region, endpoint_url=GCS_ENDPOINT,
        config=Config(signature_version=botocore.UNSIGNED, s3={"addressing_style": "path"},
                      connect_timeout=5, read_timeout=30,
                      retries={"max_attempts": 3, "mode": "standard"},
                      request_checksum_calculation="when_required",
                      response_checksum_validation="when_required"))
    client.meta.events.register("before-send.s3", make_hook(source))
    return client
