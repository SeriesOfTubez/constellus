"""S3 backend for the capture store (planning#318 S1b).

Key layout (prefixed inside each bucket, so all four may name one bucket):
  jobs bucket      jobs/<id>.json
  results bucket   results/<id>/result.json, results/<id>/screenshot.webp
  proxylog bucket  proxylog/<id>.jsonl
  images bucket    images/<id>.webp

Commit marker: the worker PUTs `result.json` LAST, so `list_results` returns only
ids whose `results/<id>/result.json` exists; a screenshot alone is an orphan that
the timeout sweep clears. CONTENT checks (JSON parse, magic bytes, sha256, field
validation) stay in page_capture.py. Read-side caps are the guarantee: the
ContentLength is compared with the cap and at most cap+1 bytes are still read.

Every botocore error surfaces as OSError so the callers' fail-closed handlers apply.
This module never logs a key, secret or presigned URL.

Auth modes (CAPTURE_S3_AUTH): `sigv4` (static or default-chain keys, SigV4 presigning) and `gcs-wi`
(planning#322: keyless Google Cloud Storage under Workload Identity). In `gcs-wi` the data plane is
botocore with UNSIGNED requests plus a Bearer token added by a before-send hook pinned to the GCS
endpoint, and the URLs handed to the worker are V4 URLs signed by google-cloud-storage through IAM
signBlob. The two tokens (data scope, signing scope) are never interchanged. `google.*` is imported
only inside the gcs-wi code paths.
"""

import logging
import os
import threading
import time
import urllib.error
import urllib.request
import uuid
import dataclasses
from dataclasses import dataclass
from datetime import timedelta
from functools import lru_cache
from typing import Literal, Mapping, Protocol
from urllib.parse import urlsplit

import botocore
import botocore.session
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from app.services.capture_store import StoreConfigError

log = logging.getLogger(__name__)

_MISSING = frozenset({"404", "NoSuchKey", "NotFound"})
_NO_BUCKET = frozenset({"NoSuchBucket", "404", "NotFound"})
RESULT_NAMES = frozenset({"result.json", "screenshot.webp"})

# Claim markers (planning#323): `claims/<id>` in the results bucket, written by a worker through a
# presigned conditional PUT. A marker may only go once its claim URL must have expired, or a slow
# worker could re-claim a job. The claim URL lives at most QUEUE_TIMEOUT_MAX + CREDENTIAL_RUN_MARGIN_S
# (page_capture.py; a drift test asserts the sum below), plus a clock-skew allowance.
CLAIM_SKEW_S = 300
CLAIM_MARKER_MAX_AGE_S = 3600 + 300 + CLAIM_SKEW_S

PROBE_URL_TTL_S = 300
PROBE_TIMEOUT_S = 10

AUTH_MODES = ("sigv4", "gcs-wi")
GCS_ENDPOINT = "https://storage.googleapis.com"
GCS_HOST = "storage.googleapis.com"
GCS_DATA_SCOPE = "https://www.googleapis.com/auth/devstorage.read_write"
GCS_SIGN_SCOPE = "https://www.googleapis.com/auth/iam"

# (data-plane endpoint, results bucket) pairs proved to honour the signed claim precondition
# (`If-None-Match: *` on S3, `x-goog-if-generation-match: 0` on GCS) by PUTting a real signed URL
# twice. Module level because get_store() builds a fresh store per call. Only successes are cached.
_CONDITIONAL_OK: set[tuple] = set()


@dataclass(frozen=True)
class S3Buckets:
    jobs: str
    results: str
    proxylog: str
    images: str


@dataclass(frozen=True)
class S3Config:
    endpoint: str | None  # None = AWS default endpoints
    # the endpoint presigned URLs are signed for, when the worker reaches the store by another host
    public_endpoint: str | None
    region: str
    access_key: str | None  # both or neither; neither = botocore's default chain
    secret_key: str | None
    path_style: bool
    buckets: S3Buckets
    auth: str = "sigv4"


class Signer(Protocol):
    claim_headers: Mapping[str, str]  # the headers the claim URL signs and the worker must send

    def presign(self, method: Literal["GET", "PUT"], bucket: str, key: str, expires_in: int) -> str: ...
    def presign_put_if_absent(self, bucket: str, key: str, expires_in: int) -> str: ...


class SigV4Signer:
    """AWS SigV4 presigning through botocore. Offline: no request is made."""

    claim_headers: Mapping[str, str] = {"If-None-Match": "*"}

    def __init__(self, client):
        self._client = client

    def presign(self, method, bucket, key, expires_in):
        op = {"GET": "get_object", "PUT": "put_object"}[method]
        return self._client.generate_presigned_url(
            ClientMethod=op, Params={"Bucket": bucket, "Key": key}, ExpiresIn=expires_in, HttpMethod=method)

    def presign_put_if_absent(self, bucket, key, expires_in):
        """A PUT whose SIGNED headers include `If-None-Match: *`: the worker must send it, and the
        store answers 412 to every PUT after the first."""
        return self._client.generate_presigned_url(
            ClientMethod="put_object", Params={"Bucket": bucket, "Key": key, "IfNoneMatch": "*"},
            ExpiresIn=expires_in, HttpMethod="PUT")


class _EndpointRefused(BotoCoreError):
    fmt = "capture store: request refused: not the pinned GCS endpoint"


class _TokenUnavailable(BotoCoreError):
    fmt = "capture store: could not obtain a Google access token"


class _GoogleToken:
    """Lazily-built Application Default Credentials for ONE scope, refreshed only when invalid."""

    def __init__(self, scope: str):
        self._scope = scope
        self._creds = None
        self._lock = threading.Lock()

    def _fresh(self):
        import google.auth
        from google.auth.transport.requests import Request
        with self._lock:
            if self._creds is None:
                self._creds, _ = google.auth.default(scopes=[self._scope])
            if not self._creds.valid:
                self._creds.refresh(Request())
            return self._creds

    def token(self) -> str:
        token = self._fresh().token
        if not token:
            raise ValueError("empty token")
        return token

    def identity(self) -> str | None:
        """The service account the credentials ARE (refreshed first: metadata creds learn it then)."""
        return getattr(self._fresh(), "service_account_email", None)


@lru_cache(maxsize=4)
def _google_token(scope: str) -> _GoogleToken:
    return _GoogleToken(scope)


def _pin_and_authorize(request, **_kwargs):
    """before-send hook: refuse anything but https://storage.googleapis.com[:443] BEFORE a header is
    set (botocore re-sends redirects through here), then add the data-plane Bearer token."""
    try:
        parts = urlsplit(request.url)
        port = parts.port
    except ValueError:
        raise _EndpointRefused() from None
    if parts.scheme != "https" or parts.hostname != GCS_HOST or port not in (None, 443) or parts.username or parts.password:
        raise _EndpointRefused()
    try:
        token = _google_token(GCS_DATA_SCOPE).token()
    except Exception:  # any credential failure: never carry its text (it can hold URLs/tokens)
        raise _TokenUnavailable() from None
    request.headers["Authorization"] = "Bearer " + token


class GcsSigner:
    """V4 URLs for GCS, signed by the maintained SDK through IAM signBlob as the service account
    ITSELF (the deploy grants signBlob on itself only). Offline apart from that signBlob call."""

    claim_headers: Mapping[str, str] = {"x-goog-if-generation-match": "0"}

    def __init__(self):
        from google.cloud import storage
        self._client = storage.Client.create_anonymous_client()

    def _sign(self, method, bucket, key, expires_in, headers):
        try:
            holder = _google_token(GCS_SIGN_SCOPE)
            token = holder.token()
            email = holder.identity()
            if not email or email == "default" or "@" not in email:
                raise ValueError("no service account identity")
            return self._client.bucket(bucket).blob(key).generate_signed_url(
                version="v4", expiration=timedelta(seconds=expires_in), method=method, headers=headers,
                service_account_email=email, access_token=token, api_access_endpoint=GCS_ENDPOINT)
        except Exception as e:  # never the message: it can carry URLs or tokens
            raise OSError(f"capture store: signer: {type(e).__name__}") from None

    def presign(self, method, bucket, key, expires_in):
        return self._sign(method, bucket, key, expires_in, None)

    def presign_put_if_absent(self, bucket, key, expires_in):
        return self._sign("PUT", bucket, key, expires_in, dict(self.claim_headers))


@lru_cache(maxsize=1)
def _gcs_signer() -> GcsSigner:
    return GcsSigner()


def _checked_url(value: str | None, name: str, insecure: bool) -> str | None:
    if not value:
        return None
    parts = urlsplit(value)
    allowed = {"https"} | ({"http"} if insecure else set())
    if parts.scheme not in allowed or not parts.netloc or "@" in parts.netloc:
        raise StoreConfigError(
            f"{name} must be an https URL (http only with CAPTURE_S3_INSECURE_HTTP=1) "
            "with a host and no credentials")
    return value


def s3_config_from_env() -> S3Config:
    env = os.environ
    auth = env.get("CAPTURE_S3_AUTH", "sigv4").strip().lower() or "sigv4"
    if auth not in AUTH_MODES:
        raise StoreConfigError("CAPTURE_S3_AUTH must be sigv4 or gcs-wi")
    insecure = env.get("CAPTURE_S3_INSECURE_HTTP") == "1"
    endpoint = _checked_url(env.get("CAPTURE_S3_ENDPOINT"), "CAPTURE_S3_ENDPOINT", insecure)
    public_endpoint = _checked_url(env.get("CAPTURE_S3_PUBLIC_ENDPOINT"), "CAPTURE_S3_PUBLIC_ENDPOINT", insecure)
    access = env.get("CAPTURE_S3_ACCESS_KEY") or None
    secret = env.get("CAPTURE_S3_SECRET_KEY") or None
    if auth != "gcs-wi" and (access is None) != (secret is None):
        raise StoreConfigError("CAPTURE_S3_ACCESS_KEY and CAPTURE_S3_SECRET_KEY must be set together")
    style = env.get("CAPTURE_S3_PATH_STYLE", "true").strip().lower()
    if style not in ("true", "false"):
        raise StoreConfigError("CAPTURE_S3_PATH_STYLE must be true or false")
    if auth == "gcs-wi":
        if env.get("CAPTURE_S3_ENDPOINT") != GCS_ENDPOINT:
            raise StoreConfigError(f"CAPTURE_S3_ENDPOINT must be exactly {GCS_ENDPOINT} when CAPTURE_S3_AUTH=gcs-wi")
        if access is not None or secret is not None or env.get("CAPTURE_S3_ACCESS_KEY") or env.get("CAPTURE_S3_SECRET_KEY"):
            raise StoreConfigError(
                "CAPTURE_S3_ACCESS_KEY / CAPTURE_S3_SECRET_KEY must be unset: gcs-wi uses Workload Identity; "
                "static keys are refused")
        if public_endpoint is not None or env.get("CAPTURE_S3_PUBLIC_ENDPOINT"):
            raise StoreConfigError("CAPTURE_S3_PUBLIC_ENDPOINT must be unset when CAPTURE_S3_AUTH=gcs-wi")
        if style != "true":
            raise StoreConfigError("CAPTURE_S3_PATH_STYLE must be true when CAPTURE_S3_AUTH=gcs-wi")
        if insecure:
            raise StoreConfigError("CAPTURE_S3_INSECURE_HTTP must not be 1 when CAPTURE_S3_AUTH=gcs-wi")
    names = {
        "jobs": "CAPTURE_S3_BUCKET_JOBS", "results": "CAPTURE_S3_BUCKET_RESULTS",
        "proxylog": "CAPTURE_S3_BUCKET_PROXYLOG", "images": "CAPTURE_S3_BUCKET_IMAGES",
    }
    vals = {k: (env.get(v) or "").strip() for k, v in names.items()}
    missing = [names[k] for k, v in vals.items() if not v]
    if missing:
        raise StoreConfigError("capture store S3 config is missing: " + ", ".join(missing))
    return S3Config(
        endpoint=endpoint, public_endpoint=public_endpoint, region=env.get("CAPTURE_S3_REGION") or "us-east-1",
        access_key=access, secret_key=secret, path_style=style == "true", buckets=S3Buckets(**vals),
        auth=auth)


@lru_cache(maxsize=8)  # two clients per config when a public endpoint is set
def _client(cfg: S3Config):
    session = botocore.session.get_session()
    if cfg.auth == "gcs-wi":
        client = session.create_client(
            "s3", region_name=cfg.region, endpoint_url=GCS_ENDPOINT,
            config=Config(signature_version=botocore.UNSIGNED, s3={"addressing_style": "path"},
                          connect_timeout=5, read_timeout=30,
                          retries={"max_attempts": 3, "mode": "standard"},
                          request_checksum_calculation="when_required",
                          response_checksum_validation="when_required"))
        client.meta.events.register("before-send.s3", _pin_and_authorize)
        return client
    return session.create_client(
        "s3", region_name=cfg.region, endpoint_url=cfg.endpoint,
        aws_access_key_id=cfg.access_key, aws_secret_access_key=cfg.secret_key,
        config=Config(signature_version="s3v4",
                      s3={"addressing_style": "path" if cfg.path_style else "virtual"},
                      connect_timeout=5, read_timeout=30,
                      retries={"max_attempts": 3, "mode": "standard"}))


def _presign_client(cfg: S3Config):
    """The client that signs URLs for the worker: bound to the public endpoint when one is set."""
    if cfg.public_endpoint is None:
        return _client(cfg)
    return _client(dataclasses.replace(cfg, endpoint=cfg.public_endpoint, public_endpoint=None))


def s3_store_from_env() -> "S3Store":
    cfg = s3_config_from_env()
    if cfg.auth == "gcs-wi":
        signer = _gcs_signer()
        return S3Store(_client(cfg), signer, cfg.buckets)
    # the probe uses the backend's own endpoint (it may be unable to reach the public one): same store,
    # same mechanism
    return S3Store(_client(cfg), SigV4Signer(_presign_client(cfg)), cfg.buckets,
                   probe_signer=SigV4Signer(_client(cfg)))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None  # any 3xx becomes an HTTPError


def _probe_put(url: str, headers: Mapping[str, str]) -> int:
    """PUT an empty body to a signed URL and return the HTTP status. No env proxies, no redirects.
    Never logs or raises with the URL."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        req = urllib.request.Request(url, data=b"", method="PUT", headers={**headers, "Content-Length": "0"})
        with opener.open(req, timeout=PROBE_TIMEOUT_S) as resp:
            status = resp.status
            resp.read(1024)
        return status
    except urllib.error.HTTPError as e:
        code = e.code
        e.close()
        return code
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise OSError(f"capture store: conditional-write probe: {type(e).__name__}") from None


def _code(e: Exception) -> str:
    if isinstance(e, ClientError):
        return str(e.response.get("Error", {}).get("Code", ""))
    return ""


def _oserror(e: Exception) -> OSError:
    # the error CODE only: the full response can echo request details
    # botocore raises modelled subclasses (e.g. `AccessDenied`) whose class name varies; report a stable one
    kind = "ClientError" if isinstance(e, ClientError) else type(e).__name__
    return OSError(f"capture store: {kind}: {_code(e)}")


class S3Store:
    def __init__(self, client, signer: Signer, buckets: S3Buckets, probe_signer: Signer | None = None):
        self._c = client
        self._signer = signer
        self._probe_signer = probe_signer or signer
        self._b = buckets

    # ── helpers ──────────────────────────────────────────────────────────
    def _get_capped(self, bucket: str, key: str, cap: int) -> bytes | None:
        try:
            resp = self._c.get_object(Bucket=bucket, Key=key)
        except ClientError as e:
            if _code(e) not in _MISSING:
                log.warning("page_capture: could not read %s/%s (%s)", bucket, key, _code(e))
            return None
        except BotoCoreError as e:
            log.warning("page_capture: could not read %s/%s (%s)", bucket, key, type(e).__name__)
            return None
        body = resp["Body"]
        try:
            if resp.get("ContentLength", cap + 1) > cap:
                return None
            data = body.read(cap + 1)
        except (BotoCoreError, OSError) as e:
            log.warning("page_capture: could not read %s/%s (%s)", bucket, key, type(e).__name__)
            return None
        finally:
            body.close()
        return None if len(data) > cap else data

    def _list(self, bucket: str, prefix: str) -> list[tuple[str, object]]:
        out = []
        for page in self._c.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                out.append((obj["Key"], obj["LastModified"]))
        return out

    def _delete_quiet(self, bucket: str, key: str) -> None:
        try:
            self._c.delete_object(Bucket=bucket, Key=key)
        except (ClientError, BotoCoreError) as e:
            log.warning("page_capture: could not remove %s/%s (%s)", bucket, key, _code(e) or type(e).__name__)

    # ── spool ────────────────────────────────────────────────────────────
    def check_spool(self) -> None:
        """The three buckets a capture needs end to end must exist before a job is
        queued: jobs (the worker reads it), results (presigned PUTs land there) and
        proxylog (the record of what the browser asked for; a missing bucket would
        silently drop it). Any failure is an OSError, so capture refuses."""
        try:
            self._c.head_bucket(Bucket=self._b.jobs)
            self._c.head_bucket(Bucket=self._b.results)
            self._c.head_bucket(Bucket=self._b.proxylog)
        except (ClientError, BotoCoreError) as e:
            raise _oserror(e) from None

    def put_job(self, capture_id: str, payload: bytes) -> None:
        try:
            self._c.put_object(Bucket=self._b.jobs, Key=f"jobs/{capture_id}.json", Body=payload,
                               ContentType="application/json")
        except (ClientError, BotoCoreError) as e:
            raise _oserror(e) from None

    def delete_job(self, capture_id: str) -> None:
        self._delete_quiet(self._b.jobs, f"jobs/{capture_id}.json")

    def ensure_conditional_writes(self) -> None:
        """Prove, once per process per (data-plane endpoint, results bucket), that the store honours the
        signed claim precondition, by PUTting a REAL signed URL twice (2xx, then 412) exactly as a worker
        will. Without it the claim marker is not exclusive and two workers could run one job, so on failure
        no job is issued (OSError). A failure is never cached."""
        cache_key = (self._c.meta.endpoint_url, self._b.results)
        if cache_key in _CONDITIONAL_OK:
            return
        results = self._b.results
        key = f"claims/.probe-{uuid.uuid4().hex}"
        try:
            url = self._probe_signer.presign_put_if_absent(results, key, PROBE_URL_TTL_S)
            headers = dict(self._probe_signer.claim_headers)
            s1 = _probe_put(url, headers)
            if not 200 <= s1 < 300:
                raise OSError(f"capture store: conditional-write probe: HTTP {s1}")
            s2 = _probe_put(url, headers)
            if 200 <= s2 < 300:
                log.error("page_capture: the capture store does not honour conditional writes (signed claim "
                          "precondition); S3 capture jobs are refused so two workers can never run one job")
                raise OSError("capture store: conditional writes not supported")
            if s2 != 412:
                raise OSError(f"capture store: conditional-write probe: HTTP {s2}")
        finally:
            self._delete_quiet(results, key)
        _CONDITIONAL_OK.add(cache_key)

    def sweep_claims(self, now_ts: float | None = None) -> int:
        """Remove claim markers old enough that their claim URL has expired. Never raises."""
        now = time.time() if now_ts is None else now_ts
        try:
            entries = self._list(self._b.results, "claims/")
        except ClientError as e:
            if _code(e) not in _NO_BUCKET:
                log.warning("page_capture: could not list claim markers (%s)", _code(e))
            return 0
        except BotoCoreError as e:
            log.warning("page_capture: could not list claim markers (%s)", type(e).__name__)
            return 0
        removed = 0
        for key, modified in entries:
            if modified.timestamp() < now - CLAIM_MARKER_MAX_AGE_S:
                self._delete_quiet(self._b.results, key)
                removed += 1
        return removed

    def job_fields(self, capture_id: str, expires_at: int) -> dict:
        self.ensure_conditional_writes()
        expires_in = max(1, int(expires_at) - int(time.time()))
        res = self._b.results
        try:
            return {"store": {
                "result_put": self._signer.presign("PUT", res, f"results/{capture_id}/result.json", expires_in),
                "screenshot_put": self._signer.presign("PUT", res, f"results/{capture_id}/screenshot.webp", expires_in),
                "claim_put": self._signer.presign_put_if_absent(res, f"claims/{capture_id}", expires_in),
                "claim_headers": dict(self._signer.claim_headers),
                "expires": int(expires_at),
            }}
        except (ClientError, BotoCoreError) as e:
            # a presign failure must fail the request closed (spool_unavailable), not leave the row queued
            raise _oserror(e) from None

    def list_results(self) -> list[str]:
        try:
            entries = self._list(self._b.results, "results/")
        except ClientError as e:
            if _code(e) in _NO_BUCKET:
                return []
            raise _oserror(e) from None
        except BotoCoreError as e:
            raise _oserror(e) from None
        ids = set()
        for key, _ in entries:
            parts = key[len("results/"):].split("/")
            if len(parts) == 2 and parts[1] == "result.json" and parts[0] and not parts[0].startswith("."):
                ids.add(parts[0])
        return sorted(ids)

    def result_info(self, name: str) -> tuple[float, bool] | None:
        try:
            resp = self._c.head_object(Bucket=self._b.results, Key=f"results/{name}/result.json")
        except ClientError as e:
            if _code(e) not in _MISSING:
                log.warning("page_capture: could not stat result for %s (%s)", name, _code(e))
            return None
        except BotoCoreError as e:
            log.warning("page_capture: could not stat result for %s (%s)", name, type(e).__name__)
            return None
        return resp["LastModified"].timestamp(), True

    def remove_result(self, name: str) -> None:
        try:
            entries = self._list(self._b.results, f"results/{name}/")
        except (ClientError, BotoCoreError) as e:
            log.warning("page_capture: could not list results for %s (%s)", name, _code(e) or type(e).__name__)
            return
        for key, _ in entries:
            self._delete_quiet(self._b.results, key)

    def result_files_ok(self, name: str) -> bool:
        try:
            entries = self._list(self._b.results, f"results/{name}/")
        except (ClientError, BotoCoreError):
            return False
        if not entries:
            return False
        allowed = {f"results/{name}/{n}" for n in RESULT_NAMES}
        return all(key in allowed for key, _ in entries)

    def read_result_file(self, name: str, filename: str, cap: int) -> bytes | None:
        return self._get_capped(self._b.results, f"results/{name}/{filename}", cap)

    # ── proxy log ────────────────────────────────────────────────────────
    def read_proxylog(self, capture_id: str, cap: int) -> tuple[bytes, bool] | None:
        key = f"proxylog/{capture_id}.jsonl"
        try:
            resp = self._c.get_object(Bucket=self._b.proxylog, Key=key)
        except ClientError as e:
            if _code(e) not in _MISSING:
                log.warning("page_capture: could not read the proxy log for %s (%s)", capture_id, _code(e))
            return None
        except BotoCoreError as e:
            log.warning("page_capture: could not read the proxy log for %s (%s)", capture_id, type(e).__name__)
            return None
        body = resp["Body"]
        try:
            data = body.read(cap)
        except (BotoCoreError, OSError) as e:
            log.warning("page_capture: could not read the proxy log for %s (%s)", capture_id, type(e).__name__)
            return None
        finally:
            body.close()
        return data, resp.get("ContentLength", 0) >= cap

    def delete_proxylog(self, capture_id: str) -> None:
        self._delete_quiet(self._b.proxylog, f"proxylog/{capture_id}.jsonl")

    # ── images ───────────────────────────────────────────────────────────
    def check_images(self) -> None:
        try:
            self._c.head_bucket(Bucket=self._b.images)
        except (ClientError, BotoCoreError) as e:
            raise _oserror(e) from None

    def put_image(self, capture_id: str, data: bytes) -> None:
        try:
            self._c.put_object(Bucket=self._b.images, Key=f"images/{capture_id}.webp", Body=data,
                               ContentType="image/webp")
        except (ClientError, BotoCoreError) as e:
            raise _oserror(e) from None

    def read_image(self, capture_id: str, cap: int) -> bytes | None:
        return self._get_capped(self._b.images, f"images/{capture_id}.webp", cap)

    def delete_image(self, capture_id: str) -> None:
        try:
            self._c.delete_object(Bucket=self._b.images, Key=f"images/{capture_id}.webp")
        except (ClientError, BotoCoreError) as e:
            raise _oserror(e) from None

    def delete_image_quiet(self, capture_id: str) -> None:
        self._delete_quiet(self._b.images, f"images/{capture_id}.webp")
