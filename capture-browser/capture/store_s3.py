"""S3 job mode of the capture worker (planning#318 S1c).

The worker's key (or, in gcs-wi mode, its access-file token) is list + get on `jobs/` and
nothing else: it can never delete. The backend deletes jobs on ingest, discard, invalid and
timeout. A job
is claimed by a presigned conditional PUT (`store.claim_put`) carrying the job-supplied
precondition `store.claim_headers` (S3 `If-None-Match: *`, GCS
`x-goog-if-generation-match: 0`; signed into the URL): the first PUT wins, every later one gets 412, so any number of workers can poll
one bucket. The claim marker alone makes the job ours. Results go out through
presigned PUT URLs carried by the job (plain HTTP, never through capture-proxy,
no redirects).
Never imports Playwright. Contract: docs/architecture/capture-spool.md.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlsplit

import botocore.session
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from capture import spool, store_auth

JOBS_PREFIX = "jobs/"
UPLOAD_TIMEOUT_S = 30.0

CLAIM_WON = "won"
CLAIM_TAKEN = "taken"  # 412: another worker has it (silent)
CLAIM_FAILED = "failed"  # anything else (logged unless the caller already reported it)


class S3ConfigError(ValueError):
    """A CAPTURE_S3_* variable is missing or malformed."""


class StoreError(OSError):
    """list/get failed; the message is the error code only."""


class UploadError(Exception):
    """A presigned PUT failed; the message never contains the URL."""


@dataclass(frozen=True)
class S3JobsConfig:
    endpoint: str
    netloc: str
    region: str
    access_key: str | None
    secret_key: str | None
    path_style: bool
    bucket: str
    allow_http: bool
    auth: str
    access_file: str | None
    results_bucket: str


def config_from_env(env=os.environ) -> S3JobsConfig:
    endpoint = (env.get("CAPTURE_S3_ENDPOINT") or "").strip()
    if not endpoint:
        raise S3ConfigError("CAPTURE_S3_ENDPOINT is required")
    allow_http = env.get("CAPTURE_S3_INSECURE_HTTP") == "1"
    try:
        parts = urlsplit(endpoint)
    except ValueError:
        raise S3ConfigError("CAPTURE_S3_ENDPOINT is not a valid URL") from None
    if parts.scheme != "https" and not (allow_http and parts.scheme == "http"):
        raise S3ConfigError("CAPTURE_S3_ENDPOINT must be https (http only with CAPTURE_S3_INSECURE_HTTP=1)")
    if not parts.netloc or "@" in parts.netloc:
        raise S3ConfigError("CAPTURE_S3_ENDPOINT needs a host and no credentials")
    region = env.get("CAPTURE_S3_REGION") or "us-east-1"
    access_key = env.get("CAPTURE_S3_ACCESS_KEY") or None
    secret_key = env.get("CAPTURE_S3_SECRET_KEY") or None
    if (access_key is None) != (secret_key is None):
        raise S3ConfigError("CAPTURE_S3_ACCESS_KEY and CAPTURE_S3_SECRET_KEY must be set together")
    style = env.get("CAPTURE_S3_PATH_STYLE", "true")
    if style not in ("true", "false"):
        raise S3ConfigError("CAPTURE_S3_PATH_STYLE must be true or false")
    bucket = (env.get("CAPTURE_S3_BUCKET_JOBS") or "").strip()
    if not bucket:
        raise S3ConfigError("CAPTURE_S3_BUCKET_JOBS is required")
    results_bucket = (env.get("CAPTURE_S3_BUCKET_RESULTS") or "").strip()
    if not results_bucket:
        raise S3ConfigError("CAPTURE_S3_BUCKET_RESULTS is required")
    try:
        auth, access_file = store_auth.auth_from_env(
            env, endpoint=endpoint, path_style=style == "true", allow_http=allow_http,
            has_keys=access_key is not None,
        )
    except store_auth.AuthConfigError as exc:
        raise S3ConfigError(str(exc)) from None
    return S3JobsConfig(
        endpoint=endpoint,
        netloc=parts.netloc.lower(),
        region=region,
        access_key=access_key,
        secret_key=secret_key,
        path_style=style == "true",
        bucket=bucket,
        allow_http=allow_http,
        auth=auth,
        access_file=access_file,
        results_bucket=results_bucket,
    )


def make_client(cfg: S3JobsConfig):
    if cfg.auth == "gcs-wi":
        assert cfg.access_file is not None
        return store_auth.make_gcs_client(
            cfg.region, store_auth.AccessFile(cfg.access_file, who="capture-worker")
        )
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
            retries={"max_attempts": 3, "mode": "standard"},
        ),
    )


def _code(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        return str(exc.response.get("Error", {}).get("Code") or type(exc).__name__)
    return type(exc).__name__


class S3Jobs:
    def __init__(self, client, bucket: str):
        self._c = client
        self._bucket = bucket

    def list_ids(self) -> list[str]:
        ids: set[str] = set()
        try:
            pages = self._c.get_paginator("list_objects_v2").paginate(
                Bucket=self._bucket, Prefix=JOBS_PREFIX
            )
            for page in pages:
                for obj in page.get("Contents") or []:
                    name = obj["Key"][len(JOBS_PREFIX):]
                    if "/" in name:
                        continue
                    cid = spool.job_id_from_name(name)
                    if cid is not None:
                        ids.add(cid)
        except (ClientError, BotoCoreError) as exc:
            raise StoreError(_code(exc)) from None
        return sorted(ids)

    def get(self, cid: str) -> bytes | None:
        try:
            resp = self._c.get_object(Bucket=self._bucket, Key=f"{JOBS_PREFIX}{cid}.json")
        except ClientError as exc:
            code = _code(exc)
            if code in ("NoSuchKey", "404", "NotFound"):
                return None
            raise StoreError(code) from None
        except BotoCoreError as exc:
            raise StoreError(_code(exc)) from None
        body = resp["Body"]
        try:
            return body.read(spool.JOB_MAX_BYTES + 1)
        except (ClientError, BotoCoreError) as exc:
            raise StoreError(_code(exc)) from None
        finally:
            body.close()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None  # any 3xx becomes an HTTPError


def upload(url: str, data: bytes, content_type: str, *, timeout_s: float = UPLOAD_TIMEOUT_S) -> None:
    """PUT `data` to a presigned URL. No env proxies, no redirects, no x-amz-* headers."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        req = urllib.request.Request(
            url,
            data=data,
            method="PUT",
            headers={"Content-Type": content_type, "Content-Length": str(len(data))},
        )
        with opener.open(req, timeout=timeout_s) as resp:
            status = resp.status
            resp.read(1024)
    except urllib.error.HTTPError as exc:
        code = exc.code
        exc.close()
        raise UploadError(f"HTTP {code}") from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise UploadError(type(exc).__name__) from None
    if not 200 <= status <= 299:
        raise UploadError(f"HTTP {status}")


def claim(url: str, headers: dict[str, str], *, cid: str, report: bool = True, timeout_s: float = UPLOAD_TIMEOUT_S) -> str:
    """Claim a job with its presigned conditional PUT, sending the job's validated
    `claim_headers` (the signed precondition) exactly. CLAIM_WON only when this worker
    won (2xx). 412 = another worker won: CLAIM_TAKEN, silently. Anything else is logged
    (code or exception type only, never the URL) and is CLAIM_FAILED; `report=False`
    suppresses that line (the caller already reported this job)."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        req = urllib.request.Request(
            url,
            data=b"",
            method="PUT",
            headers={**headers, "Content-Length": "0"},
        )
        with opener.open(req, timeout=timeout_s) as resp:
            status = resp.status
            resp.read(1024)
    except urllib.error.HTTPError as exc:
        code = exc.code
        exc.close()
        if code == 412:
            return CLAIM_TAKEN
        if report:
            _claim_failed(cid, f"HTTP {code}")
        return CLAIM_FAILED
    except (urllib.error.URLError, OSError, ValueError) as exc:
        if report:
            _claim_failed(cid, type(exc).__name__)
        return CLAIM_FAILED
    if not 200 <= status <= 299:
        if report:
            _claim_failed(cid, f"HTTP {status}")
        return CLAIM_FAILED
    return CLAIM_WON


def _claim_failed(cid: str, why: str) -> None:
    print(f"capture-worker: {cid}: could not claim the job: {why}", file=sys.stderr, flush=True)


def extract_store(raw: bytes, netloc: str, allow_http: bool, *, bucket: str, path_style: bool) -> dict | None:
    """The validated `store` object of a job, or None. Lets an otherwise-invalid
    job still be answered through its result_put."""
    try:
        obj = json.loads(raw)
    except (ValueError, RecursionError):
        return None
    if not isinstance(obj, dict):
        return None
    try:
        return spool.validate_store(obj.get("store"), netloc, allow_http, bucket=bucket, path_style=path_style)
    except spool.InvalidJob:
        return None
