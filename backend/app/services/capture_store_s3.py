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
"""

import logging
import os
import time
import dataclasses
from dataclasses import dataclass
from functools import lru_cache
from typing import Literal, Protocol
from urllib.parse import urlsplit

import botocore.session
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from app.services.capture_store import StoreConfigError

log = logging.getLogger(__name__)

_MISSING = frozenset({"404", "NoSuchKey", "NotFound"})
_NO_BUCKET = frozenset({"NoSuchBucket", "404", "NotFound"})
RESULT_NAMES = frozenset({"result.json", "screenshot.webp"})


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


class Signer(Protocol):
    def presign(self, method: Literal["GET", "PUT"], bucket: str, key: str, expires_in: int) -> str: ...


class SigV4Signer:
    """AWS SigV4 presigning through botocore. Offline: no request is made."""

    def __init__(self, client):
        self._client = client

    def presign(self, method, bucket, key, expires_in):
        op = {"GET": "get_object", "PUT": "put_object"}[method]
        return self._client.generate_presigned_url(
            ClientMethod=op, Params={"Bucket": bucket, "Key": key}, ExpiresIn=expires_in, HttpMethod=method)


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
    insecure = env.get("CAPTURE_S3_INSECURE_HTTP") == "1"
    endpoint = _checked_url(env.get("CAPTURE_S3_ENDPOINT"), "CAPTURE_S3_ENDPOINT", insecure)
    public_endpoint = _checked_url(env.get("CAPTURE_S3_PUBLIC_ENDPOINT"), "CAPTURE_S3_PUBLIC_ENDPOINT", insecure)
    access = env.get("CAPTURE_S3_ACCESS_KEY") or None
    secret = env.get("CAPTURE_S3_SECRET_KEY") or None
    if (access is None) != (secret is None):
        raise StoreConfigError("CAPTURE_S3_ACCESS_KEY and CAPTURE_S3_SECRET_KEY must be set together")
    style = env.get("CAPTURE_S3_PATH_STYLE", "true").strip().lower()
    if style not in ("true", "false"):
        raise StoreConfigError("CAPTURE_S3_PATH_STYLE must be true or false")
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
        access_key=access, secret_key=secret, path_style=style == "true", buckets=S3Buckets(**vals))


@lru_cache(maxsize=8)  # two clients per config when a public endpoint is set
def _client(cfg: S3Config):
    session = botocore.session.get_session()
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
    return S3Store(_client(cfg), SigV4Signer(_presign_client(cfg)), cfg.buckets)


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
    def __init__(self, client, signer: Signer, buckets: S3Buckets):
        self._c = client
        self._signer = signer
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

    def job_fields(self, capture_id: str, expires_at: int) -> dict:
        expires_in = max(1, int(expires_at) - int(time.time()))
        res = self._b.results
        try:
            return {"store": {
                "result_put": self._signer.presign("PUT", res, f"results/{capture_id}/result.json", expires_in),
                "screenshot_put": self._signer.presign("PUT", res, f"results/{capture_id}/screenshot.webp", expires_in),
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
