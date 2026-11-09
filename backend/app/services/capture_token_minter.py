"""Mint Credential Access Boundary (CAB) downscoped Google tokens for the capture worker and
proxy (planning#322 slice 2b-2). Used only under `CAPTURE_S3_AUTH=gcs-wi`; google-auth is
imported lazily inside the functions, so nothing here loads it in any other mode.

Token routing (a security invariant; each token goes to exactly one kind of endpoint):
  - the auth/iam token goes to IAM Credentials only (generateAccessToken here; signBlob in
    capture_store_s3);
  - the impersonated devstorage.read_write source token goes to sts.googleapis.com only (the
    google-auth downscoped exchange);
  - downscoped tokens are only published (capture_token_secret), never used by the backend.

Why a freshly impersonated source: a downscoped token expires exactly when its source does, and
the metadata server hands back its cached token until about five minutes before expiry. Only a
fresh self-impersonation (generateAccessToken, lifetime 3600) yields a roughly 60 minute token.

Errors never carry the original message (it can hold URLs or tokens): type names only.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from app.services.capture_store import StoreConfigError
from app.services.capture_store_s3 import GCS_DATA_SCOPE, GCS_SIGN_SCOPE, S3Config

SOURCE_LIFETIME_S = 3600
_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$")  # no quote or backslash can reach the CEL


class MintError(OSError):
    """A token could not be minted. The message is a type name, never the cause's text."""


@dataclass(frozen=True)
class Boundary:
    consumer: str
    bucket: str
    role: str
    prefix: str
    expression: str


@dataclass(frozen=True)
class Minted:
    token: str
    expires_at: datetime  # aware, UTC


def _checked_bucket(name: str, what: str) -> str:
    if not _BUCKET_RE.match(name or ""):
        raise StoreConfigError(f"the {what} bucket name is not a valid GCS bucket name")
    return name


def boundaries(cfg: S3Config) -> dict[str, Boundary]:
    jobs = _checked_bucket(cfg.buckets.jobs, "jobs")
    proxylog = _checked_bucket(cfg.buckets.proxylog, "proxylog")
    worker_expr = (
        f"resource.name.startsWith('projects/_/buckets/{jobs}/objects/jobs/') || "
        "api.getAttribute('storage.googleapis.com/objectListPrefix', '').startsWith('jobs/')"
    )  # both clauses: without the second, a list is refused
    proxy_expr = f"resource.name.startsWith('projects/_/buckets/{proxylog}/objects/proxylog/')"
    return {
        "worker": Boundary("worker", jobs, "roles/storage.objectViewer", "jobs/", worker_expr),
        "proxy": Boundary("proxy", proxylog, "roles/storage.objectCreator", "proxylog/", proxy_expr),
    }


def fingerprint(b: Boundary) -> str:
    """sha256 of a canonical JSON of the boundary. Not secret; a changed bucket or boundary
    changes it, which triggers a re-mint."""
    canon = json.dumps(
        [b.consumer, b.bucket, b.role, b.prefix, b.expression], separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canon.encode()).hexdigest()


def make_source():
    """A fresh self-impersonated data-plane credentials object (not yet refreshed).

    Builds its OWN auth/iam credentials (never the lru-cached holder in capture_store_s3, which
    request threads share under a lock), refreshes them to learn the identity, and impersonates
    that same service account for devstorage.read_write."""
    try:
        import google.auth
        from google.auth import impersonated_credentials
        from google.auth.transport.requests import Request

        signing, _ = google.auth.default(scopes=[GCS_SIGN_SCOPE])
        signing.refresh(Request())
        email = getattr(signing, "service_account_email", None)
        if not email or email == "default" or "@" not in email:
            raise ValueError("no service account identity")
        return impersonated_credentials.Credentials(
            source_credentials=signing, target_principal=email,
            target_scopes=[GCS_DATA_SCOPE], lifetime=SOURCE_LIFETIME_S)
    except Exception as e:
        raise MintError(f"source: {type(e).__name__}") from None


def mint(source, b: Boundary) -> Minted:
    """Exchange `source` for a token limited to boundary `b` (one STS call)."""
    try:
        from google.auth import downscoped
        from google.auth.transport.requests import Request

        rule = downscoped.AccessBoundaryRule(
            available_resource=f"//storage.googleapis.com/projects/_/buckets/{b.bucket}",
            available_permissions=[f"inRole:{b.role}"],
            availability_condition=downscoped.AvailabilityCondition(expression=b.expression))
        creds = downscoped.Credentials(
            source_credentials=source,
            credential_access_boundary=downscoped.CredentialAccessBoundary(rules=[rule]))
        creds.refresh(Request())
        token, expiry = creds.token, creds.expiry
        if not token or expiry is None:
            raise ValueError("empty token or no expiry")
        if expiry.tzinfo is None:  # google-auth expiry is naive UTC
            expiry = expiry.replace(tzinfo=timezone.utc)
        return Minted(token=token, expires_at=expiry.astimezone(timezone.utc))
    except Exception as e:
        raise MintError(f"mint {b.consumer}: {type(e).__name__}") from None
