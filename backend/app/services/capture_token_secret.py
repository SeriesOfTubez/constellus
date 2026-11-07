"""Publish the downscoped capture tokens into one Kubernetes Secret (planning#322 slice 2b-2).

A rolling job (`tick`, every TICK_INTERVAL_SECONDS) re-mints a consumer's token when the
PUBLISHED one has less than REFRESH_BELOW_S left, or its boundary changed, and publishes both
consumers' values with ONE merge PATCH pinned to the resourceVersion it read. The Secret is
pre-created by the manifests (the backend's Role is get + patch on that one name, no create).
The worker and proxy read it from slice 2b-3.

Token routing is documented in capture_token_minter. Nothing here logs, or puts in an exception
message, a token, its base64, the JSON value or the service-account bearer token.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
from datetime import datetime, timezone

from app.services import capture_token_minter as minter
from app.services import k8s_incluster as k8s
from app.services.k8s_incluster import K8sApiError, SA_DIR

log = logging.getLogger(__name__)

TICK_INTERVAL_SECONDS = 60
REFRESH_BELOW_S = 1800  # promote-to-settings: planning#332
PUBLISH_FLOOR_S = 600  # a GUARD, never a setting: never publish a token with less than this left
SOURCE_LIFETIME_S = minter.SOURCE_LIFETIME_S
DEFAULT_SECRET = "capture-store-tokens"
KEYS = {"worker": "worker.json", "proxy": "proxy.json"}


def secret_name() -> str:
    name = os.environ.get("CAPTURE_TOKEN_SECRET", DEFAULT_SECRET)
    if not k8s.valid_name(name):
        raise K8sApiError("CAPTURE_TOKEN_SECRET is not a valid Secret name")
    return name


def _rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_time(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:  # never ours (we always write Z); a naive time would be read as local
        raise ValueError("expires_at has no offset")
    return dt.astimezone(timezone.utc)


def _published(data: dict, consumer: str) -> tuple[str, datetime] | None:
    """(boundary, expires_at) of the published value, or None when absent or malformed."""
    raw = data.get(KEYS[consumer])
    if not isinstance(raw, str):
        return None
    try:
        doc = json.loads(base64.b64decode(raw, validate=True))
        boundary, expires = doc.get("boundary"), doc.get("expires_at")
        if not isinstance(boundary, str) or not isinstance(expires, str) or not isinstance(doc.get("token"), str):
            return None
        return boundary, _parse_time(expires)
    except (binascii.Error, ValueError, AttributeError, TypeError, OverflowError):
        return None


def _value(m: minter.Minted, b: minter.Boundary) -> str:
    doc = {"token": m.token, "expires_at": _rfc3339(m.expires_at), "boundary": minter.fingerprint(b)}
    return base64.b64encode(json.dumps(doc, separators=(",", ":")).encode()).decode()


def publish_tokens(cfg, *, now: datetime | None = None, client=None, sa_dir: str = SA_DIR,
                   make_source=minter.make_source, mint=minter.mint) -> dict[str, str]:
    """One tick of work. Returns a per-consumer outcome: fresh, published, refused_floor,
    mint_failed, or conflict (another writer won the PATCH; the next tick re-reads)."""
    now = now or datetime.now(timezone.utc)
    bounds = minter.boundaries(cfg)
    name = secret_name()
    base = k8s.base_url()
    namespace = k8s.read_sa_file(sa_dir, "namespace")
    if not k8s.valid_name(namespace):
        raise K8sApiError("service-account namespace is not a valid name")
    token = k8s.read_sa_file(sa_dir, "token")
    ca = os.path.join(sa_dir, "ca.crt")
    if not os.path.isfile(ca):
        raise K8sApiError("service-account ca.crt is missing")
    path = f"/api/v1/namespaces/{namespace}/secrets/{name}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    own = client is None
    c = k8s.make_client(ca) if client is None else client
    try:
        status, body = k8s.request(c, "GET", base + path, headers=headers, label="Secret")
        if status == 404:
            log.error("capture publisher: %s/%s is missing; the manifests pre-created it (planning#322); "
                      "nothing published", namespace, name)
            return {}
        if status != 200:
            raise K8sApiError(f"GET Secret {namespace}/{name}: HTTP {status}")
        try:
            parsed = json.loads(body)
        except ValueError as e:
            raise K8sApiError(f"GET Secret {namespace}/{name}: body is not JSON") from e
        if not isinstance(parsed, dict):
            raise K8sApiError(f"GET Secret {namespace}/{name}: body is not an object")
        data = parsed.get("data")
        data = data if isinstance(data, dict) else {}
        meta = parsed.get("metadata")
        rv = meta.get("resourceVersion") if isinstance(meta, dict) else None

        outcomes: dict[str, str] = {}
        needing: list[str] = []
        for consumer, b in bounds.items():
            pub = _published(data, consumer)
            if pub is None or pub[0] != minter.fingerprint(b) or (pub[1] - now).total_seconds() < REFRESH_BELOW_S:
                needing.append(consumer)
            else:
                outcomes[consumer] = "fresh"
        if not needing:
            return outcomes

        try:
            source = make_source()
        except Exception as e:
            log.error("capture publisher: could not build the mint source: %s", type(e).__name__)
            return {**outcomes, **{k: "mint_failed" for k in needing}}

        staged: dict[str, str] = {}
        expiries: dict[str, datetime] = {}
        for consumer in needing:
            try:
                m = mint(source, bounds[consumer])
            except Exception as e:
                log.error("capture publisher: mint failed for %s: %s", consumer, type(e).__name__)
                outcomes[consumer] = "mint_failed"
                continue
            remaining = (m.expires_at - now).total_seconds()
            if remaining < PUBLISH_FLOOR_S:
                log.error("capture publisher: refusing to publish for %s: only %d s remain (floor %d s)",
                          consumer, int(remaining), PUBLISH_FLOOR_S)
                outcomes[consumer] = "refused_floor"
                continue
            staged[KEYS[consumer]] = _value(m, bounds[consumer])
            expiries[consumer] = m.expires_at
            outcomes[consumer] = "published"
        if not staged:
            return outcomes

        patch = json.dumps({"metadata": {"resourceVersion": rv}, "data": staged}, separators=(",", ":")).encode()
        status, _ = k8s.request(
            c, "PATCH", base + path, headers={**headers, "Content-Type": "application/merge-patch+json"},
            content=patch, label="Secret")
        if status == 409:
            log.info("capture publisher: %s/%s changed under us; the next tick re-reads", namespace, name)
            return {**outcomes, **{k: "conflict" for k in expiries}}
        if status != 200:
            raise K8sApiError(f"PATCH Secret {namespace}/{name}: HTTP {status}")
        for consumer, exp in expiries.items():
            log.info("capture publisher: published for %s, expires_at %s (%d s left)",
                     consumer, _rfc3339(exp), int((exp - now).total_seconds()))
        return outcomes
    finally:
        if own:
            c.close()


def tick() -> None:
    """The scheduled job. Never raises: the scheduler must keep firing."""
    try:
        from app.services.capture_store_s3 import s3_config_from_env
        publish_tokens(s3_config_from_env())
    except K8sApiError as e:
        log.error("capture publisher: tick failed: %s: %s", type(e).__name__, e)
    except Exception as e:
        log.error("capture publisher: tick failed: %s", type(e).__name__)
