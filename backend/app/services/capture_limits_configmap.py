"""Proxy-limits sink for Kubernetes (planning#324 slice 2).

The capture proxy's limits travel as one named ConfigMap in the backend's own
namespace, written through the in-cluster API with the pod's service account: a
GET to compare, then a JSON merge PATCH of a single key, only when the content
differs (the same rule as the file sink).

Raw API over httpx by decision: the `kubernetes` package would add eight
dependencies for one call. Not wrapped by the SSRF guard: the target is
`KUBERNETES_SERVICE_HOST` from the pod environment, never user input. The
ConfigMap is pre-created by the manifests, so the service account needs only
get and patch on that one resourceName; a missing ConfigMap is an error, never
a create.
"""

from __future__ import annotations

import json
import logging
import os

import httpx

from app.services import k8s_incluster as k8s
from app.services.k8s_incluster import MAX_RESPONSE_BYTES, SA_DIR, TIMEOUT  # noqa: F401  (re-exported: tests read them here)

log = logging.getLogger(__name__)

DEFAULT_CONFIGMAP = "capture-proxy-limits"
CONFIGMAP_KEY = "proxy_limits.json"  # == page_capture.PROXY_LIMITS_FILE; a test asserts it (importing it here would be circular)

ConfigMapSinkError = k8s.K8sApiError  # alias: one error type for the whole in-cluster client
_client = k8s.make_client  # kept under its old name for the tests that call it


def configmap_name() -> str:
    name = os.environ.get("CAPTURE_LIMITS_CONFIGMAP", DEFAULT_CONFIGMAP)
    if not k8s.valid_name(name):
        raise ConfigMapSinkError("CAPTURE_LIMITS_CONFIGMAP is not a valid ConfigMap name")
    return name


def _request(client: httpx.Client, method: str, url: str, *, headers: dict[str, str],
             content: bytes | None = None) -> tuple[int, bytes]:
    return k8s.request(client, method, url, headers=headers, content=content, label="ConfigMap")


def write_configmap_limits(want: bytes, *, client: httpx.Client | None = None, sa_dir: str = SA_DIR) -> bool:
    """Write `want` as the ConfigMap's proxy_limits.json key when it differs. True if it
    wrote; False when equal, or when the ConfigMap is missing (logged: the manifests
    pre-create it). Raises ConfigMapSinkError for anything else; the message never
    carries the token. `client` is a test seam (the production client is built per call
    so the token file is re-read each tick; projected tokens rotate)."""
    name = configmap_name()
    base = k8s.base_url()
    namespace = k8s.read_sa_file(sa_dir, "namespace")
    if not k8s.valid_name(namespace):
        raise ConfigMapSinkError("service-account namespace is not a valid name")
    token = k8s.read_sa_file(sa_dir, "token")
    ca = os.path.join(sa_dir, "ca.crt")
    if not os.path.isfile(ca):
        raise ConfigMapSinkError("service-account ca.crt is missing")
    try:
        text = want.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ConfigMapSinkError("limits are not valid UTF-8") from e
    path = f"/api/v1/namespaces/{namespace}/configmaps/{name}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    own = client is None
    c = _client(ca) if client is None else client
    try:
        status, body = _request(c, "GET", base + path, headers=headers)
        if status == 404:
            log.error(
                "page_capture: ConfigMap %s/%s is missing; the manifests pre-create it (planning#324); limits not written",
                namespace, name,
            )
            return False
        if status != 200:
            raise ConfigMapSinkError(f"GET ConfigMap {namespace}/{name}: HTTP {status}")
        try:
            parsed = json.loads(body)
        except ValueError as e:
            raise ConfigMapSinkError(f"GET ConfigMap {namespace}/{name}: body is not JSON") from e
        data = parsed.get("data") if isinstance(parsed, dict) else None
        current = data.get(CONFIGMAP_KEY) if isinstance(data, dict) else None
        if current == text:
            return False
        patch = json.dumps({"data": {CONFIGMAP_KEY: text}}, separators=(",", ":")).encode()
        status, _ = _request(
            c, "PATCH", base + path,
            headers={**headers, "Content-Type": "application/merge-patch+json"}, content=patch,
        )
        if status != 200:
            raise ConfigMapSinkError(f"PATCH ConfigMap {namespace}/{name}: HTTP {status}")
    finally:
        if own:
            c.close()
    log.info("page_capture: wrote proxy limits to ConfigMap %s/%s %s", namespace, name, text.strip())
    return True
