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

import ipaddress
import json
import logging
import os
import re
import ssl

import httpx

log = logging.getLogger(__name__)

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
DEFAULT_CONFIGMAP = "capture-proxy-limits"
CONFIGMAP_KEY = "proxy_limits.json"  # == page_capture.PROXY_LIMITS_FILE; a test asserts it (importing it here would be circular)
TIMEOUT = httpx.Timeout(connect=3.0, read=5.0, write=5.0, pool=3.0)
MAX_RESPONSE_BYTES = 1 << 20  # a ConfigMap cannot exceed 1 MiB; a larger body is not ours
MAX_SA_FILE_BYTES = 64 * 1024
_NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")  # DNS-1123 label: enough for our names
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


class ConfigMapSinkError(OSError):
    """The sink could not be read or written. The message never carries the token."""


def configmap_name() -> str:
    name = os.environ.get("CAPTURE_LIMITS_CONFIGMAP", DEFAULT_CONFIGMAP)
    if len(name) > 253 or not _NAME_RE.match(name):
        raise ConfigMapSinkError("CAPTURE_LIMITS_CONFIGMAP is not a valid ConfigMap name")
    return name


def _read_sa_file(sa_dir: str, name: str) -> str:
    try:
        with open(os.path.join(sa_dir, name), "rb") as f:
            raw = f.read(MAX_SA_FILE_BYTES + 1)
    except OSError as e:
        raise ConfigMapSinkError(f"service-account {name} is unreadable: not running in a cluster?") from e
    if len(raw) > MAX_SA_FILE_BYTES or not raw.strip():
        raise ConfigMapSinkError(f"service-account {name} is empty or oversized")
    try:
        return raw.decode("utf-8").strip()
    except UnicodeDecodeError as e:
        raise ConfigMapSinkError(f"service-account {name} is not valid UTF-8") from e


def _base_url() -> str:
    host = os.environ.get("KUBERNETES_SERVICE_HOST", "").strip()
    if not host:
        raise ConfigMapSinkError("KUBERNETES_SERVICE_HOST is unset: not running in a cluster?")
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443").strip()
    if not (port.isascii() and port.isdigit() and 1 <= int(port) <= 65535):
        raise ConfigMapSinkError("KUBERNETES_SERVICE_PORT is not a valid port")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if not _HOST_RE.match(host):
            raise ConfigMapSinkError("KUBERNETES_SERVICE_HOST is not a valid host") from None
    else:
        if ip.version == 6:
            host = f"[{host}]"
    return f"https://{host}:{port}"


def _client(ca_path: str) -> httpx.Client:
    """TLS pinned to the service account's CA bundle; redirects never followed (one
    would carry the bearer token elsewhere); trust_env=False so an HTTPS_PROXY in the
    environment can never route the token through a proxy."""
    ctx = ssl.create_default_context(cafile=ca_path)  # httpx 0.28 deprecates a path string here
    return httpx.Client(verify=ctx, timeout=TIMEOUT, follow_redirects=False, trust_env=False)


def _request(client: httpx.Client, method: str, url: str, *, headers: dict[str, str],
             content: bytes | None = None) -> tuple[int, bytes]:
    try:
        with client.stream(method, url, headers=headers, content=content) as r:
            body = b""
            for chunk in r.iter_bytes():
                body += chunk
                if len(body) > MAX_RESPONSE_BYTES:
                    raise ConfigMapSinkError(f"{method} ConfigMap: response larger than {MAX_RESPONSE_BYTES} bytes")
            return r.status_code, body
    except httpx.HTTPError as e:
        raise ConfigMapSinkError(f"{method} ConfigMap: {type(e).__name__}") from e


def write_configmap_limits(want: bytes, *, client: httpx.Client | None = None, sa_dir: str = SA_DIR) -> bool:
    """Write `want` as the ConfigMap's proxy_limits.json key when it differs. True if it
    wrote; False when equal, or when the ConfigMap is missing (logged: the manifests
    pre-create it). Raises ConfigMapSinkError for anything else; the message never
    carries the token. `client` is a test seam (the production client is built per call
    so the token file is re-read each tick; projected tokens rotate)."""
    name = configmap_name()
    base = _base_url()
    namespace = _read_sa_file(sa_dir, "namespace")
    if not _NAME_RE.match(namespace):
        raise ConfigMapSinkError("service-account namespace is not a valid name")
    token = _read_sa_file(sa_dir, "token")
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
