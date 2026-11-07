"""Minimal in-cluster Kubernetes API client helpers (shared by the ConfigMap and Secret writers).

Raw API over httpx by decision: the `kubernetes` package would add eight dependencies for a
couple of calls. Not wrapped by the SSRF guard: the target is `KUBERNETES_SERVICE_HOST` from the
pod environment, never user input. TLS is pinned to the service account's CA, redirects are never
followed and the environment's proxy settings are ignored, so the bearer token cannot be routed
elsewhere. No message raised here ever carries the token.
"""

from __future__ import annotations

import ipaddress
import os
import re
import ssl

import httpx

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
TIMEOUT = httpx.Timeout(connect=3.0, read=5.0, write=5.0, pool=3.0)
MAX_RESPONSE_BYTES = 1 << 20  # a ConfigMap or Secret cannot exceed 1 MiB; a larger body is not ours
MAX_SA_FILE_BYTES = 64 * 1024
_NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")  # DNS-1123 label: enough for our names
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


class K8sApiError(OSError):
    """The in-cluster API could not be read or written. The message never carries the token."""


def valid_name(name: str) -> bool:
    return len(name) <= 253 and bool(_NAME_RE.match(name))


def read_sa_file(sa_dir: str, name: str) -> str:
    try:
        with open(os.path.join(sa_dir, name), "rb") as f:
            raw = f.read(MAX_SA_FILE_BYTES + 1)
    except OSError as e:
        raise K8sApiError(f"service-account {name} is unreadable: not running in a cluster?") from e
    if len(raw) > MAX_SA_FILE_BYTES or not raw.strip():
        raise K8sApiError(f"service-account {name} is empty or oversized")
    try:
        return raw.decode("utf-8").strip()
    except UnicodeDecodeError as e:
        raise K8sApiError(f"service-account {name} is not valid UTF-8") from e


def base_url() -> str:
    host = os.environ.get("KUBERNETES_SERVICE_HOST", "").strip()
    if not host:
        raise K8sApiError("KUBERNETES_SERVICE_HOST is unset: not running in a cluster?")
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443").strip()
    if not (port.isascii() and port.isdigit() and 1 <= int(port) <= 65535):
        raise K8sApiError("KUBERNETES_SERVICE_PORT is not a valid port")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if not _HOST_RE.match(host):
            raise K8sApiError("KUBERNETES_SERVICE_HOST is not a valid host") from None
    else:
        if ip.version == 6:
            host = f"[{host}]"
    return f"https://{host}:{port}"


def make_client(ca_path: str) -> httpx.Client:
    """TLS pinned to the service account's CA bundle; redirects never followed (one
    would carry the bearer token elsewhere); trust_env=False so an HTTPS_PROXY in the
    environment can never route the token through a proxy."""
    ctx = ssl.create_default_context(cafile=ca_path)  # httpx 0.28 deprecates a path string here
    return httpx.Client(verify=ctx, timeout=TIMEOUT, follow_redirects=False, trust_env=False)


def request(client: httpx.Client, method: str, url: str, *, headers: dict[str, str],
            content: bytes | None = None, label: str = "object") -> tuple[int, bytes]:
    """One request with a capped body. `label` names the object kind in messages ("ConfigMap")."""
    try:
        with client.stream(method, url, headers=headers, content=content) as r:
            body = b""
            for chunk in r.iter_bytes():
                body += chunk
                if len(body) > MAX_RESPONSE_BYTES:
                    raise K8sApiError(f"{method} {label}: response larger than {MAX_RESPONSE_BYTES} bytes")
            return r.status_code, body
    except httpx.HTTPError as e:
        raise K8sApiError(f"{method} {label}: {type(e).__name__}") from e
