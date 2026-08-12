"""SSRF guard for outbound HTTP fetches with user-supplied URLs.

The naive pattern — `socket.getaddrinfo(host)` → validate → `urlopen(url)` —
has a TOCTOU race window: the IP that the library actually connects to
may differ from the one we just validated. DNS rebinding, multi-record
sets returned in different orders, or a hostile resolver can all exploit
this.

`SSRFGuardTransport` is an `httpx.HTTPTransport` subclass that closes the
window: it resolves the request hostname itself, validates every address
against the blocklist, picks one validated IP, and pins the connection
to that IP via URL rewrite. Host header and TLS SNI / cert hostname are
preserved so the server's TLS certificate is still verified against the
original hostname.

Usage:

    from app.core.ssrf import ssrf_safe_client

    with ssrf_safe_client() as client:
        resp = client.get(user_supplied_url)

Use for any outbound fetch where the URL came from a user (SAML IdP
metadata, connector favicons, etc.). Hardcoded API endpoints don't need
it.
"""

import ipaddress
import socket
from typing import Iterable

import httpx

# Match the SAML legacy blocklist plus a couple of broadcast/multicast nets.
# Adjust here — every SSRF-protected fetch in the app inherits this list.
DEFAULT_BLOCKED_NETWORKS: tuple = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),    # RFC 6598 CGNAT
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / AWS IMDS
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),    # benchmarking
    ipaddress.ip_network("224.0.0.0/4"),      # multicast
    ipaddress.ip_network("240.0.0.0/4"),      # reserved
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
    ipaddress.ip_network("ff00::/8"),         # IPv6 multicast
)


class SSRFBlockedError(httpx.RequestError):
    """Raised when a request's resolved address is on the blocklist."""


def is_blocked(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    blocked: Iterable = DEFAULT_BLOCKED_NETWORKS,
) -> bool:
    """Return True if `ip` is on the SSRF blocklist.

    Exposed publicly so static validators (e.g. SAML metadata URL
    validation) can reject IP-literal hosts without re-implementing the
    classification rules used at request time.
    """
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return True
    if isinstance(ip, ipaddress.IPv4Address) and ip.is_reserved:
        return True
    return any(ip in net for net in blocked)


class SSRFGuardTransport(httpx.HTTPTransport):
    """httpx transport that pre-validates resolved IPs before connecting.

    On every request:
      1. If the URL host is an IP literal, validate it directly.
      2. Otherwise resolve via `socket.getaddrinfo`, validate every answer,
         pick the first non-blocked address.
      3. Rewrite the request URL to use the pinned IP, set the original
         Host header, and set `extensions["sni_hostname"]` so TLS SNI and
         cert validation still target the original hostname.
    """

    def __init__(
        self,
        blocked_networks: Iterable = DEFAULT_BLOCKED_NETWORKS,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self._blocked = tuple(blocked_networks)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        original_host = request.url.host
        if not original_host:
            raise SSRFBlockedError("Request URL missing host", request=request)

        # IP literal: no DNS to race; just validate.
        try:
            literal = ipaddress.ip_address(original_host)
        except ValueError:
            literal = None
        if literal is not None:
            if is_blocked(literal, self._blocked):
                raise SSRFBlockedError(f"Blocked address: {literal}", request=request)
            return super().handle_request(request)

        port = request.url.port or (443 if request.url.scheme == "https" else 80)
        try:
            addrs = socket.getaddrinfo(original_host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise httpx.ConnectError(f"DNS resolution failed: {exc}", request=request)

        pinned_ip: str | None = None
        for _family, _type, _proto, _canon, sockaddr in addrs:
            try:
                ip = ipaddress.ip_address(sockaddr[0])
            except ValueError:
                continue
            if is_blocked(ip, self._blocked):
                continue
            pinned_ip = sockaddr[0]
            break

        if pinned_ip is None:
            raise SSRFBlockedError(
                f"All resolved addresses for {original_host} are on the SSRF blocklist",
                request=request,
            )

        # Pin the connection to the validated IP. The Host header keeps the
        # original hostname for HTTP routing; `sni_hostname` extension makes
        # httpcore use the original hostname for TLS SNI and cert validation
        # so the server's certificate is still verified against the real name.
        ipv6_literal = f"[{pinned_ip}]" if ":" in pinned_ip else pinned_ip
        pinned_url = request.url.copy_with(host=ipv6_literal)
        pinned = httpx.Request(
            method=request.method,
            url=pinned_url,
            headers=request.headers,
            content=request.stream,
            extensions={**request.extensions, "sni_hostname": original_host},
        )
        pinned.headers["Host"] = original_host

        return super().handle_request(pinned)


def ssrf_safe_client(
    timeout: float = 15.0,
    follow_redirects: bool = False,
    **kwargs,
) -> httpx.Client:
    """Return an `httpx.Client` wired with the SSRF guard transport.

    Use as a context manager so connections are cleaned up. Redirects are
    off by default — a metadata URL that redirects somewhere unexpected
    is itself a signal worth surfacing rather than silently following.
    When enabled, every redirect target re-enters `handle_request` and is
    re-validated against the blocklist, so redirect-following remains safe.
    """
    return httpx.Client(
        transport=SSRFGuardTransport(),
        timeout=timeout,
        follow_redirects=follow_redirects,
        **kwargs,
    )
