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

Note that CodeQL cannot model this as a sanitizer, so every call site is
likely to raise `py/full-ssrf`. Triage against
`docs/development/codeql-triage.md` rather than dismissing on the grounds
that this module exists — that file records what was actually verified,
and why "it's guarded" is not sufficient grounds.

The second class of bypass this guards against is ENCODING rather than
timing: an internal IPv4 address can be spelled as an IPv6 address, and a
naive blocklist misses it because an IPv6Address is never `in` an IPv4
network. `::ffff:10.0.0.1` reaches 10.0.0.1 on any dual-stack host, and it
is a legal AAAA record value, so this arrives both as a URL literal and
via ordinary DNS resolution. `is_blocked` therefore unwraps every IPv6
form that embeds an IPv4 address and classifies what the address actually
reaches — see `_embedded_ipv4`.
"""

import ipaddress
import socket
from typing import Iterable

import httpx

# The blocklist, the IPv4-in-IPv6 unwrapping and the classification rule all
# live in `ip_blocklist` — a stdlib-only leaf module that is byte-identical to
# `scanner-worker/ip_blocklist.py`. They were duplicated prose-to-prose before,
# with a comment asking the next maintainer to keep them in sync; they did not
# stay in sync, and the worker (the component that actually opens sockets) was
# the copy left behind. See that module's docstring for the verified bypasses
# and for why a build-topology constraint forces two files but not two
# behaviours. `test_blocklist_parity.py` fails if the copies diverge.
from app.core.ip_blocklist import (  # noqa: F401  (re-exported — see below)
    DEFAULT_BLOCKED_NETWORKS,
    embedded_ipv4 as _embedded_ipv4,
    is_blocked,
)

class SSRFBlockedError(httpx.RequestError):
    """Raised when a request's resolved address is on the blocklist."""


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
