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
    # RFC 8215 local-use NAT64. Unlike the well-known 64:ff9b::/96 prefix,
    # the embedded-IPv4 offset here depends on a translator prefix length we
    # can't know (RFC 6052 allows /32../96), so there is nothing reliable to
    # unwrap — and no legitimate reason for a user-supplied URL to point into
    # a network-specific translation range. Blocked wholesale.
    ipaddress.ip_network("64:ff9b:1::/48"),
)

# IPv6 prefixes that carry an IPv4 address in a known position. Everything
# here is unwrapped by `_embedded_ipv4` and re-classified as that IPv4
# address, so `::ffff:10.0.0.1` is blocked while `::ffff:8.8.8.8` is not —
# the encoding isn't what's dangerous, the destination is.
_NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")
_IPV4_COMPATIBLE = ipaddress.ip_network("::/96")


class SSRFBlockedError(httpx.RequestError):
    """Raised when a request's resolved address is on the blocklist."""


def _embedded_ipv4(ip) -> ipaddress.IPv4Address | None:
    """Return the IPv4 address an IPv6 address embeds, or None.

    Covers every standard IPv4-in-IPv6 encoding:

      * `::ffff:a.b.c.d`  IPv4-mapped (`::ffff:0:0/96`) — the important one.
        Connects straight to the IPv4 address on a dual-stack socket.
      * `::a.b.c.d`       IPv4-compatible (`::/96`) — deprecated by RFC 4291
        but still parsed, and still missed by every IPv4-network check.
      * `2002:...`        6to4 (RFC 3056) — the embedded IPv4 is the relay.
      * `2001:0:...`      Teredo (RFC 4380) — server and client IPv4.
      * `64:ff9b::a.b.c.d` NAT64 well-known prefix (RFC 6052) — /96, so the
        IPv4 is unambiguously the low 32 bits.

    Python exposes `.ipv4_mapped` / `.sixtofour` / `.teredo` directly; the
    other two are matched by prefix here. Teredo returns (server, client)
    and the SERVER is what the packet is actually sent to, so that is what
    gets classified — the obfuscated client address is a payload, not a
    destination.
    """
    if not isinstance(ip, ipaddress.IPv6Address):
        return None
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip.teredo is not None:
        return ip.teredo[0]
    if ip in _NAT64_WELL_KNOWN:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    # `::` and `::1` fall inside ::/96 but are the unspecified and loopback
    # addresses, not IPv4-compatible ones (RFC 4291 defines the form as
    # ::a.b.c.d over a global IPv4 address). Both are already classified
    # above, so excluding them changes no verdict — it just stops this
    # helper claiming loopback embeds an IPv4 address, which it does not.
    if ip in _IPV4_COMPATIBLE and int(ip) > 1:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def is_blocked(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    blocked: Iterable = DEFAULT_BLOCKED_NETWORKS,
) -> bool:
    """Return True if `ip` is on the SSRF blocklist.

    Exposed publicly so static validators (e.g. SAML metadata URL
    validation) can reject IP-literal hosts without re-implementing the
    classification rules used at request time.

    An IPv6 address that embeds an IPv4 address is classified by the
    address it actually reaches, not by its spelling — without that, the
    IPv4 networks listed above are trivially sidestepped, since an
    IPv6Address is never `in` an IPv4 network. Note this is not a blanket
    rejection of those encodings: `::ffff:8.8.8.8` still resolves to a
    public address and is still allowed.
    """
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return True
    if isinstance(ip, ipaddress.IPv4Address) and ip.is_reserved:
        return True
    if any(ip in net for net in blocked):
        return True
    embedded = _embedded_ipv4(ip)
    if embedded is not None and is_blocked(embedded, blocked):
        return True
    return False


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
