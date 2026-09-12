"""Egress IP blocklist — the single source of truth, vendored into both trees.

⚠️  THIS FILE EXISTS TWICE AND THE TWO COPIES MUST BE BYTE-IDENTICAL:

        backend/app/core/ip_blocklist.py
        scanner-worker/ip_blocklist.py

    The backend and scanner-worker are separate Docker build contexts
    (`./backend` and `./scanner-worker` — see docker-compose.yml), so
    neither can COPY a file from a shared parent directory, and the worker
    image deliberately carries no backend package. Duplication is therefore
    forced by the build topology; what is NOT forced is the duplication
    going unnoticed.

    `test_blocklist_parity.py` (present in both test suites) compares the
    two files' SHA-256 and fails if they differ. Edit one, run the tests,
    copy it across. The alarm fires in CI, not in production.

    Do not add imports beyond the standard library. The worker installs
    only its own requirements.txt, and anything else here would break its
    image at import time.

## Why this module was extracted (planning#89, and the drift that followed)

The backend and the worker each grew their own copy of this blocklist, and
the comment in the worker's copy said "keep the two lists in sync". They
did not stay in sync. The backend gained IPv4-in-IPv6 unwrapping; the
worker never did. Verified on the pinned runtime (Python 3.12), the worker
allowed all of these while the backend blocked them:

    ::ffff:10.0.0.1      IPv4-mapped RFC1918
    ::10.0.0.1           IPv4-compatible
    2002:0a00:0001::     6to4 -> 10.0.0.1
    64:ff9b::a01:a01     NAT64 -> 10.1.10.1
    64:ff9b::a9fe:a9fe   NAT64 -> 169.254.169.254  (cloud metadata)

The worker is the component that actually opens sockets, so its guard is
the one that matters. A legal AAAA record pointing at any of those forms
steers nuclei/naabu/tlsx/httpx/zgrab2 into the deployer's own network.

The worker caught `::ffff:127.0.0.1` and `::ffff:169.254.169.254` only by
accident: Python's `is_loopback` and `is_link_local` consult `.ipv4_mapped`
internally. It never called `is_private`, which is why RFC1918 walked
through. Relying on that accident is exactly the kind of near-miss that
reads as "it works" until the one case that matters.

## The two classes of bypass

Timing (DNS rebinding) is handled by the CALLER — `ssrf.py`'s pinning
transport in the backend, `_resolve_public_ip` in the worker. This module
handles only the second class: ENCODING. An internal IPv4 address can be
spelled as an IPv6 address, and a naive blocklist misses it because an
`IPv6Address` is never `in` an IPv4 network.

`is_blocked` therefore unwraps every IPv6 form that embeds an IPv4 address
and classifies what the address actually REACHES, not how it is spelled.
This is not a blanket rejection of those encodings — `::ffff:8.8.8.8` is
still allowed, because the destination is public. The encoding was never
the danger.
"""

import ipaddress
from typing import Iterable

# Every SSRF-protected fetch and every worker probe inherits this list.
DEFAULT_BLOCKED_NETWORKS: tuple = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),    # RFC 6598 CGNAT
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / cloud metadata
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
    # unwrap — and no legitimate reason for a scan target or user-supplied
    # URL to point into a network-specific translation range. Blocked
    # wholesale.
    ipaddress.ip_network("64:ff9b:1::/48"),
)

# IPv6 prefixes that carry an IPv4 address in a known position.
_NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")
_IPV4_COMPATIBLE = ipaddress.ip_network("::/96")


def embedded_ipv4(ip) -> "ipaddress.IPv4Address | None":
    """Return the IPv4 address an IPv6 address embeds, or None.

    Covers every standard IPv4-in-IPv6 encoding:

      * `::ffff:a.b.c.d`   IPv4-mapped (`::ffff:0:0/96`) — the important one.
        Connects straight to the IPv4 address on a dual-stack socket.
      * `::a.b.c.d`        IPv4-compatible (`::/96`) — deprecated by RFC 4291
        but still parsed, and still missed by every IPv4-network check.
      * `2002:...`         6to4 (RFC 3056) — the embedded IPv4 is the relay.
      * `2001:0:...`       Teredo (RFC 4380) — server and client IPv4.
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
    # ::a.b.c.d over a global IPv4 address). Both are already classified by
    # is_blocked's first branch, so excluding them changes no verdict — it
    # just stops this helper claiming loopback embeds an IPv4 address, which
    # it does not.
    if ip in _IPV4_COMPATIBLE and int(ip) > 1:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def is_blocked(
    ip: "ipaddress.IPv4Address | ipaddress.IPv6Address",
    blocked: Iterable = DEFAULT_BLOCKED_NETWORKS,
) -> bool:
    """Return True if `ip` must not be connected to.

    An IPv6 address that embeds an IPv4 address is classified by the
    address it actually reaches, not by its spelling — without that, every
    IPv4 network in the list above is trivially sidestepped, since an
    `IPv6Address` is never `in` an IPv4 network.
    """
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return True
    if isinstance(ip, ipaddress.IPv4Address) and ip.is_reserved:
        return True
    if any(ip in net for net in blocked):
        return True
    embedded = embedded_ipv4(ip)
    if embedded is not None and is_blocked(embedded, blocked):
        return True
    return False
