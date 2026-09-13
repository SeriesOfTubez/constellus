"""Shared network-address predicate.

One definition of "is this address globally routable" for every module that
probes, looks up, or counts addresses as internet-facing. Do not hand-roll a
local copy of this predicate — import this one.
"""

import ipaddress


def is_public_ip(value: str) -> bool:
    """Globally routable, i.e. an address that could plausibly be a public
    cloud resource's.

    This is the single definition of the predicate. Eight modules once
    carried their own copies (shodan.py, naabu.py, tlsx.py, httpx_probe.py,
    banner_grab.py, exposure_analyzer.py, wiz.py, whois_service.py), seven
    of them spelled as a hand-rolled negation:

        not (is_private or is_loopback or is_multicast
             or is_link_local or is_reserved or is_unspecified)

    That negation has a hole: it accepts CGNAT space (100.64.0.0/10,
    RFC 6598), for which `is_private` is False while `is_global` is also
    False — so CGNAT addresses would be probed, looked up in Shodan, and
    counted as internet-facing. For an EASM, over-probing non-routable
    space is the dangerous direction.

    `is_global` alone is not the fix either — it is True for multicast
    (224.0.0.0/4, ff00::/8), which the six-clause negation does exclude. The
    two predicates have complementary holes, so this pairs them. Verified
    across RFC-1918, loopback, link-local, multicast, unspecified, CGNAT and
    the RFC-5737/3849 documentation ranges (see `app/tests/test_netaddr.py`).
    """
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return addr.is_global and not addr.is_multicast
