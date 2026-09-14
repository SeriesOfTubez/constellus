"""Case table for `app.core.netaddr.is_public_ip` — the single shared
"globally routable" predicate every connector and analyzer uses to decide
whether an address may be probed / looked up / counted as internet-facing.

Run directly (from backend/):
    python -m app.tests.test_netaddr
or via pytest:
    ./.venv/Scripts/python.exe -m pytest app/tests/test_netaddr.py -q

Address hygiene: this file is an exception to the usual RFC-5737-only rule,
because the whole point is a routability case table and RFC-5737 addresses
are non-routable by definition. The only real addresses used are well-known
public resolver addresses (8.8.8.8, 1.1.1.1, 2606:4700:4700::1111) —
infrastructure, not anyone's estate.
"""

from app.connectors import banner_grab, httpx_probe, naabu, shodan, tlsx, wiz
from app.core import netaddr
from app.services import exposure_analyzer, whois_service


def test_rejects_cgnat():
    # 100.64.0.0/10 (RFC 6598): is_private is False, is_global is False.
    # The old six-clause negation accepted these — the bug this helper
    # exists to close. Over-probing CGNAT space is the dangerous direction.
    assert netaddr.is_public_ip("100.64.0.1") is False
    assert netaddr.is_public_ip("100.127.255.255") is False


def test_rejects_multicast():
    # is_global alone is True for multicast; the pairing must exclude it.
    assert netaddr.is_public_ip("224.0.0.1") is False
    assert netaddr.is_public_ip("ff02::1") is False


def test_rejects_private_loopback_linklocal_unspecified():
    for addr in (
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "127.0.0.1",
        "::1",
        "169.254.1.1",
        "fe80::1",
        "0.0.0.0",
        "::",
    ):
        assert netaddr.is_public_ip(addr) is False


def test_rejects_documentation_ranges():
    # RFC-5737 / RFC-3849 documentation ranges are non-routable by
    # definition — which is also why connector tests stub this predicate
    # rather than feeding it real addresses.
    for addr in ("192.0.2.1", "198.51.100.1", "203.0.113.1", "2001:db8::1"):
        assert netaddr.is_public_ip(addr) is False


def test_accepts_globally_routable():
    assert netaddr.is_public_ip("8.8.8.8") is True
    assert netaddr.is_public_ip("1.1.1.1") is True
    assert netaddr.is_public_ip("2606:4700:4700::1111") is True


def test_rejects_malformed_input():
    for bad in ("", "not-an-ip", "192.0.2.0/24", "999.999.999.999"):
        assert netaddr.is_public_ip(bad) is False


def test_network_rejects_documentation_and_private_ranges():
    # planning#161 — the CIDR-sweep predicate. RFC-5737/3849 documentation
    # ranges and RFC-1918 private space are non-routable by definition, same
    # as the single-address cases above.
    for net in (
        "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
        "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12",
    ):
        assert netaddr.is_public_network(net) is False


def test_network_rejects_multicast():
    assert netaddr.is_public_network("224.0.0.0/4") is False
    assert netaddr.is_public_network("ff00::/8") is False


def test_network_rejects_malformed_input():
    for bad in ("", "not-a-network", "999.999.999.999/24", "203.0.113.0/33"):
        assert netaddr.is_public_network(bad) is False


def test_network_accepts_globally_routable():
    # Reuses the exact public-resolver literals this module already
    # sanctions above (see the module docstring) rather than introducing
    # new routable ranges: the surrounding /24s are real address space
    # belonging to real operators, and the repo's secret-scanning hook
    # rejects them on sight. A /32 still exercises the network path —
    # ip_network parsing plus is_global on a network object — and the
    # host-bits case below covers a genuinely multi-address range.
    assert netaddr.is_public_network("8.8.8.8/32") is True
    assert netaddr.is_public_network("1.1.1.1/32") is True


def test_network_accepts_host_bits_set_non_strict():
    # strict=False: a "network" with host bits still set describes a
    # sweep range, not a canonical network address — must not raise.
    assert netaddr.is_public_network("8.8.8.8/24") is True


def test_every_call_site_shares_one_implementation():
    # Every module's bound name must BE the shared helper — this is what
    # stops a ninth copy being introduced later. The bindings keep their
    # private local names so test monkeypatching (wiz._is_public_ip,
    # naabu._is_public_ip) keeps working.
    assert shodan._is_public_ip is netaddr.is_public_ip
    assert naabu._is_public_ip is netaddr.is_public_ip
    assert tlsx._is_public_ip is netaddr.is_public_ip
    assert httpx_probe._is_public_ip is netaddr.is_public_ip
    assert banner_grab._is_public_ip is netaddr.is_public_ip
    assert wiz._is_public_ip is netaddr.is_public_ip
    assert exposure_analyzer._is_public_ip is netaddr.is_public_ip
    assert whois_service._is_public is netaddr.is_public_ip


if __name__ == "__main__":
    _tests = [
        test_rejects_cgnat,
        test_rejects_multicast,
        test_rejects_private_loopback_linklocal_unspecified,
        test_rejects_documentation_ranges,
        test_accepts_globally_routable,
        test_rejects_malformed_input,
        test_network_rejects_documentation_and_private_ranges,
        test_network_rejects_multicast,
        test_network_rejects_malformed_input,
        test_network_accepts_globally_routable,
        test_network_accepts_host_bits_set_non_strict,
        test_every_call_site_shares_one_implementation,
    ]
    for _t in _tests:
        _t()
        print(f"ok {_t.__name__}")
