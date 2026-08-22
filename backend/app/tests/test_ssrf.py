"""Tests for the SSRF guard (app.core.ssrf) and the SAML metadata URL
validation that sits in front of it.

Why this file exists: CodeQL's `py/full-ssrf` fires on
`saml.fetch_metadata_xml`, because it can't see that `ssrf_safe_client` is a
sanitizer. Probing that alert rather than dismissing it turned up a real
hole — the blocklist enumerated IPv4 networks, but an `IPv6Address` is never
`in` an IPv4 network, so every internal IPv4 range could be reached by
spelling it as IPv6. `::ffff:10.0.0.1` connects to 10.0.0.1 on any
dual-stack host, and it is a legal AAAA value, so it arrived both as a URL
literal AND through ordinary DNS resolution — past the static validator and
past the transport.

Coverage was uneven rather than absent, which is what made it easy to miss:
loopback and link-local WERE caught, because Python's `IPv6Address`
`.is_loopback` / `.is_link_local` see through IPv4-mapped addresses. So
`::ffff:169.254.169.254` (cloud IMDS, the highest-value target) was blocked
while `::ffff:10.0.0.1` was not.

No DB and no network: pure classification and URL-parsing assertions.

Run with:  python -m app.tests.test_ssrf
       or: pytest app/tests/test_ssrf.py
"""

import ipaddress

from app.core.ssrf import DEFAULT_BLOCKED_NETWORKS, _embedded_ipv4, is_blocked
from app.services.saml import _validate_metadata_url


def _blocked(literal: str) -> bool:
    return is_blocked(ipaddress.ip_address(literal))


# ── plain internal targets (the baseline that already worked) ───────────────

def test_blocks_plain_internal_ipv4():
    for literal in (
        "127.0.0.1", "169.254.169.254", "10.0.0.1", "172.16.0.1",
        "192.168.1.1", "100.64.0.1", "0.0.0.0", "192.0.0.1",
        "198.18.0.1", "255.255.255.255", "224.0.0.1", "240.0.0.1",
    ):
        assert _blocked(literal), f"{literal} must be blocked"


def test_blocks_plain_internal_ipv6():
    for literal in ("::1", "fc00::1", "fe80::1", "ff02::1", "::"):
        assert _blocked(literal), f"{literal} must be blocked"


# ── the regression: IPv4 addresses spelled as IPv6 ──────────────────────────

def test_blocks_ipv4_mapped_internal_addresses():
    """`::ffff:a.b.c.d` connects to a.b.c.d on a dual-stack host. Every
    internal range must be caught through this spelling, not just the ones
    Python's IPv6Address properties happen to cover."""
    for literal in (
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",   # cloud IMDS
        "::ffff:10.0.0.1",
        "::ffff:172.16.0.1",
        "::ffff:192.168.1.1",
        "::ffff:100.64.0.1",        # CGNAT
        "::ffff:0.0.0.0",
    ):
        assert _blocked(literal), f"{literal} must be blocked (IPv4-mapped internal)"


def test_blocks_ipv4_mapped_in_hex_form():
    """Same addresses, written without dotted-quad notation — the parser
    normalizes these identically, so the guard must too."""
    assert _blocked("::ffff:a00:1"), "::ffff:a00:1 is 10.0.0.1"
    assert _blocked("::ffff:c0a8:101"), "::ffff:c0a8:101 is 192.168.1.1"


def test_blocks_ipv4_compatible_internal_addresses():
    """`::a.b.c.d` — deprecated by RFC 4291 but still parsed, and missed by
    every IPv4-network membership check."""
    for literal in ("::127.0.0.1", "::10.0.0.1", "::192.168.1.1"):
        assert _blocked(literal), f"{literal} must be blocked (IPv4-compatible internal)"


def test_blocks_transition_prefixes_wrapping_internal_addresses():
    """6to4 / NAT64 / Teredo all carry an IPv4 address that is where the
    traffic actually ends up."""
    assert _blocked("2002:7f00:1::"), "6to4 wrapping 127.0.0.1"
    assert _blocked("2002:a00:1::"), "6to4 wrapping 10.0.0.1"
    assert _blocked("64:ff9b::127.0.0.1"), "NAT64 well-known prefix -> loopback"
    assert _blocked("64:ff9b::10.0.0.1"), "NAT64 well-known prefix -> RFC1918"
    assert _blocked("64:ff9b:1::1"), "RFC 8215 local-use NAT64 range, blocked wholesale"


# ── the other half: public addresses must still be reachable ───────────────

def test_allows_public_addresses():
    """RFC 5737 documentation ranges stand in for "ordinary routable
    address" here — they are outside every blocked network, so they exercise
    the allow path without putting real infrastructure IPs in the repo (see
    .gitleaks.toml's non-reserved-public-ipv4 rule). The two public resolvers
    are explicitly allowlisted there."""
    for literal in (
        "8.8.8.8", "1.1.1.1",
        "192.0.2.5", "198.51.100.5", "203.0.113.5",
        "2606:4700:4700::1111",
    ):
        assert not _blocked(literal), f"{literal} is not internal and must be allowed"


def test_allows_public_addresses_in_embedded_forms():
    """The encoding is not what's dangerous — the destination is. A mapped
    or translated PUBLIC address stays allowed, so the fix is a
    classification of what the address reaches rather than a blanket
    rejection of IPv6 forms that happen to embed IPv4."""
    assert not _blocked("::ffff:8.8.8.8"), "IPv4-mapped public address"
    assert not _blocked("64:ff9b::8.8.8.8"), "NAT64-translated public address"


# ── _embedded_ipv4 itself ──────────────────────────────────────────────────

def test_embedded_ipv4_extraction():
    cases = {
        "::ffff:10.0.0.1": "10.0.0.1",
        "::ffff:a00:1": "10.0.0.1",
        "::10.0.0.1": "10.0.0.1",
        "2002:a00:1::": "10.0.0.1",
        "64:ff9b::10.0.0.1": "10.0.0.1",
    }
    for literal, expected in cases.items():
        got = _embedded_ipv4(ipaddress.ip_address(literal))
        assert got == ipaddress.IPv4Address(expected), f"{literal} -> {got}, want {expected}"


def test_embedded_ipv4_none_for_ordinary_addresses():
    """An ordinary global-unicast IPv6 address embeds nothing — the
    extraction must not manufacture an IPv4 address out of arbitrary bits,
    or public IPv6 traffic would start getting blocked at random."""
    for literal in ("2606:4700:4700::1111", "2001:db8::1", "fc00::1"):
        assert _embedded_ipv4(ipaddress.ip_address(literal)) is None, literal


def test_embedded_ipv4_none_for_unspecified_and_loopback():
    """`::` and `::1` sit inside ::/96 but are the unspecified and loopback
    addresses, not IPv4-compatible ones. Both are blocked on their own
    merits, so this is about the helper telling the truth rather than about
    a verdict — loopback does not embed an IPv4 address."""
    for literal in ("::", "::1"):
        assert _embedded_ipv4(ipaddress.ip_address(literal)) is None, literal
        assert _blocked(literal), f"{literal} must still be blocked"


def test_embedded_ipv4_ignores_ipv4_addresses():
    assert _embedded_ipv4(ipaddress.ip_address("10.0.0.1")) is None


def test_is_blocked_honours_a_custom_blocklist():
    """The `blocked` parameter must flow through the embedded-address
    recursion too, not just the top-level membership test."""
    custom = (ipaddress.ip_network("203.0.113.0/24"),)
    assert is_blocked(ipaddress.ip_address("203.0.113.5"), custom)
    assert is_blocked(ipaddress.ip_address("::ffff:203.0.113.5"), custom)
    assert not is_blocked(ipaddress.ip_address("8.8.8.8"), custom)


# ── the SAML static validator, which shares the classifier ─────────────────

def test_saml_validator_rejects_embedded_internal_literals():
    """`_validate_metadata_url` is the first of two barriers; it calls
    is_blocked for IP-literal hosts, so it inherits the fix. These URLs
    previously passed BOTH barriers."""
    for url in (
        "https://[::ffff:10.0.0.1]/idp/metadata",
        "https://[::ffff:a00:1]/idp/metadata",
        "https://[::ffff:192.168.1.1]/idp/metadata",
        "https://[::ffff:100.64.0.1]/idp/metadata",
        "https://[64:ff9b::127.0.0.1]/idp/metadata",
        "https://[2002:7f00:1::]/idp/metadata",
        "https://[::127.0.0.1]/idp/metadata",
    ):
        try:
            _validate_metadata_url(url)
        except ValueError:
            continue
        raise AssertionError(f"validator accepted an internal target: {url}")


def test_saml_validator_still_rejects_the_basics():
    for url, why in (
        ("http://idp.example.com/metadata", "non-HTTPS"),
        ("https://user:pw@idp.example.com/metadata", "embedded credentials"),
        ("https://169.254.169.254/latest/meta-data/", "IMDS literal"),
        ("https://10.0.0.1/idp/metadata", "RFC1918 literal"),
    ):
        try:
            _validate_metadata_url(url)
        except ValueError:
            continue
        raise AssertionError(f"validator accepted {why}: {url}")


def test_saml_validator_accepts_a_normal_https_url():
    url = "https://idp.example.com/idp/metadata"
    assert _validate_metadata_url(url) == url


def test_saml_validator_enforces_allowed_host_pin():
    _validate_metadata_url("https://idp.example.com/m", allowed_host="idp.example.com")
    _validate_metadata_url("https://IDP.example.com/m", allowed_host="idp.example.com")
    try:
        _validate_metadata_url("https://evil.example.net/m", allowed_host="idp.example.com")
    except ValueError:
        return
    raise AssertionError("validator ignored the allowed_host pin")


def test_default_blocklist_covers_the_documented_ranges():
    """Guard against a range being dropped from DEFAULT_BLOCKED_NETWORKS in
    a future edit — each of these is load-bearing for a known SSRF target."""
    present = {str(net) for net in DEFAULT_BLOCKED_NETWORKS}
    for net in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
        "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/8", "64:ff9b:1::/48",
    ):
        assert net in present, f"{net} dropped from the default blocklist"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
