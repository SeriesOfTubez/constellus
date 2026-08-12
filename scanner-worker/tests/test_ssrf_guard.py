"""Tests for the SSRF egress guard in scanner-worker/main.py (planning#89).

Pure-assert style: no pytest dependency required.
Run with (from /app inside the container):
    python tests/test_ssrf_guard.py
"""

import sys
import os

# Allow running from /app (bind-mounted source root inside container)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ipaddress

from main import (
    EgressBlockedError,
    _is_blocked_ip,
    _resolve_public_ip,
    _resolve_targets_parallel,
    _target_host,
)


# ---------------------------------------------------------------------------
# _is_blocked_ip — the classification the whole guard rests on
# ---------------------------------------------------------------------------

def test_blocks_loopback():
    assert _is_blocked_ip(ipaddress.ip_address("127.0.0.1")) is True
    assert _is_blocked_ip(ipaddress.ip_address("::1")) is True


def test_blocks_private_ranges():
    assert _is_blocked_ip(ipaddress.ip_address("10.1.2.3")) is True
    assert _is_blocked_ip(ipaddress.ip_address("172.16.0.5")) is True
    assert _is_blocked_ip(ipaddress.ip_address("192.168.1.1")) is True


def test_blocks_cloud_metadata_endpoint():
    """169.254.169.254 — the AWS/GCP/Azure metadata IP named explicitly in
    the issue. Falls under the link-local /16."""
    assert _is_blocked_ip(ipaddress.ip_address("169.254.169.254")) is True


def test_blocks_ipv6_unique_local_and_link_local():
    assert _is_blocked_ip(ipaddress.ip_address("fc00::1")) is True
    assert _is_blocked_ip(ipaddress.ip_address("fe80::1")) is True


def test_allows_public_ip():
    assert _is_blocked_ip(ipaddress.ip_address("8.8.8.8")) is False
    assert _is_blocked_ip(ipaddress.ip_address("1.1.1.1")) is False


# ---------------------------------------------------------------------------
# _resolve_public_ip — IP-literal fast path (no DNS/network dependency)
# ---------------------------------------------------------------------------

def test_resolve_public_ip_literal_blocked_raises():
    try:
        _resolve_public_ip("10.0.0.5")
        raise AssertionError("expected EgressBlockedError for a private IP literal")
    except EgressBlockedError:
        pass


def test_resolve_public_ip_literal_metadata_raises():
    try:
        _resolve_public_ip("169.254.169.254")
        raise AssertionError("expected EgressBlockedError for the metadata IP")
    except EgressBlockedError:
        pass


def test_resolve_public_ip_literal_public_passes_through():
    assert _resolve_public_ip("8.8.8.8") == "8.8.8.8"


def test_resolve_public_ip_hostname_localhost_is_blocked():
    """The exact shape of bug this guard exists for: an authorized hostname
    resolving to a loopback/internal address. 'localhost' resolves via the
    system's own hosts file — no network access needed for this test — and
    must be rejected exactly like the issue's 'localhost.example.com ->
    127.0.0.1' example."""
    try:
        _resolve_public_ip("localhost")
        raise AssertionError("expected EgressBlockedError — localhost resolves to loopback")
    except EgressBlockedError:
        pass


# ---------------------------------------------------------------------------
# _target_host — port-suffix stripping for nuclei target strings
# ---------------------------------------------------------------------------

def test_target_host_strips_port():
    assert _target_host("example.com:8443") == "example.com"


def test_target_host_bare_hostname_unchanged():
    assert _target_host("example.com") == "example.com"


def test_target_host_bracketed_ipv6_with_port():
    assert _target_host("[2001:db8::1]:443") == "2001:db8::1"


def test_target_host_bare_ipv6_unchanged():
    assert _target_host("2001:db8::1") == "2001:db8::1"


def test_target_host_ipv4_with_port():
    assert _target_host("10.0.0.1:80") == "10.0.0.1"


# ---------------------------------------------------------------------------
# _resolve_targets_parallel — batch resolution, dedup, drop-not-abort
# ---------------------------------------------------------------------------

def test_resolve_targets_parallel_separates_blocked_and_public():
    values = ["8.8.8.8", "10.0.0.1", "1.1.1.1", "169.254.169.254"]
    resolved = _resolve_targets_parallel(values)
    assert resolved["8.8.8.8"] == "8.8.8.8"
    assert resolved["1.1.1.1"] == "1.1.1.1"
    assert resolved["10.0.0.1"] is None
    assert resolved["169.254.169.254"] is None


def test_resolve_targets_parallel_empty_input():
    assert _resolve_targets_parallel([]) == {}


def test_resolve_targets_parallel_dedup_by_host_fn():
    """Two target strings sharing the same host (different ports) must both
    get an answer, keyed by the ORIGINAL value, even though resolution only
    happens once per unique host."""
    values = ["8.8.8.8:443", "8.8.8.8:8443", "10.0.0.1:443"]
    resolved = _resolve_targets_parallel(values, host_fn=_target_host)
    assert resolved["8.8.8.8:443"] == "8.8.8.8"
    assert resolved["8.8.8.8:8443"] == "8.8.8.8"
    assert resolved["10.0.0.1:443"] is None


# ---------------------------------------------------------------------------
# Standalone runner (no pytest required)
# ---------------------------------------------------------------------------

def _run():
    tests = [
        test_blocks_loopback,
        test_blocks_private_ranges,
        test_blocks_cloud_metadata_endpoint,
        test_blocks_ipv6_unique_local_and_link_local,
        test_allows_public_ip,
        test_resolve_public_ip_literal_blocked_raises,
        test_resolve_public_ip_literal_metadata_raises,
        test_resolve_public_ip_literal_public_passes_through,
        test_resolve_public_ip_hostname_localhost_is_blocked,
        test_target_host_strips_port,
        test_target_host_bare_hostname_unchanged,
        test_target_host_bracketed_ipv6_with_port,
        test_target_host_bare_ipv6_unchanged,
        test_target_host_ipv4_with_port,
        test_resolve_targets_parallel_separates_blocked_and_public,
        test_resolve_targets_parallel_empty_input,
        test_resolve_targets_parallel_dedup_by_host_fn,
    ]
    for fn in tests:
        try:
            fn()
            print(f"OK: {fn.__name__}")
        except AssertionError as exc:
            print(f"FAIL: {fn.__name__}: {exc}")
            raise SystemExit(1)
    print("ALL PASS")


if __name__ == "__main__":
    _run()
