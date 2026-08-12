"""Tests for the pure helpers behind /affinity/probe in scanner-worker/main.py
(planning#89 / planning#102).

Pure-assert style: no pytest dependency required.
Run with (from /app inside the container):
    python tests/test_affinity_probe.py
"""

import sys
import os

# Allow running from /app (bind-mounted source root inside container)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import AffinityProbeRequest, _target_with_port


def test_target_with_port_hostname():
    assert _target_with_port("example.com", 443) == "example.com:443"


def test_target_with_port_ipv4():
    assert _target_with_port("203.0.113.44", 80) == "203.0.113.44:80"


def test_target_with_port_ipv6_bracketed():
    """IPv6 literals contain their own colons — must be bracketed so
    httpx/tlsx parse host:port correctly instead of splitting on the wrong
    colon."""
    assert _target_with_port("2001:db8::1", 443) == "[2001:db8::1]:443"


def test_affinity_request_defaults_to_443_then_80():
    req = AffinityProbeRequest(hostname="example.com", origin_ip="203.0.113.44")
    assert req.ports == [443, 80]


def test_affinity_request_ports_capped():
    req = AffinityProbeRequest(
        hostname="example.com", origin_ip="1.2.3.4",
        ports=list(range(1, 20)),
    )
    assert len(req.ports) == 8


def test_affinity_request_rejects_non_ip_origin():
    try:
        AffinityProbeRequest(hostname="example.com", origin_ip="not-an-ip")
        raise AssertionError("expected validation error for non-IP origin_ip")
    except ValueError:
        pass


# ---------------------------------------------------------------------------
# Standalone runner (no pytest required)
# ---------------------------------------------------------------------------

def _run():
    tests = [
        test_target_with_port_hostname,
        test_target_with_port_ipv4,
        test_target_with_port_ipv6_bracketed,
        test_affinity_request_defaults_to_443_then_80,
        test_affinity_request_ports_capped,
        test_affinity_request_rejects_non_ip_origin,
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
