"""Tests for _filter_stale_ports in app.api.assets.

Pure-assert style: no pytest dependency required.
Run with:  python -m app.tests.test_stale_port_filter       (from /app)
       or: pytest app/tests/test_stale_port_filter.py       (if pytest installed)
"""

from datetime import datetime, timezone

from app.api.assets import _filter_stale_ports

# Fixed reference points:
#   naabu_last_scan_at = 2026-06-19T00:00:00+00:00   (the scan cutoff)
#   now                = 2026-06-19T01:00:00+00:00   (evaluation instant)
_NAABU_SCAN_AT = "2026-06-19T00:00:00+00:00"
_NOW = datetime(2026, 6, 19, 1, 0, 0, tzinfo=timezone.utc)


def _metadata(*open_ports_entries):
    return {
        "naabu_last_scan_at": _NAABU_SCAN_AT,
        "open_ports": list(open_ports_entries),
    }


# Entries used across tests
_PORT_A = {   # shodan, 3 days old — within 14-day grace → KEPT
    "port": 8022,
    "protocol": "tcp",
    "sources": ["shodan"],
    "last_seen_at": "2026-06-16T00:00:00+00:00",
}
_PORT_B = {   # shodan, ~30 days old — past grace → DROPPED
    "port": 8080,
    "protocol": "tcp",
    "sources": ["shodan"],
    "last_seen_at": "2026-05-20T00:00:00+00:00",
}
_PORT_C = {   # naabu, predates cutoff, not shodan → DROPPED (no grace)
    "port": 443,
    "protocol": "tcp",
    "sources": ["naabu"],
    "last_seen_at": "2026-06-18T00:00:00+00:00",
}
_PORT_D = {   # any source, last_seen_at >= cutoff → KEPT
    "port": 80,
    "protocol": "tcp",
    "sources": ["naabu"],
    "last_seen_at": "2026-06-19T00:30:00+00:00",
}
_PORT_E = {   # no last_seen_at → KEPT (unchanged behavior)
    "port": 22,
    "protocol": "tcp",
    "sources": ["shodan"],
}


# ---------------------------------------------------------------------------
# Test 1: All five cases together
# ---------------------------------------------------------------------------

def test_combined_filter():
    """A, D, E are kept; B and C are dropped."""
    result = _filter_stale_ports(
        _metadata(_PORT_A, _PORT_B, _PORT_C, _PORT_D, _PORT_E),
        now=_NOW,
    )
    kept_ports = {e["port"] for e in result["open_ports"]}

    assert _PORT_A["port"] in kept_ports, (
        f"Port {_PORT_A['port']} (shodan, within grace) should be KEPT; "
        f"kept={kept_ports!r}"
    )
    assert _PORT_B["port"] not in kept_ports, (
        f"Port {_PORT_B['port']} (shodan, past grace) should be DROPPED; "
        f"kept={kept_ports!r}"
    )
    assert _PORT_C["port"] not in kept_ports, (
        f"Port {_PORT_C['port']} (naabu, stale) should be DROPPED; "
        f"kept={kept_ports!r}"
    )
    assert _PORT_D["port"] in kept_ports, (
        f"Port {_PORT_D['port']} (>= cutoff) should be KEPT; "
        f"kept={kept_ports!r}"
    )
    assert _PORT_E["port"] in kept_ports, (
        f"Port {_PORT_E['port']} (no last_seen_at) should be KEPT; "
        f"kept={kept_ports!r}"
    )
    assert kept_ports == {
        _PORT_A["port"], _PORT_D["port"], _PORT_E["port"]
    }, f"Unexpected ports in result: {kept_ports!r}"


# ---------------------------------------------------------------------------
# Test 2: No naabu_last_scan_at — all ports kept unchanged
# ---------------------------------------------------------------------------

def test_no_naabu_scan_all_kept():
    """Without naabu_last_scan_at the function is a no-op."""
    meta = {
        "open_ports": [_PORT_B, _PORT_C],
    }
    result = _filter_stale_ports(meta, now=_NOW)
    assert result is meta or result == meta, (
        "Expected metadata returned unchanged when no naabu_last_scan_at"
    )


# ---------------------------------------------------------------------------
# Test 3: No open_ports key — returned unchanged
# ---------------------------------------------------------------------------

def test_no_open_ports_returned_unchanged():
    meta = {"naabu_last_scan_at": _NAABU_SCAN_AT}
    result = _filter_stale_ports(meta, now=_NOW)
    assert "open_ports" not in result, (
        f"open_ports should not appear: {result!r}"
    )


# ---------------------------------------------------------------------------
# Test 4: Shodan port exactly at grace boundary (now - 14d) — KEPT
# ---------------------------------------------------------------------------

def test_shodan_port_at_grace_boundary_kept():
    """A shodan port with last_seen_at == now - 14d is exactly on the boundary
    and should be kept (>= grace_cutoff)."""
    from datetime import timedelta
    boundary_ts = (_NOW - timedelta(days=14)).isoformat()
    entry = {
        "port": 9999,
        "sources": ["shodan"],
        "last_seen_at": boundary_ts,
    }
    result = _filter_stale_ports(
        {"naabu_last_scan_at": _NAABU_SCAN_AT, "open_ports": [entry]},
        now=_NOW,
    )
    kept_ports = {e["port"] for e in result["open_ports"]}
    assert 9999 in kept_ports, (
        f"Port 9999 at exact grace boundary should be KEPT; kept={kept_ports!r}"
    )


# ---------------------------------------------------------------------------
# Test 5: Shodan port one second past grace — DROPPED
# ---------------------------------------------------------------------------

def test_shodan_port_just_past_grace_dropped():
    """A shodan port with last_seen_at just beyond 14d is dropped."""
    from datetime import timedelta
    past_boundary_ts = (_NOW - timedelta(days=14, seconds=1)).isoformat()
    entry = {
        "port": 7777,
        "sources": ["shodan"],
        "last_seen_at": past_boundary_ts,
    }
    result = _filter_stale_ports(
        {"naabu_last_scan_at": _NAABU_SCAN_AT, "open_ports": [entry]},
        now=_NOW,
    )
    kept_ports = {e["port"] for e in result["open_ports"]}
    assert 7777 not in kept_ports, (
        f"Port 7777 just past grace should be DROPPED; kept={kept_ports!r}"
    )


# ---------------------------------------------------------------------------
# Test 6: Non-shodan stale port has no grace (even if only 1 day old)
# ---------------------------------------------------------------------------

def test_naabu_port_stale_no_grace():
    """A naabu port older than naabu_last_scan_at is dropped regardless of age."""
    entry = {
        "port": 6543,
        "sources": ["naabu"],
        "last_seen_at": "2026-06-18T23:59:59+00:00",  # 1 second before cutoff
    }
    result = _filter_stale_ports(
        {"naabu_last_scan_at": _NAABU_SCAN_AT, "open_ports": [entry]},
        now=_NOW,
    )
    kept_ports = {e["port"] for e in result["open_ports"]}
    assert 6543 not in kept_ports, (
        f"Stale naabu port should be DROPPED with no grace; kept={kept_ports!r}"
    )


# ---------------------------------------------------------------------------
# Test 7: Unparseable last_seen_at — entry kept (unchanged behavior)
# ---------------------------------------------------------------------------

def test_unparseable_timestamp_kept():
    entry = {
        "port": 1234,
        "sources": ["shodan"],
        "last_seen_at": "not-a-date",
    }
    result = _filter_stale_ports(
        {"naabu_last_scan_at": _NAABU_SCAN_AT, "open_ports": [entry]},
        now=_NOW,
    )
    kept_ports = {e["port"] for e in result["open_ports"]}
    assert 1234 in kept_ports, (
        f"Entry with unparseable timestamp should be KEPT; kept={kept_ports!r}"
    )


# ---------------------------------------------------------------------------
# Test 8: l7_confirmed port stale vs cutoff but within 3-day confirmed grace — KEPT
# ---------------------------------------------------------------------------

def test_confirmed_port_within_grace_kept():
    """A previously app-confirmed (l7_confirmed) naabu port that's stale vs the
    scan cutoff but within the 3-day confirmed grace is KEPT (flap-guard)."""
    entry = {
        "port": 80,
        "sources": ["naabu"],
        "l7_confirmed": True,
        "last_seen_at": "2026-06-17T00:00:00+00:00",  # 2d old: < cutoff, within 3d grace
    }
    result = _filter_stale_ports(
        {"naabu_last_scan_at": _NAABU_SCAN_AT, "open_ports": [entry]}, now=_NOW,
    )
    assert 80 in {e["port"] for e in result["open_ports"]}, (
        f"l7_confirmed port within confirmed grace should be KEPT; got {result['open_ports']!r}"
    )


# ---------------------------------------------------------------------------
# Test 9: l7_confirmed port older than the 3-day confirmed grace — DROPPED
# ---------------------------------------------------------------------------

def test_confirmed_port_past_grace_dropped():
    """An l7_confirmed port not re-confirmed for longer than the 3-day grace is
    treated as genuinely closed and DROPPED."""
    entry = {
        "port": 80,
        "sources": ["naabu"],
        "l7_confirmed": True,
        "last_seen_at": "2026-06-15T00:00:00+00:00",  # >3d old → past confirmed grace
    }
    result = _filter_stale_ports(
        {"naabu_last_scan_at": _NAABU_SCAN_AT, "open_ports": [entry]}, now=_NOW,
    )
    assert 80 not in {e["port"] for e in result["open_ports"]}, (
        f"l7_confirmed port past confirmed grace should be DROPPED; got {result['open_ports']!r}"
    )


# ---------------------------------------------------------------------------
# Standalone runner
# ---------------------------------------------------------------------------

def _run():
    tests = [
        test_combined_filter,
        test_no_naabu_scan_all_kept,
        test_no_open_ports_returned_unchanged,
        test_shodan_port_at_grace_boundary_kept,
        test_shodan_port_just_past_grace_dropped,
        test_naabu_port_stale_no_grace,
        test_unparseable_timestamp_kept,
        test_confirmed_port_within_grace_kept,
        test_confirmed_port_past_grace_dropped,
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
