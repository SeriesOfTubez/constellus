"""Tests for _prune_stale_ports in app.services.asset_writer (write-time stale drop).

Mirror of the read-time _filter_stale_ports, including the confirmed-port
flap-guard grace (planning#69/#72).

Pure-assert style: no pytest dependency required.
Run with:  python -m app.tests.test_prune_stale_ports        (from /app)
       or: pytest app/tests/test_prune_stale_ports.py
"""

from datetime import datetime, timezone

from app.services.projector import _prune_stale_ports

_CUTOFF = "2026-06-19T00:00:00+00:00"          # naabu_last_scan_at
_NOW = datetime(2026, 6, 19, 1, 0, 0, tzinfo=timezone.utc)


def _ports(rows):
    return {e["port"] for e in rows}


def test_fresh_port_kept():
    """Re-observed at/after the cutoff → kept."""
    e = {"port": 80, "sources": ["naabu"], "last_seen_at": "2026-06-19T00:30:00+00:00"}
    assert 80 in _ports(_prune_stale_ports([e], _CUTOFF, _NOW))


def test_stale_unconfirmed_naabu_dropped():
    """A bare naabu port older than the cutoff, never app-confirmed → dropped."""
    e = {"port": 443, "sources": ["naabu"], "last_seen_at": "2026-06-18T00:00:00+00:00"}
    assert 443 not in _ports(_prune_stale_ports([e], _CUTOFF, _NOW))


def test_confirmed_within_grace_kept():
    """l7_confirmed port stale vs cutoff but within the 3-day grace → kept (flap-guard)."""
    e = {"port": 80, "sources": ["naabu"], "l7_confirmed": True,
         "last_seen_at": "2026-06-17T00:00:00+00:00"}  # 2d old
    assert 80 in _ports(_prune_stale_ports([e], _CUTOFF, _NOW))


def test_confirmed_past_grace_dropped():
    """l7_confirmed port not re-confirmed for >3 days → dropped (genuinely closed)."""
    e = {"port": 80, "sources": ["naabu"], "l7_confirmed": True,
         "last_seen_at": "2026-06-15T00:00:00+00:00"}  # >3d old
    assert 80 not in _ports(_prune_stale_ports([e], _CUTOFF, _NOW))


def test_shodan_within_grace_kept():
    """Shodan intel within the 14-day Shodan grace is still kept (unchanged)."""
    e = {"port": 8022, "sources": ["shodan"], "last_seen_at": "2026-06-10T00:00:00+00:00"}  # 9d
    assert 8022 in _ports(_prune_stale_ports([e], _CUTOFF, _NOW))


def test_no_timestamp_kept():
    """No last_seen_at → can't judge staleness → kept."""
    e = {"port": 22, "sources": ["naabu"]}
    assert 22 in _ports(_prune_stale_ports([e], _CUTOFF, _NOW))


def _run():
    tests = [
        test_fresh_port_kept,
        test_stale_unconfirmed_naabu_dropped,
        test_confirmed_within_grace_kept,
        test_confirmed_past_grace_dropped,
        test_shodan_within_grace_kept,
        test_no_timestamp_kept,
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
