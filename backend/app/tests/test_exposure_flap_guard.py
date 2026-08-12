"""Tests for _classify_ports in app.services.exposure_analyzer (planning#73).

Exposure findings must EMIT off ports seen this run (fresh) but RESOLVE off the
retained (post-prune) inventory — so a risky service that briefly flaps isn't
churned resolved↔open while the port-inventory flap-guard (planning#72) holds it.

Pure-assert style: no pytest dependency required.
Run with:  python -m app.tests.test_exposure_flap_guard        (from /app)
       or: pytest app/tests/test_exposure_flap_guard.py
"""

from datetime import datetime, timezone

from app.services.exposure_analyzer import _classify_ports

_SINCE = datetime(2026, 6, 19, 0, 0, 0, tzinfo=timezone.utc)  # run.started_at


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def test_fresh_port_in_both():
    """A port observed this run is both emit-eligible (fresh) and retained."""
    op = [{"port": 443, "l7_confirmed": True,
           "last_seen_at": "2026-06-19T00:01:00+00:00"}]
    fresh, retained = _classify_ports(op, _SINCE)
    assert [e["port"] for e in fresh] == [443]
    assert retained == {443}


def test_flapping_confirmed_port_retained_not_fresh():
    """THE FIX: an l7_confirmed port missed this run but still held in the pruned
    inventory (stale last_seen) is RETAINED (won't resolve) yet NOT fresh
    (won't re-emit) — no resolved↔open churn."""
    op = [
        {"port": 443, "l7_confirmed": True, "last_seen_at": "2026-06-19T00:01:00+00:00"},   # fresh -> gate passes
        {"port": 3389, "l7_confirmed": True, "last_seen_at": "2026-06-17T00:00:00+00:00"},  # 2d stale, kept by prune
    ]
    fresh, retained = _classify_ports(op, _SINCE)
    assert 3389 not in [e["port"] for e in fresh], "stale port must not re-emit"
    assert 3389 in retained, "stale-but-present port must NOT resolve (flap-guard)"
    assert 443 in retained and 443 in [e["port"] for e in fresh]


def test_phantom_excluded_from_both():
    """l7_confirmed is False = firewall phantom: never emits, never keeps a
    finding alive — excluded from fresh AND retained even when fresh-timed."""
    op = [{"port": 22, "l7_confirmed": False,
           "last_seen_at": "2026-06-19T00:01:00+00:00"}]
    fresh, retained = _classify_ports(op, _SINCE)
    assert fresh == []
    assert retained == set()


def test_retired_port_absent_from_retained():
    """A genuinely retired port is already pruned out of open_ports[], so it is
    absent from `retained` → its finding resolves. (Modeled by absence.)"""
    op = [{"port": 443, "l7_confirmed": True, "last_seen_at": "2026-06-19T00:01:00+00:00"}]
    _fresh, retained = _classify_ports(op, _SINCE)
    assert 1433 not in retained  # the closed MSSQL port left the inventory → would resolve


def test_no_timestamp_retained_not_fresh():
    """A present, non-phantom port with no timestamp can't be judged fresh, but
    it's still in the inventory → retained (won't resolve)."""
    op = [{"port": 3306, "l7_confirmed": True}]  # no last_seen_at
    fresh, retained = _classify_ports(op, _SINCE)
    assert fresh == []
    assert retained == {3306}


def test_garbage_entries_ignored():
    """Non-dict entries and dicts without an int port are skipped."""
    op = ["nope", {"no_port": 1}, {"port": "443"},
          {"port": 8080, "l7_confirmed": True, "last_seen_at": "2026-06-19T00:05:00+00:00"}]
    fresh, retained = _classify_ports(op, _SINCE)
    assert [e["port"] for e in fresh] == [8080]
    assert retained == {8080}


def _run():
    tests = [
        test_fresh_port_in_both,
        test_flapping_confirmed_port_retained_not_fresh,
        test_phantom_excluded_from_both,
        test_retired_port_absent_from_retained,
        test_no_timestamp_retained_not_fresh,
        test_garbage_entries_ignored,
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
