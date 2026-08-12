"""Tests for _suppress_phantom_ports in app.api.assets.

Pure-assert style: no pytest dependency required.
Run with:  python -m app.tests.test_phantom_suppression       (from /app)
       or: pytest app/tests/test_phantom_suppression.py       (if pytest installed)
"""

from app.api.assets import _suppress_phantom_ports

# Fixed reference timestamp used throughout.
T = "2026-06-19T00:00:00+00:00"
T_OLD = "2026-06-10T00:00:00+00:00"  # older than T — nmap stale


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_entry(port: int, l7_confirmed, ts: str = T) -> dict:
    """Build a minimal open_ports entry."""
    entry: dict = {"port": port, "last_seen_at": ts}
    if l7_confirmed is not None:
        entry["l7_confirmed"] = l7_confirmed
    return entry


def _make_metadata(
    open_ports: list,
    naabu_last_scan_at: str | None = T,
    nmap_verified_at: str | None = T,
) -> dict:
    meta: dict = {"open_ports": open_ports}
    if naabu_last_scan_at is not None:
        meta["naabu_last_scan_at"] = naabu_last_scan_at
    if nmap_verified_at is not None:
        meta["nmap_verified_at"] = nmap_verified_at
    return meta


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_deception_host_drops_unconfirmed():
    """Deception host: 25 False entries dropped, 3 True entries kept."""
    ports = (
        [_make_entry(i + 1, False) for i in range(25)]
        + [_make_entry(i + 1001, True) for i in range(3)]
    )
    meta = _make_metadata(ports)
    result = _suppress_phantom_ports(meta)
    remaining = result["open_ports"]
    assert len(remaining) == 3, (
        f"Expected 3 entries after suppression, got {len(remaining)}"
    )
    for entry in remaining:
        assert entry.get("l7_confirmed") is True, (
            f"Expected l7_confirmed=True, got {entry!r}"
        )


def test_below_threshold_not_suppressed():
    """5 unconfirmed + 3 confirmed = 8 total; 5 < 20, no suppression."""
    ports = (
        [_make_entry(i + 1, False) for i in range(5)]
        + [_make_entry(i + 101, True) for i in range(3)]
    )
    meta = _make_metadata(ports)
    result = _suppress_phantom_ports(meta)
    remaining = result["open_ports"]
    assert len(remaining) == 8, (
        f"Expected 8 entries (no suppression, below threshold), got {len(remaining)}"
    )


def test_nmap_stale_fail_open():
    """nmap_verified_at older than naabu_last_scan_at → fail-open, keep all."""
    ports = [_make_entry(i + 1, False) for i in range(25)]
    meta = _make_metadata(ports, naabu_last_scan_at=T, nmap_verified_at=T_OLD)
    result = _suppress_phantom_ports(meta)
    remaining = result["open_ports"]
    assert len(remaining) == 25, (
        f"Expected 25 entries (nmap stale, fail-open), got {len(remaining)}"
    )


def test_missing_nmap_verified_at_fail_open():
    """No nmap_verified_at at all → unchanged (fail-open)."""
    ports = [_make_entry(i + 1, False) for i in range(25)]
    meta = _make_metadata(ports, nmap_verified_at=None)
    result = _suppress_phantom_ports(meta)
    remaining = result["open_ports"]
    assert len(remaining) == 25, (
        f"Expected 25 entries (no nmap_verified_at, fail-open), got {len(remaining)}"
    )


def test_legacy_entries_not_counted_or_dropped():
    """Entries with NO l7_confirmed field are not counted as unconfirmed and not dropped."""
    # 25 legacy entries (no l7_confirmed key), on a deception-eligible host
    ports = [_make_entry(i + 1, None) for i in range(25)]  # None → key omitted
    meta = _make_metadata(ports)
    result = _suppress_phantom_ports(meta)
    remaining = result["open_ports"]
    assert len(remaining) == 25, (
        f"Expected 25 legacy entries unchanged (count=0, no suppression), got {len(remaining)}"
    )
    # Confirm none have l7_confirmed key
    for entry in remaining:
        assert "l7_confirmed" not in entry, (
            f"Legacy entry should not have l7_confirmed field: {entry!r}"
        )


def test_confirmed_entry_always_kept():
    """A l7_confirmed=True entry is always retained, even on a deception host."""
    ports = (
        [_make_entry(i + 1, False) for i in range(25)]
        + [_make_entry(9999, True)]
    )
    meta = _make_metadata(ports)
    result = _suppress_phantom_ports(meta)
    remaining = result["open_ports"]
    assert len(remaining) == 1, (
        f"Expected 1 confirmed entry, got {len(remaining)}: {remaining!r}"
    )
    assert remaining[0]["port"] == 9999
    assert remaining[0]["l7_confirmed"] is True


# ---------------------------------------------------------------------------
# Standalone runner (no pytest required)
# ---------------------------------------------------------------------------

def _run():
    tests = [
        test_deception_host_drops_unconfirmed,
        test_below_threshold_not_suppressed,
        test_nmap_stale_fail_open,
        test_missing_nmap_verified_at_fail_open,
        test_legacy_entries_not_counted_or_dropped,
        test_confirmed_entry_always_kept,
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
