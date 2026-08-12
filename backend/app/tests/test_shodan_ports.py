"""Tests for _parse_host_ports and _iso_utc in app.connectors.shodan.

Pure-assert style: no pytest dependency required.
Run with:  python -m app.tests.test_shodan_ports       (from /app)
       or: pytest app/tests/test_shodan_ports.py       (if pytest installed)
"""

from app.connectors.shodan import _parse_host_ports, _iso_utc

# ---------------------------------------------------------------------------
# Representative fixture — 3 services:
#   port 22  : SSH with product, version, CPE, timestamp, module
#   port 443 : HTTPS with no product, only module + banner, own timestamp
#   port 8080: UDP, no timestamp (falls back to host last_update)
# ---------------------------------------------------------------------------
_HOST = {
    "last_update": "2026-06-03T00:00:00.000000",
    "ports": [22, 443, 8080],
    "data": [
        {
            "port": 22,
            "transport": "tcp",
            "product": "OpenSSH",
            "version": "8.9p1 Ubuntu",
            "data": "SSH-2.0-OpenSSH_8.9p1\n...",
            "cpe23": ["cpe:2.3:a:openbsd:openssh:8.9p1"],
            "timestamp": "2026-06-01T12:00:00.000000",
            "_shodan": {"module": "ssh"},
        },
        {
            "port": 443,
            "transport": "tcp",
            "data": "HTTP/1.1 200 OK\nServer: nginx",
            "timestamp": "2026-06-02T08:30:00.000000",
            "_shodan": {"module": "https"},
        },
        {
            "port": 8080,
            "transport": "udp",
            # no timestamp — should fall back to host last_update
            "_shodan": {"module": "http"},
        },
    ],
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_empty_host():
    """_parse_host_ports({}) returns an empty list without error."""
    result = _parse_host_ports({})
    assert result == [], f"Expected [], got {result!r}"


def test_invalid_port_skipped():
    """Ports outside 1-65535 or non-int values are skipped."""
    host = {
        "data": [
            {"port": 70000, "transport": "tcp"},  # > 65535
            {"port": 0, "transport": "tcp"},       # 0 is invalid
            {"port": "22", "transport": "tcp"},    # string, not int
            {"port": 80, "transport": "tcp"},      # valid
        ]
    }
    result = _parse_host_ports(host)
    assert len(result) == 1, f"Expected 1 entry, got {len(result)}: {result!r}"
    assert result[0]["port"] == 80


def test_result_count_and_sort_order():
    """Fixture yields exactly 3 entries, sorted by port ascending."""
    result = _parse_host_ports(_HOST)
    assert len(result) == 3, f"Expected 3 entries, got {len(result)}: {result!r}"
    ports = [e["port"] for e in result]
    assert ports == [22, 443, 8080], f"Expected [22, 443, 8080], got {ports!r}"


def test_all_entries_have_required_keys():
    """Every entry must have port (int), protocol (str), sources=['shodan'], last_seen_at (tz-aware str)."""
    result = _parse_host_ports(_HOST)
    for entry in result:
        assert isinstance(entry["port"], int), f"port not int: {entry!r}"
        assert isinstance(entry["protocol"], str), f"protocol not str: {entry!r}"
        assert entry["sources"] == ["shodan"], f"sources wrong: {entry!r}"
        assert isinstance(entry["last_seen_at"], str), f"last_seen_at not str: {entry!r}"
        assert "+00:00" in entry["last_seen_at"], (
            f"last_seen_at not UTC-aware: {entry['last_seen_at']!r}"
        )


def test_entry_port_22():
    """SSH entry: service, service_version, banner_snippet, cpe, shodan_module."""
    result = _parse_host_ports(_HOST)
    e22 = next(e for e in result if e["port"] == 22)

    assert e22["service"] == "OpenSSH", f"service wrong: {e22!r}"
    assert e22["service_version"] == "OpenSSH 8.9p1 Ubuntu", (
        f"service_version wrong: {e22!r}"
    )
    assert e22["banner_snippet"].startswith("SSH-2.0-OpenSSH"), (
        f"banner_snippet wrong: {e22!r}"
    )
    assert e22["cpe"] == ["cpe:2.3:a:openbsd:openssh:8.9p1"], f"cpe wrong: {e22!r}"
    assert e22["shodan_module"] == "ssh", f"shodan_module wrong: {e22!r}"
    assert e22["protocol"] == "tcp"
    # Timestamp from the svc entry, not host.last_update
    assert "2026-06-01" in e22["last_seen_at"], (
        f"last_seen_at should be 2026-06-01, got {e22['last_seen_at']!r}"
    )


def test_entry_port_443():
    """HTTPS entry: service falls back to module; no service_version key; banner present."""
    result = _parse_host_ports(_HOST)
    e443 = next(e for e in result if e["port"] == 443)

    assert e443["service"] == "https", f"service should be 'https' (module), got {e443!r}"
    assert "service_version" not in e443, (
        f"service_version should be absent (no product/version): {e443!r}"
    )
    assert "Server: nginx" in e443["banner_snippet"], (
        f"banner_snippet should contain 'Server: nginx': {e443!r}"
    )
    assert e443["shodan_module"] == "https"
    assert e443["protocol"] == "tcp"
    assert "2026-06-02" in e443["last_seen_at"], (
        f"last_seen_at should be 2026-06-02, got {e443['last_seen_at']!r}"
    )


def test_entry_port_8080_uses_host_last_update():
    """UDP entry with no per-service timestamp falls back to host.last_update."""
    result = _parse_host_ports(_HOST)
    e8080 = next(e for e in result if e["port"] == 8080)

    assert e8080["protocol"] == "udp", f"protocol should be udp: {e8080!r}"
    assert "2026-06-03" in e8080["last_seen_at"], (
        f"last_seen_at should use host last_update (2026-06-03), got {e8080['last_seen_at']!r}"
    )
    assert "+00:00" in e8080["last_seen_at"]


def test_duplicate_port_keeps_first():
    """When the same port appears twice, the first occurrence wins."""
    host = {
        "data": [
            {"port": 80, "transport": "tcp", "product": "FirstProduct"},
            {"port": 80, "transport": "tcp", "product": "SecondProduct"},
        ]
    }
    result = _parse_host_ports(host)
    assert len(result) == 1
    assert result[0]["service"] == "FirstProduct", (
        f"Expected FirstProduct (first wins), got {result[0].get('service')!r}"
    )


def test_banner_truncated_to_256():
    """Banners longer than 256 chars are truncated."""
    long_banner = "X" * 300
    host = {
        "data": [{"port": 9000, "transport": "tcp", "data": long_banner}]
    }
    result = _parse_host_ports(host)
    assert len(result) == 1
    assert len(result[0]["banner_snippet"]) == 256, (
        f"banner not truncated: len={len(result[0]['banner_snippet'])}"
    )


def test_iso_utc_naive_string():
    """_iso_utc converts a naive string to a UTC-aware ISO string."""
    out = _iso_utc("2026-06-01T12:00:00.000000")
    assert out is not None
    assert "+00:00" in out, f"Expected UTC offset, got {out!r}"


def test_iso_utc_falsy():
    """_iso_utc returns None for falsy or unparseable input."""
    assert _iso_utc(None) is None
    assert _iso_utc("") is None
    assert _iso_utc("not-a-date") is None


# ---------------------------------------------------------------------------
# Standalone runner (no pytest required)
# ---------------------------------------------------------------------------

def _run():
    tests = [
        test_empty_host,
        test_invalid_port_skipped,
        test_result_count_and_sort_order,
        test_all_entries_have_required_keys,
        test_entry_port_22,
        test_entry_port_443,
        test_entry_port_8080_uses_host_last_update,
        test_duplicate_port_keeps_first,
        test_banner_truncated_to_256,
        test_iso_utc_naive_string,
        test_iso_utc_falsy,
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
