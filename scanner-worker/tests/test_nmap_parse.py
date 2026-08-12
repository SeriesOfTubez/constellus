"""Tests for _parse_nmap_xml in scanner-worker/main.py.

Pure-assert style: no pytest dependency required.
Run with (from /app inside the container):
    python tests/test_nmap_parse.py
"""

import sys
import os

# Allow running from /app (bind-mounted source root inside container)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import _parse_nmap_xml, _build_nmap_verify_cmd, _verify_subprocess_timeout

# ---------------------------------------------------------------------------
# Fixture XML strings
# ---------------------------------------------------------------------------

# 1. Host UP, one open port 80, service http, product Apache
_XML_ONE_OPEN_PORT = (
    '<nmaprun>'
    '<host>'
    '<status state="up"/>'
    '<address addr="1.2.3.4" addrtype="ipv4"/>'
    '<ports>'
    '<port protocol="tcp" portid="80">'
    '<state state="open"/>'
    '<service name="http" product="Apache"/>'
    '</port>'
    '</ports>'
    '</host>'
    '</nmaprun>'
)

# 2. Host UP, zero open ports (host element present but no open <port>)
_XML_ZERO_OPEN_PORTS = (
    '<nmaprun>'
    '<host>'
    '<status state="up"/>'
    '<address addr="1.2.3.4" addrtype="ipv4"/>'
    '<ports/>'
    '</host>'
    '</nmaprun>'
)

# 3. Host UP, one filtered port (must NOT be included)
_XML_FILTERED_PORT = (
    '<nmaprun>'
    '<host>'
    '<status state="up"/>'
    '<address addr="1.2.3.4" addrtype="ipv4"/>'
    '<ports>'
    '<port protocol="tcp" portid="443">'
    '<state state="filtered"/>'
    '<service name="https"/>'
    '</port>'
    '</ports>'
    '</host>'
    '</nmaprun>'
)

# 4. Empty string
_XML_EMPTY = ""

# 5. Garbage / unparseable
_XML_GARBAGE = "not xml <<<"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_one_open_port():
    """Host with one open port 80 (http/Apache) → scanned=True, 1 port entry."""
    scanned, ports = _parse_nmap_xml(_XML_ONE_OPEN_PORT, "1.2.3.4")
    assert scanned is True, f"Expected scanned=True, got {scanned!r}"
    assert len(ports) == 1, f"Expected 1 port, got {len(ports)}: {ports!r}"
    assert ports[0]["port"] == 80, f"Expected port 80, got {ports[0]['port']!r}"
    assert ports[0]["service"] == "http", f"Expected service='http', got {ports[0]['service']!r}"
    assert ports[0]["product"] == "Apache", f"Expected product='Apache', got {ports[0]['product']!r}"


def test_zero_open_ports_still_scanned():
    """Host with no open ports: scanned=True, ports=[] (critical: distinguishable from failure)."""
    scanned, ports = _parse_nmap_xml(_XML_ZERO_OPEN_PORTS, "1.2.3.4")
    assert scanned is True, f"Expected scanned=True (host element present), got {scanned!r}"
    assert ports == [], f"Expected empty ports list, got {ports!r}"


def test_filtered_port_excluded():
    """Filtered port must NOT appear in ports; host element is present so scanned=True."""
    scanned, ports = _parse_nmap_xml(_XML_FILTERED_PORT, "1.2.3.4")
    assert scanned is True, f"Expected scanned=True (host element present), got {scanned!r}"
    assert ports == [], f"Filtered port should not appear in ports, got {ports!r}"


def test_empty_string():
    """Empty string input → scanned=False, ports=[]."""
    scanned, ports = _parse_nmap_xml(_XML_EMPTY, "1.2.3.4")
    assert scanned is False, f"Expected scanned=False for empty input, got {scanned!r}"
    assert ports == [], f"Expected empty ports list, got {ports!r}"


def test_garbage_xml():
    """Garbage/unparseable input → scanned=False, ports=[] (ET.ParseError handled)."""
    scanned, ports = _parse_nmap_xml(_XML_GARBAGE, "1.2.3.4")
    assert scanned is False, f"Expected scanned=False for garbage XML, got {scanned!r}"
    assert ports == [], f"Expected empty ports list, got {ports!r}"


# ---------------------------------------------------------------------------
# _build_nmap_verify_cmd — gentle (tarpit) vs fast (normal) timing
# (command only; the subprocess timeout is computed separately — CodeQL #86)
# ---------------------------------------------------------------------------

def test_gentle_cmd_full_connect_slow():
    """Gentle (tarpit) verify: full-connect -sT at -T2 with --reason; -sV kept as
    the phantom discriminator; fast -T4 absent. Returns the command only."""
    cmd = _build_nmap_verify_cmd("1.2.3.4", [53, 80], gentle=True)
    assert "-sT" in cmd, cmd
    assert "-T2" in cmd, cmd
    assert "--reason" in cmd, cmd
    assert "-T4" not in cmd, cmd
    assert "-sV" in cmd, cmd
    # --host-timeout is an app-chosen literal (no user input in argv)
    assert cmd[cmd.index("--host-timeout") + 1] == "240s", cmd
    assert "53,80" in cmd, cmd
    assert cmd[-1] == "1.2.3.4", cmd   # target is last (no injection ahead of it)


def test_normal_cmd_fast_default():
    """Normal (non-tarpit) verify: fast -T4, no -sT/-T2/--reason; -sV kept.
    Returns the command only."""
    cmd = _build_nmap_verify_cmd("1.2.3.4", [443], gentle=False)
    assert "-T4" in cmd, cmd
    assert "-sT" not in cmd, cmd
    assert "-T2" not in cmd, cmd
    assert "--reason" not in cmd, cmd
    assert "-sV" in cmd, cmd
    assert cmd[cmd.index("--host-timeout") + 1] == "60s", cmd  # app-chosen literal


def test_verify_subprocess_timeout_budget():
    """Gentle scans get a roomier subprocess budget (>=300s); normal keep the
    caller's value. Computed apart from the argv builder so the numeric timeout
    never shares a return tuple with the command list (the real cause of #86)."""
    assert _verify_subprocess_timeout(120.0, gentle=True) >= 300.0
    assert _verify_subprocess_timeout(400.0, gentle=True) == 400.0   # already roomier
    assert _verify_subprocess_timeout(120.0, gentle=False) == 120.0


# ---------------------------------------------------------------------------
# Standalone runner (no pytest required)
# ---------------------------------------------------------------------------

def _run():
    tests = [
        test_one_open_port,
        test_zero_open_ports_still_scanned,
        test_filtered_port_excluded,
        test_empty_string,
        test_garbage_xml,
        test_gentle_cmd_full_connect_slow,
        test_normal_cmd_fast_default,
        test_verify_subprocess_timeout_budget,
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
