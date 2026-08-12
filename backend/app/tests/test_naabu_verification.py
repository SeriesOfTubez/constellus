"""Tests for NaabuConnector._apply_nmap_verification — nmap-authoritative gating.

Pure-assert style: no pytest dependency required.
Run with:  python -m app.tests.test_naabu_verification        (from /app)
"""

from app.connectors.naabu import NaabuConnector

IP = "1.2.3.4"


def _merged(*entries):
    """entries: (port, hint_source|None) → merged dict keyed by (ip, port)."""
    m = {}
    for port, hint in entries:
        row = {"ip": IP, "host": IP, "port": port}
        if hint:
            row["hint_source"] = hint
        m[(IP, port)] = row
    return m


def test_keeps_only_nmap_confirmed_open():
    """The core fix: a naabu discovery nmap did NOT confirm open (returned
    nothing) is DROPPED — not kept-on-trust. Only nmap-confirmed-open survives."""
    conn = NaabuConnector()
    merged = _merged((80, None), (53, None), (1001, None))
    nmap_data = {IP: {
        80: {"service": "http", "product": "Apache", "version": "2.4.6"},
        # 53 absent → nmap returned nothing (filtered/closed) → must drop
        1001: {"service": "tcpwrapped"},  # handshake, no app data → must drop
    }}
    out = conn._apply_nmap_verification(merged, nmap_data)
    assert set(out) == {(IP, 80)}, out
    assert out[(IP, 80)]["service"] == "http"


def test_hint_kept_only_if_confirmed():
    """A Shodan hint is kept only if nmap confirms a real service on it."""
    conn = NaabuConnector()
    merged = _merged((4433, "shodan"), (9999, "shodan"))
    nmap_data = {IP: {4433: {"service": "https", "product": "nginx"}}}  # 9999 silent
    out = conn._apply_nmap_verification(merged, nmap_data)
    assert set(out) == {(IP, 4433)}, out


def test_tcpwrapped_dropped_for_both_sources():
    conn = NaabuConnector()
    merged = _merged((22, None), (8080, "shodan"))
    nmap_data = {IP: {
        22: {"service": "tcpwrapped"},
        8080: {"service": "tcpwrapped"},
    }}
    assert conn._apply_nmap_verification(merged, nmap_data) == {}


def test_fail_open_when_nmap_unavailable():
    """nmap unavailable + FEW ports → fail OPEN to naabu discoveries, drop hints."""
    conn = NaabuConnector()
    merged = _merged((80, None), (443, None), (4433, "shodan"))
    out = conn._apply_nmap_verification(merged, {})
    assert set(out) == {(IP, 80), (IP, 443)}, out  # hints dropped, discoveries kept


def test_fail_closed_when_nmap_unavailable_and_many_ports():
    """nmap unavailable + MANY ports (flood-protection noise) → fail CLOSED.
    Prevents the phantom leak where an empty nmap result let all naabu finds
    through (the live tarpit bug)."""
    conn = NaabuConnector()
    merged = _merged(*[(p, None) for p in range(1000, 1030)])  # 30 naabu ports
    assert conn._apply_nmap_verification(merged, {}) == {}


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
