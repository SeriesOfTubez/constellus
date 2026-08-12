"""Chunk 4: active probers (banner_grab / httpx / tlsx) set l7_confirmed=True
when they extract real application-layer data, so a genuine service nmap -sV
missed is not wrongly suppressed as a firewall phantom.

Plain-assert; runs without pytest:  python -m app.tests.test_l7_corroboration
"""
from app.connectors.banner_grab import BannerGrabConnector
from app.connectors.httpx_probe import HttpxConnector
from app.connectors.tlsx import TlsxConnector


def _ports(result):
    out = {}
    for a in result.assets:
        for e in (a.asset_metadata.get("open_ports") or []):
            out[e["port"]] = e
    return out


def test_banner_grab_confirms_on_service():
    res = BannerGrabConnector()._build_phase_result([
        {"ip": "1.2.3.4", "port": 22, "service": "ssh", "banner": "SSH-2.0-OpenSSH"},
    ])
    e = _ports(res)[22]
    assert e["l7_confirmed"] is True, e


def test_banner_grab_no_data_not_confirmed():
    # A row with no service/banner/zgrab2 (e.g. connected but tcpwrapped) must
    # NOT claim confirmation — leave the key absent so nmap's verdict stands.
    res = BannerGrabConnector()._build_phase_result([
        {"ip": "1.2.3.4", "port": 9999},
    ])
    e = _ports(res)[9999]
    assert "l7_confirmed" not in e, e


def test_httpx_confirms_on_scheme():
    res = HttpxConnector()._build_phase_result([
        {"ip": "1.2.3.4", "port": 80, "scheme": "http", "webserver": "nginx"},
    ])
    e = _ports(res)[80]
    assert e["l7_confirmed"] is True, e


def test_tlsx_confirms_on_cert():
    res = TlsxConnector()._build_phase_result([
        {"host": "1.2.3.4", "ip": "1.2.3.4", "port": 443, "subject_cn": "example.com"},
    ])
    e = _ports(res)[443]
    assert e["l7_confirmed"] is True, e


def test_tlsx_no_cert_no_entry():
    # Non-TLS port: tlsx returns nothing useful → no entry at all (so it can
    # never falsely confirm a phantom).
    res = TlsxConnector()._build_phase_result([
        {"host": "1.2.3.4", "ip": "1.2.3.4", "port": 444},
    ])
    assert 444 not in _ports(res)


def _run():
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"OK: {name}")
    print("ALL PASS")


if __name__ == "__main__":
    _run()
