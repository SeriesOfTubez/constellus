"""Tests for NaabuConnector.port_scan tarpit handling.

A flooded (tarpit / scan-deception) host is re-discovered with `naabu -verify`
(x2 union, replacing its phantom baseline) and then verified GENTLY (-sT -T2 via
gentle_ips). Normal hosts are untouched. See planning#69/#72.

Pure-assert style: no pytest dependency required.
Run with:  python -m app.tests.test_tarpit_narrowing        (from /app)
       or: pytest app/tests/test_tarpit_narrowing.py
"""

import types

from app.connectors.naabu import NaabuConnector, _TARPIT_PORT_THRESHOLD
from app.models.asset import AssetType

TARPIT = "1.2.3.4"   # public; broad sweep returns a phantom flood (> threshold)
NORMAL = "8.8.8.8"   # public; few real ports, not a tarpit


def _ip_asset(value):
    return types.SimpleNamespace(
        asset_type=AssetType.IP_ADDRESS, value=value, asset_metadata={},
    )


def _config():
    return {
        "_tier": "test",
        "_aggressiveness": {"naabu": {
            "enabled": True, "top_ports": 1000, "rate": 1000, "concurrency": 25,
        }},
    }


def test_tarpit_rediscovered_with_verify_and_verified_gently():
    """Flooded host: replaced-by -verify (x2), flood dropped, gently verified.
    Normal host: baseline kept, not gentle."""
    conn = NaabuConnector()
    calls = []
    captured = {}
    flood = list(range(2000, 2000 + _TARPIT_PORT_THRESHOLD + 10))  # > threshold

    def fake_worker(*, hosts, top_ports, ports, exclude_ports, rate, concurrency, verify=False):
        calls.append({"hosts": list(hosts), "verify": verify})
        if verify:  # -verify narrows the flood to the real ports
            return [{"host": TARPIT, "ip": TARPIT, "port": p} for p in (53, 80)]
        rows = [{"host": TARPIT, "ip": TARPIT, "port": p} for p in flood]
        rows += [{"host": TARPIT, "ip": TARPIT, "port": p} for p in (53, 80)]
        rows += [{"host": NORMAL, "ip": NORMAL, "port": p} for p in (22, 443)]
        return rows

    def fake_nmap(merged, gentle_ips=None):
        captured["merged_keys"] = set(merged.keys())
        captured["gentle_ips"] = set(gentle_ips or ())
        return {}  # empty nmap_data → fail-open downstream; irrelevant to asserts

    conn._invoke_worker = fake_worker
    conn._invoke_nmap_verify = fake_nmap
    conn.port_scan([_ip_asset(TARPIT), _ip_asset(NORMAL)], _config())

    # tarpit IP re-discovered with naabu -verify (x2 union), scoped to just it
    verify_calls = [c for c in calls if c["verify"]]
    assert len(verify_calls) == 2, calls
    assert all(c["hosts"] == [TARPIT] for c in verify_calls), calls
    # exactly one broad (non-verify) sweep over both IPs
    broad = [c for c in calls if not c["verify"]]
    assert len(broad) == 1 and set(broad[0]["hosts"]) == {TARPIT, NORMAL}, calls

    # the phantom flood is GONE from the nmap candidate set; only -verify reals remain
    keys = captured["merged_keys"]
    assert (TARPIT, 53) in keys and (TARPIT, 80) in keys, keys
    assert not any(ip == TARPIT and 2000 <= p < 2100 for (ip, p) in keys), keys
    # non-tarpit host keeps its fast baseline untouched
    assert (NORMAL, 22) in keys and (NORMAL, 443) in keys, keys
    # only the tarpit IP is verified gently
    assert captured["gentle_ips"] == {TARPIT}, captured["gentle_ips"]


def test_no_tarpit_skips_verify_and_gentle():
    """A clean host (few ports) → no -verify re-discovery, no gentle verify."""
    conn = NaabuConnector()
    calls = []
    captured = {}

    def fake_worker(*, hosts, top_ports, ports, exclude_ports, rate, concurrency, verify=False):
        calls.append({"hosts": list(hosts), "verify": verify})
        return [{"host": NORMAL, "ip": NORMAL, "port": p} for p in (22, 443)]

    def fake_nmap(merged, gentle_ips=None):
        captured["gentle_ips"] = set(gentle_ips or ())
        return {}

    conn._invoke_worker = fake_worker
    conn._invoke_nmap_verify = fake_nmap
    conn.port_scan([_ip_asset(NORMAL)], _config())

    assert not any(c["verify"] for c in calls), calls   # no -verify pass
    assert captured["gentle_ips"] == set(), captured     # nothing gently verified


def test_prior_ports_folded_into_candidate_set():
    """A hydrated prior-confirmed port is added to the nmap-verify candidate set
    even when naabu's sweep missed it this run (the flaky port-80 dropout case)."""
    conn = NaabuConnector()
    captured = {}

    def fake_worker(*, hosts, top_ports, ports, exclude_ports, rate, concurrency, verify=False):
        return [{"host": NORMAL, "ip": NORMAL, "port": 443}]  # naabu found only 443

    def fake_nmap(merged, gentle_ips=None):
        captured["merged_keys"] = set(merged.keys())
        return {}

    conn._invoke_worker = fake_worker
    conn._invoke_nmap_verify = fake_nmap
    asset = _ip_asset(NORMAL)
    asset.asset_metadata = {"prior_ports": [80]}  # 80 confirmed on a prior run
    conn.port_scan([asset], _config())

    assert (NORMAL, 443) in captured["merged_keys"], captured  # naabu's find
    assert (NORMAL, 80) in captured["merged_keys"], captured   # prior seed re-verified


def _run():
    tests = [
        test_tarpit_rediscovered_with_verify_and_verified_gently,
        test_no_tarpit_skips_verify_and_gentle,
        test_prior_ports_folded_into_candidate_set,
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
