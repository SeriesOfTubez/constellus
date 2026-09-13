"""Regression tests for planning#160 — a scanner-worker outage must never
read as "we scanned and found nothing".

The bug: naabu and nuclei collapsed "the worker call failed" and "the
worker call timed out" into the same return value as "scanned and found
nothing". naabu's phase-result builder then wrote a fresh
`naabu_last_scan_at` — the staleness cutoff `_filter_stale_ports` reads —
for every in-scope IP, retiring every previously-known port on a run the
UI reported as a clean COMPLETED.

The port in the `_filter_stale_ports` test is deliberately PLAIN
naabu/nmap-discovered: neither `l7_confirmed` nor shodan-sourced. Those
carry 3-day/14-day grace windows, so a test written around them would
still pass with the bug present.

Addresses are RFC-5737 documentation ranges only. Python classifies those
ranges as private, so the test that exercises port_scan's orchestration
stubs `_is_public_ip` — the established pattern (test_wiz_ownership.py).

Run with:  python -m app.tests.test_worker_outage_absence
       or: pytest app/tests/test_worker_outage_absence.py
"""

import types
from datetime import datetime, timedelta, timezone

import httpx

from app.api.assets import _filter_stale_ports
from app.connectors import naabu
from app.connectors.base import PhaseResult
from app.connectors.naabu import NaabuConnector, WorkerResult
from app.connectors.nuclei import NucleiConnector
from app.models.asset import AssetType


# ── stub plumbing ──────────────────────────────────────────────────────────

class _Response:
    """Minimal httpx.Response stand-in for the worker transport."""

    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def _install_post(stub):
    """Swap httpx.post — the single transport seam both worker connectors
    call — and return a restore callable. Raw attribute assignment with an
    explicit restore: conftest.py's autouse snapshot fixture does not guard
    httpx, and this file also runs standalone via `python -m`."""
    original = httpx.post
    httpx.post = stub

    def restore():
        httpx.post = original

    return restore


def _install_public_ip_filter():
    """Stub naabu._is_public_ip to accept the RFC-5737 documentation
    addresses these tests are written with. Python classifies those ranges
    as private, so the real filter correctly rejects every address this
    repo is permitted to write down (same pattern as test_wiz_ownership)."""
    original = naabu._is_public_ip
    naabu._is_public_ip = lambda value: value.startswith(
        ("192.0.2.", "198.51.100.", "203.0.113.")
    )

    def restore():
        naabu._is_public_ip = original

    return restore


def _ip_asset(value):
    return types.SimpleNamespace(
        asset_type=AssetType.IP_ADDRESS, value=value, asset_metadata={},
    )


def _config():
    return {
        "_tier": "test",
        "_aggressiveness": {"naabu": {
            "enabled": True, "top_ports": 100, "rate": 500, "concurrency": 10,
        }},
    }


# ── naabu transport: failure is not emptiness ──────────────────────────────

def test_worker_http_error_yields_incomplete_result():
    """The primary bug path: an unreachable worker used to come back as
    `[]` — the same value as "scanned and the host has no open ports"."""
    def post_down(*args, **kwargs):
        raise httpx.HTTPError("worker unreachable")

    restore = _install_post(post_down)
    try:
        result = NaabuConnector()._invoke_worker(
            hosts=["192.0.2.10"], top_ports=100, ports=None,
            exclude_ports=[], rate=500, concurrency=10,
        )
    finally:
        restore()

    assert isinstance(result, WorkerResult)
    assert result.rows == []
    assert result.completed is False


def test_worker_timeout_is_incomplete_but_keeps_rows():
    """A timed-out pass is an incomplete pass — but rows recovered before
    the subprocess was killed are real observations and survive."""
    def post_timed_out(*args, **kwargs):
        return _Response({
            "results": [{"host": "192.0.2.10", "ip": "192.0.2.10", "port": 443}],
            "timed_out": True,
        })

    restore = _install_post(post_timed_out)
    try:
        result = NaabuConnector()._invoke_worker(
            hosts=["192.0.2.10"], top_ports=100, ports=None,
            exclude_ports=[], rate=500, concurrency=10,
        )
    finally:
        restore()

    assert isinstance(result, WorkerResult)
    assert result.completed is False
    assert len(result.rows) == 1


# ── naabu phase result: absence needs a completed baseline ─────────────────

def test_incomplete_baseline_emits_no_absence_patches():
    """Zero-port fill patches ARE the absence claim — an incomplete baseline
    must emit none of them, for any IP, and must say it was incomplete."""
    result = NaabuConnector()._build_phase_result(
        [], "tier", scanned_ips={"192.0.2.10", "192.0.2.11"},
        baseline_complete=False,
    )
    assert result.assets == []
    assert result.complete is False


def test_complete_baseline_still_emits_absence_patches():
    """Regression guard on the existing, correct behaviour: a COMPLETED
    baseline keeps advancing the cutoff so genuinely closed ports retire."""
    result = NaabuConnector()._build_phase_result(
        [], "tier", scanned_ips={"192.0.2.10", "192.0.2.11"},
        baseline_complete=True,
    )
    assert len(result.assets) == 2
    for patch in result.assets:
        assert patch.asset_metadata["open_ports"] == []
        assert "naabu_last_scan_at" in patch.asset_metadata
    assert result.complete is True


def test_incomplete_baseline_never_writes_scan_timestamp():
    """The case the obvious fix misses: even on an incomplete baseline,
    partial results can still confirm ports on some IPs (Shodan hints /
    prior ports re-confirmed by nmap). Those per-IP patches must record
    the ports — presence is safe — but must NOT carry a fresh
    naabu_last_scan_at, which would retire every *other* port on the
    same IP."""
    row = {
        "host": "192.0.2.10", "ip": "192.0.2.10", "port": 443,
        "service": "https", "product": "nginx",
    }
    result = NaabuConnector()._build_phase_result(
        [row], "tier", scanned_ips={"192.0.2.10"},
        baseline_complete=False,
    )
    assert len(result.assets) == 1
    patch = result.assets[0]
    assert [p["port"] for p in patch.asset_metadata["open_ports"]] == [443]
    assert "naabu_last_scan_at" not in patch.asset_metadata
    assert result.complete is False


def test_port_scan_incomplete_baseline_writes_nothing_and_reports_it():
    """The D2/D3 wiring end-to-end: a baseline the worker never completed
    produces an incomplete phase result that writes no patch at all — no
    per-IP patches, no zero-port fills — so nothing advances the
    staleness cutoff."""
    conn = NaabuConnector()

    def worker_dead(*, hosts, top_ports, ports, exclude_ports, rate,
                    concurrency, verify=False):
        return WorkerResult(rows=[], completed=False)

    conn._invoke_worker = worker_dead
    conn._invoke_nmap_verify = lambda merged, gentle_ips=None: {}

    restore = _install_public_ip_filter()
    try:
        result = conn.port_scan([_ip_asset("192.0.2.10")], _config())
    finally:
        restore()

    assert result.assets == []
    assert result.complete is False


# ── the staleness filter: no cutoff, no retirement ─────────────────────────

def test_stale_filter_keeps_plain_port_when_timestamp_absent():
    """End-to-end proof of the fix's mechanism. With no naabu_last_scan_at
    (an incomplete pass wrote none) the staleness filter keeps every port —
    it only ever prunes against a cutoff a completed scan wrote. The port
    is PLAIN naabu/nmap-discovered on purpose: l7_confirmed and shodan
    entries carry grace windows that would keep it visible even with the
    bug present, making the assert vacuous."""
    now = datetime.now(timezone.utc)
    plain_port = {
        "port": 22,
        "protocol": "tcp",
        "sources": ["naabu", "nmap"],
        "last_seen_at": (now - timedelta(days=30)).isoformat(),
    }

    filtered = _filter_stale_ports({"open_ports": [plain_port]}, now=now)
    assert filtered["open_ports"] == [plain_port], (
        "a plain 30-day-old port must survive when no scan timestamp exists"
    )

    # Contrast: had the incomplete pass written a fresh cutoff anyway, the
    # same port would have been retired. This is what makes the assert
    # above a real regression guard rather than a vacuous pass.
    retired = _filter_stale_ports(
        {"open_ports": [plain_port], "naabu_last_scan_at": now.isoformat()},
        now=now,
    )
    assert retired["open_ports"] == []


# ── nuclei: a failed scan is not a clean one ───────────────────────────────

def test_nuclei_worker_failure_is_incomplete():
    def post_down(*args, **kwargs):
        raise httpx.HTTPError("worker unreachable")

    restore = _install_post(post_down)
    try:
        result = NucleiConnector().scan(["example.com"], {})
    finally:
        restore()

    assert result.complete is False
    assert result.findings == []


def test_nuclei_timeout_keeps_findings_but_is_incomplete():
    """D4 for nuclei: a timed-out pass keeps its recovered findings (real
    observations) but reports complete=False — absence not inferable."""
    def post_timed_out(*args, **kwargs):
        return _Response({
            "timed_out": True,
            "findings": [{
                "host": "192.0.2.10",
                "matched-at": "http://192.0.2.10:80/example",
                "template-id": "detected-tech",
                "info": {
                    "name": "Detected Technology", "severity": "info",
                    "tags": ["tech"],
                },
            }],
        })

    restore = _install_post(post_timed_out)
    try:
        result = NucleiConnector().scan(["192.0.2.10"], {})
    finally:
        restore()

    assert result.complete is False
    assert len(result.findings) == 1


def test_phase_result_defaults_to_complete():
    """The guard that the new field cannot silently degrade every other
    connector: absent an explicit signal, a phase result is complete."""
    assert PhaseResult().complete is True


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
