"""Tests for _hydrate_asset_ports in app.services.scan_executor.

Pure-assert style: no pytest dependency required.
Run with:  python -m app.tests.test_port_hydration       (from /app)
       or: pytest app/tests/test_port_hydration.py       (if pytest installed)
"""

import types

from app.services.scan_executor import _hydrate_asset_ports


def _make_asset(value="1.2.3.4", asset_type="ip_address", metadata=None):
    """Return a minimal stub asset with .asset_metadata."""
    return types.SimpleNamespace(
        asset_type=asset_type,
        value=value,
        asset_metadata=dict(metadata) if metadata is not None else {},
    )


# ---------------------------------------------------------------------------
# Test 1: shodan_ports merged; shodan open_ports hydrated; naabu port NOT hydrated
# ---------------------------------------------------------------------------

def test_shodan_ports_and_open_ports_hydration():
    """shodan_ports and shodan-sourced open_ports are hydrated; naabu port is not."""
    asset = _make_asset(metadata={})
    persisted_meta = {
        "shodan_ports": [22, 443],
        "open_ports": [
            {
                "port": 22,
                "protocol": "tcp",
                "sources": ["shodan"],
                "last_seen_at": "2026-06-01T00:00:00+00:00",
                "service": "OpenSSH",
            },
            {
                "port": 80,
                "protocol": "tcp",
                "sources": ["naabu"],
                "last_seen_at": "2026-06-10T00:00:00+00:00",
            },
        ],
    }
    _hydrate_asset_ports(asset, persisted_meta)

    meta = asset.asset_metadata
    assert meta["shodan_ports"] == [22, 443], (
        f"shodan_ports wrong: {meta['shodan_ports']!r}"
    )

    open_ports = meta.get("open_ports", [])
    ports_in_result = {e["port"] for e in open_ports}

    assert 22 in ports_in_result, (
        f"Port 22 (shodan) should be hydrated; open_ports={open_ports!r}"
    )
    assert 80 not in ports_in_result, (
        f"Port 80 (naabu) must NOT be hydrated; open_ports={open_ports!r}"
    )

    # Verify the shodan entry's service and last_seen_at are preserved
    e22 = next(e for e in open_ports if e["port"] == 22)
    assert e22.get("service") == "OpenSSH", (
        f"service not preserved on port 22: {e22!r}"
    )
    assert e22.get("last_seen_at") == "2026-06-01T00:00:00+00:00", (
        f"last_seen_at not preserved on port 22: {e22!r}"
    )


# ---------------------------------------------------------------------------
# Test 2: merge over existing in-batch naabu entry — sources unioned, newer ts wins
# ---------------------------------------------------------------------------

def test_merge_over_existing_naabu_entry():
    """When in-batch already has a naabu entry for a Shodan port, sources are
    unioned and the newer last_seen_at wins."""
    asset = _make_asset(metadata={
        "open_ports": [
            {
                "port": 22,
                "protocol": "tcp",
                "sources": ["naabu"],
                "last_seen_at": "2026-06-15T00:00:00+00:00",
                "service": "OpenSSH 9",
            },
        ],
    })
    persisted_meta = {
        "shodan_ports": [22],
        "open_ports": [
            {
                "port": 22,
                "protocol": "tcp",
                "sources": ["shodan"],
                "last_seen_at": "2026-06-01T00:00:00+00:00",
                "service": "OpenSSH",
            },
        ],
    }
    _hydrate_asset_ports(asset, persisted_meta)

    open_ports = asset.asset_metadata.get("open_ports", [])
    assert len(open_ports) == 1, (
        f"Expected exactly one port-22 entry, got {len(open_ports)}: {open_ports!r}"
    )
    e22 = open_ports[0]
    assert e22["port"] == 22

    sources = e22.get("sources", [])
    assert "naabu" in sources, f"'naabu' missing from sources: {sources!r}"
    assert "shodan" in sources, f"'shodan' missing from sources: {sources!r}"

    # Newer timestamp (2026-06-15, from naabu) must win over older (2026-06-01, shodan)
    assert e22["last_seen_at"] == "2026-06-15T00:00:00+00:00", (
        f"last_seen_at should be the newer 2026-06-15 timestamp, got {e22['last_seen_at']!r}"
    )


# ---------------------------------------------------------------------------
# Test 3: persisted_meta None — no crash, metadata stays empty
# ---------------------------------------------------------------------------

def test_none_persisted_meta_no_crash():
    """Passing an empty dict for persisted_meta must not crash."""
    asset = _make_asset(metadata={})
    _hydrate_asset_ports(asset, {})
    assert asset.asset_metadata == {}, (
        f"metadata should stay empty, got {asset.asset_metadata!r}"
    )


# ---------------------------------------------------------------------------
# Test 4: asset_metadata starts as None — treated as empty dict
# ---------------------------------------------------------------------------

def test_asset_metadata_none_handled():
    """asset.asset_metadata=None is handled defensively."""
    asset = types.SimpleNamespace(
        asset_type="ip_address",
        value="5.6.7.8",
        asset_metadata=None,
    )
    persisted_meta = {
        "shodan_ports": [443],
        "open_ports": [
            {
                "port": 443,
                "protocol": "tcp",
                "sources": ["shodan"],
                "last_seen_at": "2026-06-01T00:00:00+00:00",
            },
        ],
    }
    _hydrate_asset_ports(asset, persisted_meta)
    meta = asset.asset_metadata
    assert isinstance(meta, dict), f"asset_metadata should be a dict, got {type(meta)}"
    assert meta.get("shodan_ports") == [443], (
        f"shodan_ports wrong: {meta.get('shodan_ports')!r}"
    )
    assert any(e["port"] == 443 for e in (meta.get("open_ports") or [])), (
        f"Port 443 should be hydrated; open_ports={meta.get('open_ports')!r}"
    )


# ---------------------------------------------------------------------------
# Test 5: persisted open_ports with no shodan entries — nothing hydrated
# ---------------------------------------------------------------------------

def test_no_shodan_open_ports_nothing_hydrated():
    """When persisted open_ports contain only non-shodan entries, open_ports
    on the in-batch asset remains absent."""
    asset = _make_asset(metadata={})
    persisted_meta = {
        "open_ports": [
            {
                "port": 8080,
                "protocol": "tcp",
                "sources": ["naabu"],
                "last_seen_at": "2026-06-10T00:00:00+00:00",
            },
        ],
    }
    _hydrate_asset_ports(asset, persisted_meta)
    open_ports = asset.asset_metadata.get("open_ports")
    assert not open_ports, (
        f"No shodan entries — open_ports should be absent/empty, got {open_ports!r}"
    )


# ---------------------------------------------------------------------------
# Test 6: prior app-confirmed ports → prior_ports hint (l7_confirmed only)
# ---------------------------------------------------------------------------

def test_prior_confirmed_ports_hydrated():
    """open_ports entries with l7_confirmed=True become the prior_ports hint;
    unconfirmed (False / missing) entries are excluded."""
    asset = _make_asset(metadata={})
    persisted_meta = {
        "open_ports": [
            {"port": 80, "sources": ["naabu"], "l7_confirmed": True},        # → seed
            {"port": 53, "sources": ["banner_grab"], "l7_confirmed": True},  # → seed
            {"port": 9101, "sources": ["naabu"], "l7_confirmed": False},     # phantom → excluded
            {"port": 7, "sources": ["shodan"]},                              # no l7 field → excluded
        ],
    }
    _hydrate_asset_ports(asset, persisted_meta)
    assert asset.asset_metadata.get("prior_ports") == [53, 80], (
        f"prior_ports should be the l7_confirmed set: {asset.asset_metadata.get('prior_ports')!r}"
    )


# ---------------------------------------------------------------------------
# Standalone runner
# ---------------------------------------------------------------------------

def _run():
    tests = [
        test_shodan_ports_and_open_ports_hydration,
        test_merge_over_existing_naabu_entry,
        test_none_persisted_meta_no_crash,
        test_asset_metadata_none_handled,
        test_no_shodan_open_ports_nothing_hydrated,
        test_prior_confirmed_ports_hydrated,
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
