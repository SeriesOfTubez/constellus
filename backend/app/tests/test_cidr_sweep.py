"""Tests for planning#161 — the CIDR sweep.

Background: a CIDR target was never scanned. `_run_pipeline` read
`ip_ranges` into a local and used it in exactly one place (the
`skip_discovery` seed), so the normal discovery path — which loops
`domains` only — gave a CIDR-only scope zero assets and a silent green
COMPLETED run. `NaabuConnector.port_scan` never saw scope at all.

The fix has three parts, each covered below:
  1. The seam — `scan_executor._run_pipeline` injects
     `config["_ip_ranges"]` into every Phase 1.5 connector's config (only
     naabu reads it), and seeds a placeholder asset so a CIDR-only chunk
     still reaches Phase 1.5 at all (the planning#161 seeding block in
     `_run_pipeline`, just above the `if all_assets:` gate).
  2. `NaabuConnector.port_scan` sweeps every CIDR that is public/global
     and within `MAX_SWEEP_ADDRESSES`, folding responding hosts (new
     `ip_address` assets) into its `PhaseResult`.
  3. The run-level interim guard near `_set_status(..., COMPLETED, ...)`
     in `scan_executor._run` now reports a CIDR only when it was NOT
     actually attempted (non-public, oversized, or naabu disabled/
     unavailable) — a clean sweep that finds nothing is a real result.

Address hygiene: every "public" CIDR/IP below is an RFC-5737 documentation
address with a stubbed predicate (`is_public_network`/`is_public_ip`),
matching the established pattern in test_worker_outage_absence.py — this
repo's pre-commit hook forbids real routable addresses in tracked files,
and every real predicate would reject RFC-5737 space anyway (that's the
whole point of it being reserved for documentation).

Run with:  python -m app.tests.test_cidr_sweep
       or: pytest app/tests/test_cidr_sweep.py

Some tests drive the real dev DB (no dedicated test DB exists — see
CLAUDE.md / test_run_reaper.py) by creating a throwaway ScanRun row and a
stub connector, then deleting the row afterward. Nothing here writes a
real asset: the stub connectors used against the full `_run()` path never
return assets, so `write_assets` is never reached for them.
"""

import logging
import types
import uuid

from app.connectors import naabu
from app.connectors.base import PhaseResult
from app.connectors.naabu import NaabuConnector, WorkerResult
from app.core.database import SessionLocal
from app.models.asset import AssetType
from app.models.scan import ScanRun, ScanStatus
from app.services import app_settings as settings_svc
from app.services import connector_config
from app.services import scan_executor


# ── shared stub plumbing (mirrors test_worker_outage_absence.py) ───────────

def _install_public_network_filter(accepted: set[str]):
    """Stub naabu._is_public_network to accept exactly the given RFC-5737
    CIDR strings. The real predicate correctly rejects every documentation
    range, which is the whole reason it needs stubbing here."""
    original = naabu._is_public_network
    naabu._is_public_network = lambda value: value in accepted

    def restore():
        naabu._is_public_network = original

    return restore


def _install_public_ip_filter(prefixes=("192.0.2.", "198.51.100.", "203.0.113.")):
    original = naabu._is_public_ip
    naabu._is_public_ip = lambda value: value.startswith(prefixes)

    def restore():
        naabu._is_public_ip = original

    return restore


def _ip_asset(value):
    return types.SimpleNamespace(asset_type=AssetType.IP_ADDRESS, value=value, asset_metadata={})


def _config(**overrides):
    cfg = {
        "_tier": "test",
        "_aggressiveness": {"naabu": {
            "enabled": True, "top_ports": 100, "rate": 500, "concurrency": 10,
        }},
    }
    cfg.update(overrides)
    return cfg


class _CaptureLogHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record):
        self.messages.append(record.getMessage())


# ── 1. naabu.port_scan: public CIDR reaches the worker ─────────────────────

def test_public_cidr_reaches_invoke_worker_hosts():
    """config["_ip_ranges"] must flow through to _invoke_worker's `hosts`
    for the baseline pass, once it passes the public/size checks."""
    conn = NaabuConnector()
    calls: list[list[str]] = []

    def fake_invoke_worker(*, hosts, top_ports, ports, exclude_ports, rate,
                            concurrency, verify=False):
        calls.append(list(hosts))
        return WorkerResult(rows=[], completed=True)

    conn._invoke_worker = fake_invoke_worker
    conn._invoke_nmap_verify = lambda merged, gentle_ips=None: {}

    cidr = "203.0.113.0/28"
    restore = _install_public_network_filter({cidr})
    try:
        result = conn.port_scan([], _config(_ip_ranges=[cidr]))
    finally:
        restore()

    assert len(calls) == 1, f"expected exactly one baseline worker call, got {calls!r}"
    assert cidr in calls[0], f"CIDR never reached the worker's hosts: {calls[0]!r}"
    assert result.assets == []  # no rows returned, nothing to report


def test_non_public_cidr_never_reaches_the_worker():
    """Without the predicate stubbed, the real is_public_network rejects
    RFC-5737 space — proof the filter is actually load-bearing, not a
    passthrough (the trap called out in the issue: a test that seeds a
    documentation CIDR and expects it to be scanned passes for the wrong
    reason unless the predicate is exercised for real somewhere)."""
    conn = NaabuConnector()
    calls: list[list[str]] = []

    def fake_invoke_worker(*, hosts, top_ports, ports, exclude_ports, rate,
                            concurrency, verify=False):
        calls.append(list(hosts))
        return WorkerResult(rows=[], completed=True)

    conn._invoke_worker = fake_invoke_worker
    conn._invoke_nmap_verify = lambda merged, gentle_ips=None: {}

    result = conn.port_scan([], _config(_ip_ranges=["192.0.2.0/24"]))

    assert calls == [], "a non-public CIDR must never reach the worker"
    assert result.assets == []
    assert result.complete is True  # a legitimate no-op, not a failure


# ── 2. size cap ──────────────────────────────────────────────────────────

def test_oversized_cidr_is_skipped_and_reason_recorded():
    """A CIDR whose address count exceeds the cap is skipped outright, not
    truncated — and the skip reason is logged (naabu has no other
    reporting channel; see the port_scan docstring / planning#161)."""
    conn = NaabuConnector()
    calls: list[list[str]] = []

    def fake_invoke_worker(*, hosts, top_ports, ports, exclude_ports, rate,
                            concurrency, verify=False):
        calls.append(list(hosts))
        return WorkerResult(rows=[], completed=True)

    conn._invoke_worker = fake_invoke_worker
    conn._invoke_nmap_verify = lambda merged, gentle_ips=None: {}

    oversized = "203.0.113.0/24"  # 256 addresses
    restore_net = _install_public_network_filter({oversized})
    restore_ip = _install_public_ip_filter()
    handler = _CaptureLogHandler()
    naabu.log.addHandler(handler)
    naabu.log.setLevel(logging.WARNING)
    try:
        # A known IP asset is also present so the connector doesn't just
        # early-return before ever building the skip list.
        result = conn.port_scan(
            [_ip_asset("203.0.113.99")],
            _config(_ip_ranges=[oversized], max_sweep_addresses=4),
        )
    finally:
        restore_net()
        restore_ip()
        naabu.log.removeHandler(handler)

    assert len(calls) == 1
    assert oversized not in calls[0], "oversized CIDR must not reach the worker"
    assert "203.0.113.99" in calls[0], "the real IP asset must still be swept"
    assert any(oversized in msg and "exceeds" in msg for msg in handler.messages), (
        f"skip reason was not logged: {handler.messages!r}"
    )
    # The known IP asset still gets its normal (empty, since the worker
    # returned no rows) patch — only the oversized CIDR contributed nothing.
    assert {a.value for a in result.assets} == {"203.0.113.99"}


# ── 3. responders become assets ─────────────────────────────────────────────

def test_responding_cidr_host_becomes_new_asset():
    """A host that only responded because it was inside a swept CIDR has
    no pre-existing asset — port_scan must mint one, distinct from the
    per-IP open_ports metadata patch `_build_phase_result` already
    builds."""
    conn = NaabuConnector()

    def fake_invoke_worker(*, hosts, top_ports, ports, exclude_ports, rate,
                            concurrency, verify=False):
        if verify:
            return WorkerResult(rows=[], completed=True)
        return WorkerResult(
            rows=[{"host": "203.0.113.5", "ip": "203.0.113.5", "port": 80}],
            completed=True,
        )

    conn._invoke_worker = fake_invoke_worker
    conn._invoke_nmap_verify = lambda merged, gentle_ips=None: {
        "203.0.113.5": {80: {
            "service": "http", "product": "nginx", "version": None, "extra_info": None,
        }},
    }

    cidr = "203.0.113.0/28"
    restore_net = _install_public_network_filter({cidr})
    restore_ip = _install_public_ip_filter()
    try:
        result = conn.port_scan([], _config(_ip_ranges=[cidr]))
    finally:
        restore_net()
        restore_ip()

    new_assets = [a for a in result.assets if a.value == "203.0.113.5"]
    assert new_assets, f"no asset minted for the responding host: {result.assets!r}"
    assert all(a.asset_type == AssetType.IP_ADDRESS for a in new_assets)
    # And the open_ports metadata patch is still there, unchanged.
    patched = [a for a in new_assets if a.asset_metadata.get("open_ports")]
    assert patched, "the existing per-IP metadata patch must still be emitted"
    assert patched[0].asset_metadata["open_ports"][0]["port"] == 80


def test_known_ip_in_cidr_range_is_not_duplicated_as_new():
    """A host that WAS already a known asset (e.g. discovered by a prior
    run, now inside a newly-declared CIDR target) must not be reported as
    a freshly-minted new host — only genuinely unknown responders are."""
    conn = NaabuConnector()

    def fake_invoke_worker(*, hosts, top_ports, ports, exclude_ports, rate,
                            concurrency, verify=False):
        if verify:
            return WorkerResult(rows=[], completed=True)
        return WorkerResult(
            rows=[{"host": "203.0.113.5", "ip": "203.0.113.5", "port": 80}],
            completed=True,
        )

    conn._invoke_worker = fake_invoke_worker
    conn._invoke_nmap_verify = lambda merged, gentle_ips=None: {
        "203.0.113.5": {80: {
            "service": "http", "product": "nginx", "version": None, "extra_info": None,
        }},
    }

    cidr = "203.0.113.0/28"
    restore_net = _install_public_network_filter({cidr})
    restore_ip = _install_public_ip_filter()
    try:
        result = conn.port_scan([_ip_asset("203.0.113.5")], _config(_ip_ranges=[cidr]))
    finally:
        restore_net()
        restore_ip()

    # Exactly one asset for this host — the metadata patch — not a second
    # bare "new host" marker on top of it.
    matching = [a for a in result.assets if a.value == "203.0.113.5"]
    assert len(matching) == 1, f"known host duplicated as new: {result.assets!r}"


# ── 4. the executor seam: config["_ip_ranges"] ──────────────────────────────

class _CaptureConnector:
    """Minimal Phase 1.5 stand-in. `observer = "naabu"` reuses the real
    seeded observer row (migration 0039) so probe_authorisation's
    connector-declaration check resolves it — same trick as
    test_probe_authorisation.py's `_StubConnector`."""
    observer = "naabu"

    def __init__(self):
        self.calls: list[dict] = []

    def port_scan(self, assets, config):
        self.calls.append(config)
        return PhaseResult()


def _set_probe_mode(db, value):
    from app.models.app_settings import AppSetting
    if value is None:
        db.query(AppSetting).filter(AppSetting.key == "probe_authorisation_mode").delete()
        db.commit()
    else:
        settings_svc.set_value(db, "probe_authorisation_mode", value)


def _run_pipeline_with_stub(chunk_scope: dict, tier: str = "standard"):
    """Drive `_run_pipeline` directly against a throwaway chunk, with a
    stub registry of exactly one connector so no real network call or
    unrelated connector runs. Returns the connector so its captured calls
    can be inspected. Mirrors test_run_reaper.py's snapshot/restore
    convention for touching shared dev-DB rows (naabu's enabled flag, the
    probe_authorisation_mode setting)."""
    db = SessionLocal()
    stub = _CaptureConnector()
    naabu_row = connector_config.get_one(db, "naabu")
    had_naabu_row = naabu_row is not None
    original_enabled = naabu_row.enabled if naabu_row else None
    original_mode = settings_svc.get(db, "probe_authorisation_mode")
    try:
        connector_config.set_enabled(db, "naabu", True)
        _set_probe_mode(db, "log_only")
        scan_executor._run_pipeline(
            db, uuid.uuid4(), chunk_scope, {}, "disabled", tier,
            False, {"naabu": stub}, [], frozenset(),
        )
    finally:
        if had_naabu_row:
            connector_config.set_enabled(db, "naabu", original_enabled)
        _set_probe_mode(db, original_mode)
        db.close()
    return stub


def test_executor_injects_ip_ranges_into_config():
    cidr = "203.0.113.0/28"
    stub = _run_pipeline_with_stub({"domains": [], "ip_ranges": [cidr]})

    assert len(stub.calls) == 1, (
        "port_scan was not called — check naabu enablement / the probe gate"
    )
    assert stub.calls[0].get("_ip_ranges") == [cidr]


def test_executor_omits_ip_ranges_key_as_empty_list_when_none_declared():
    """A domain-only chunk still gets the key (as an empty list), not a
    missing one — connectors that check truthiness see no difference, but
    this pins the always-present shape."""
    stub = _run_pipeline_with_stub({"domains": [], "ip_ranges": []})
    # No assets and no ip_ranges means Phase 1.5 never runs at all — the
    # gate has nothing to authorise and nothing to sweep.
    assert stub.calls == []


# ── 5. the run-level interim guard ──────────────────────────────────────────

def _mk_run(db, ip_ranges: list[str]) -> ScanRun:
    run = ScanRun(
        id=uuid.uuid4(),
        status=ScanStatus.PENDING,
        scope={"domains": [], "ip_ranges": ip_ranges},
        options={"aggressiveness": "standard"},
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def _cleanup_run(db, run_id):
    db.rollback()
    db.query(ScanRun).filter(ScanRun.id == run_id).delete()
    db.commit()


def _guard_messages(run: ScanRun, value: str) -> list[str]:
    return [m for m in (run.partial_failures or []) if value in m and "was not scanned" in m]


def test_guard_does_not_fire_for_a_successfully_swept_cidr():
    """A CIDR that is public, within the size cap, naabu-enabled, and
    completes cleanly must NOT be reported by the interim guard, even
    though (in this stub) it found nothing — a clean empty sweep is a
    real result."""
    cidr = "203.0.113.0/28"
    db = SessionLocal()
    naabu_row = connector_config.get_one(db, "naabu")
    had_naabu_row = naabu_row is not None
    original_enabled = naabu_row.enabled if naabu_row else None
    original_mode = settings_svc.get(db, "probe_authorisation_mode")
    original_is_public_network = scan_executor.is_public_network
    run = None
    try:
        connector_config.set_enabled(db, "naabu", True)
        _set_probe_mode(db, "log_only")
        # The guard re-derives eligibility independently of naabu.py — it
        # reads scan_executor.is_public_network, stubbed here the same way
        # naabu's own predicate is stubbed elsewhere in this file.
        scan_executor.is_public_network = lambda v: v == cidr

        class _SweptConnector:
            observer = "naabu"

            def port_scan(self, assets, config):
                return PhaseResult(complete=True)

        run = _mk_run(db, [cidr])
        scan_executor._run(db, run.id, run.scope, {"naabu": _SweptConnector()})
        db.refresh(run)

        assert _guard_messages(run, cidr) == [], (
            f"guard fired for a cleanly-swept CIDR: {run.partial_failures!r}"
        )
    finally:
        scan_executor.is_public_network = original_is_public_network
        if had_naabu_row:
            connector_config.set_enabled(db, "naabu", original_enabled)
        _set_probe_mode(db, original_mode)
        if run is not None:
            _cleanup_run(db, run.id)
        db.close()


def test_guard_fires_for_a_non_public_cidr():
    """The real is_public_network predicate correctly rejects RFC-5737
    documentation space (no stubbing here) — the guard must report it as
    never attempted."""
    cidr = "192.0.2.0/24"
    db = SessionLocal()
    naabu_row = connector_config.get_one(db, "naabu")
    had_naabu_row = naabu_row is not None
    original_enabled = naabu_row.enabled if naabu_row else None
    original_mode = settings_svc.get(db, "probe_authorisation_mode")
    run = None
    try:
        connector_config.set_enabled(db, "naabu", True)
        _set_probe_mode(db, "log_only")

        class _NoOpConnector:
            observer = "naabu"

            def port_scan(self, assets, config):
                return PhaseResult()

        run = _mk_run(db, [cidr])
        scan_executor._run(db, run.id, run.scope, {"naabu": _NoOpConnector()})
        db.refresh(run)

        messages = _guard_messages(run, cidr)
        assert messages, f"guard did not fire for a non-public CIDR: {run.partial_failures!r}"
        assert "not a public" in messages[0]
    finally:
        if had_naabu_row:
            connector_config.set_enabled(db, "naabu", original_enabled)
        _set_probe_mode(db, original_mode)
        if run is not None:
            _cleanup_run(db, run.id)
        db.close()


def test_guard_fires_for_an_oversized_cidr():
    """A CIDR that IS public but exceeds the size cap is also reported as
    never attempted, with a distinct reason from the non-public case."""
    cidr = "203.0.113.0/24"  # 256 addresses
    db = SessionLocal()
    naabu_row = connector_config.get_one(db, "naabu")
    had_naabu_row = naabu_row is not None
    original_enabled = naabu_row.enabled if naabu_row else None
    original_mode = settings_svc.get(db, "probe_authorisation_mode")
    original_is_public_network = scan_executor.is_public_network
    original_naabu_config = connector_config.get_decrypted_config(db, "naabu")
    run = None
    try:
        connector_config.set_enabled(db, "naabu", True)
        connector_config.upsert_config(db, "naabu", {**original_naabu_config, "max_sweep_addresses": 4})
        _set_probe_mode(db, "log_only")
        scan_executor.is_public_network = lambda v: v == cidr

        class _NoOpConnector:
            observer = "naabu"

            def port_scan(self, assets, config):
                return PhaseResult()

        run = _mk_run(db, [cidr])
        scan_executor._run(db, run.id, run.scope, {"naabu": _NoOpConnector()})
        db.refresh(run)

        messages = _guard_messages(run, cidr)
        assert messages, f"guard did not fire for an oversized CIDR: {run.partial_failures!r}"
        assert "exceeds" in messages[0]
    finally:
        scan_executor.is_public_network = original_is_public_network
        connector_config.upsert_config(db, "naabu", original_naabu_config)
        if had_naabu_row:
            connector_config.set_enabled(db, "naabu", original_enabled)
        _set_probe_mode(db, original_mode)
        if run is not None:
            _cleanup_run(db, run.id)
        db.close()


if __name__ == "__main__":
    _tests = [
        test_public_cidr_reaches_invoke_worker_hosts,
        test_non_public_cidr_never_reaches_the_worker,
        test_oversized_cidr_is_skipped_and_reason_recorded,
        test_responding_cidr_host_becomes_new_asset,
        test_known_ip_in_cidr_range_is_not_duplicated_as_new,
        test_executor_injects_ip_ranges_into_config,
        test_executor_omits_ip_ranges_key_as_empty_list_when_none_declared,
        test_guard_does_not_fire_for_a_successfully_swept_cidr,
        test_guard_fires_for_a_non_public_cidr,
        test_guard_fires_for_an_oversized_cidr,
    ]
    for _t in _tests:
        _t()
        print(f"ok {_t.__name__}")
    print(f"\n{len(_tests)} passed")
