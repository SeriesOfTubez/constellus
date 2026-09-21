"""Tests for planning#175 — absence licensing for CIDR-swept hosts.

## What the issue said, and what is actually true

planning#175's body states the defect as: *"a port that genuinely closes on a
sweep-discovered host stays in the projection forever, because `scanned_ips`
is built from the asset list only"*. Measured against the code, that is
**wrong in the common case**, and the real defect is both narrower and
sharper.

`NaabuConnector._build_phase_result` writes `naabu_last_scan_at` — the marker
that licenses `projector._prune_stale_ports` to retire a port — in two
places:

  * on the **per-IP patch** built for every host that has at least one
    confirmed port this run, and
  * on the **zero-port fill patch**, built by iterating `scanned_ips`.

Only the second reads `scanned_ips`. So a swept host that still has one open
port gets a fresh marker anyway, and its *other* ports are retired normally.
The conservatism the planning#161 call-site comment claims for swept hosts is
therefore not what the code delivers — it is delivered for exactly one case:

    the host's LAST port.

When every port on a swept host closes, the host produces no patch at all —
it is absent from `merged` (nmap confirmed nothing), so no per-IP patch, and
absent from `scanned_ips` (built from `ip_values`), so no fill patch either.
Nothing advances its cutoff, `_prune_stale_ports` never runs against a fresh
marker, and the final port is frozen in the projection permanently.

`test_a_swept_host_keeping_a_port_already_licenses_absence` and
`test_a_swept_hosts_last_port_is_never_retired` pin both halves of that, so
the distinction cannot quietly collapse again.

## Why it is not self-resolving

planning#175 asks first whether a swept host simply arrives as an ordinary
`ip_address` asset on run N+1, in which case it needs a pin and no fix. It
does not. `_run_pipeline` assembles `all_assets` from **this run's discovery
output** plus the scope seeds; nothing loads persisted assets back in. A host
that only ever enters via a sweep is re-found by the sweep every run and
never reaches `ip_values`. `test_a_persisted_swept_host_is_not_rediscovered_
as_an_ordinary_asset` drives the real pipeline to show that.

## The fix, and why it is bookkeeping rather than probing

The sweep **already scans** every address in the range — that is what
sweeping a CIDR is. The only thing missing is the record that it did. So the
executor hands naabu the addresses inside the declared ranges that are
already persisted assets (`config["_known_ips_in_ranges"]`), and naabu unions
into `scanned_ips` those of them that fall inside a CIDR it **actually
swept** — not merely one that was declared, since an oversized or non-public
range is skipped and licenses nothing (planning#160 D2/D3).

No new packets are sent, no asset is minted, and no additional asset reaches
the probe gate: the range itself was authorised, and an address inside a
swept range is covered by that same authorisation. That is deliberately the
minimum — see the hand-off comment on planning#175 for the enrichment
inconsistency this does *not* address.

Address hygiene: the addresses below are mocked worker/config data rather
than database identities, which is the case `_docaddr` documents as out of
scope (the same footing as test_cidr_sweep.py's sweep configs). The one test
that writes a real row draws from `_docaddr.alloc_cidr()`.

Run with:  backend/scripts/test.ps1 app/tests/test_swept_host_port_retirement.py
"""

import types
import uuid

from app.connectors import naabu as naabu_mod
from app.connectors.base import PhaseResult
from app.connectors.naabu import NaabuConnector, WorkerResult
from app.core.database import SessionLocal
from app.models.asset import AssetType
from app.models.asset_canonical import AssetCanonical
from app.services import app_settings as settings_svc
from app.services import connector_config
from app.services import scan_executor
from app.tests import _decision_log
from app.tests._docaddr import alloc_cidr

# A /28 of documentation space used only as mocked sweep input — never a
# database identity, which is the case `_docaddr` puts out of scope. It sits
# below the 192.0.2 pool block and below the /25 test_cloud_ranges claims by
# containment; `test_docaddr_guard` re-checks that on every run, so the
# ranges are not restated here (writing one down is itself an R3 offence —
# this comment previously tripped the guard by quoting the pool bounds).
CIDR = "192.0.2.16/28"
HOST = "192.0.2.17"
OTHER = "192.0.2.18"


# ── stub plumbing (same conventions as test_cidr_sweep.py) ─────────────────

def _install_filters(networks: set[str]):
    """Stub naabu's public-address predicates. The real ones correctly reject
    every documentation range, which is why they need stubbing here."""
    o_net, o_ip = naabu_mod._is_public_network, naabu_mod._is_public_ip
    naabu_mod._is_public_network = lambda value: value in networks
    naabu_mod._is_public_ip = lambda value: value.startswith("192.0.2.")

    def restore():
        naabu_mod._is_public_network = o_net
        naabu_mod._is_public_ip = o_ip

    return restore


def _ip_asset(value):
    return types.SimpleNamespace(
        asset_type=AssetType.IP_ADDRESS, value=value, asset_metadata={},
    )


def _config(**overrides):
    cfg = {
        "_tier": "test",
        "_aggressiveness": {"naabu": {
            "enabled": True, "top_ports": 100, "rate": 500, "concurrency": 10,
        }},
    }
    cfg.update(overrides)
    return cfg


def _sweep(*, responding_port=None, assets=None, networks=(CIDR,), complete=True,
           **config_overrides):
    """Drive one `port_scan` pass over `CIDR`. `responding_port=None` means
    every port on every host in the range is closed — the sweep runs and
    nothing answers."""
    conn = NaabuConnector()

    def fake_worker(*, hosts, top_ports, ports, exclude_ports, rate,
                    concurrency, verify=False):
        if verify or responding_port is None:
            return WorkerResult(rows=[], completed=complete)
        return WorkerResult(
            rows=[{"host": HOST, "ip": HOST, "port": responding_port}],
            completed=complete,
        )

    conn._invoke_worker = fake_worker
    conn._invoke_nmap_verify = lambda merged, gentle_ips=None: (
        {} if responding_port is None else
        {HOST: {responding_port: {
            "service": "http", "product": "nginx", "version": None,
            "extra_info": None,
        }}}
    )
    restore = _install_filters(set(networks))
    try:
        return conn.port_scan(
            assets or [], _config(_ip_ranges=[CIDR], **config_overrides),
        )
    finally:
        restore()


def _patch_for(result: PhaseResult, value: str) -> list:
    return [a for a in result.assets if a.value == value]


def _licenses_absence(result: PhaseResult, value: str) -> bool:
    """True when some patch for `value` carries the marker that lets
    `projector._prune_stale_ports` retire a port not re-seen this run."""
    return any(
        (a.asset_metadata or {}).get("naabu_last_scan_at")
        for a in _patch_for(result, value)
    )


# ── 1. what the code actually does today, both halves ──────────────────────

def test_a_swept_host_keeping_a_port_already_licenses_absence():
    """The conservatism planning#161's call-site comment claims is NOT what
    the code delivers. A swept host with one confirmed port gets a per-IP
    patch, and that patch carries `naabu_last_scan_at` regardless of
    `scanned_ips` — so every OTHER port on it is retired normally.

    This is the half of planning#175's premise that is false, and it is
    pinned here so that a future reading of the comment cannot re-derive the
    wrong model from it."""
    result = _sweep(responding_port=80)

    assert _patch_for(result, HOST), "the swept host produced no patch at all"
    assert _licenses_absence(result, HOST), (
        "a swept host with a confirmed port must carry naabu_last_scan_at — "
        "absence for its other ports is already licensed"
    )


def test_a_swept_hosts_last_port_is_never_retired():
    """The real defect. When every port on a swept host closes, the host is
    in neither `merged` (nmap confirmed nothing) nor `scanned_ips` (built
    from `ip_values`), so no patch is emitted at all and its final port is
    frozen in the projection forever."""
    result = _sweep(responding_port=None, _known_ips_in_ranges=[HOST])

    assert _licenses_absence(result, HOST), (
        "a host inside a swept range whose last port closed must still get a "
        "zero-port fill patch — otherwise _prune_stale_ports never sees a "
        "fresh cutoff and the dead port survives indefinitely"
    )
    fills = _patch_for(result, HOST)
    assert len(fills) == 1, f"expected exactly one fill patch, got {fills!r}"
    assert fills[0].asset_metadata.get("open_ports") == [], (
        "the fill patch asserts no ports; the merge leaves real rows alone "
        "and the prune retires the stale ones"
    )


def test_an_ordinary_asset_in_the_same_position_is_retired():
    """The control that isolates the variable: the identical host, identical
    closed-port situation, differing only in arriving as an ordinary asset.
    `scanned_ips` is built from that list, so the fill patch is emitted."""
    result = _sweep(responding_port=None, assets=[_ip_asset(HOST)])

    assert _licenses_absence(result, HOST), (
        "an ordinary in-batch asset must be absence-licensed — if this fails "
        "the defect is somewhere other than where planning#175 places it"
    )


# ── 2. the licensing must not outrun the coverage ──────────────────────────

def test_absence_is_not_licensed_for_a_range_the_sweep_skipped():
    """A declared range that naabu refuses to sweep (here: not public) is
    never scanned, so nothing inside it may claim an absence — planning#160
    D2. The executor passes known addresses for every DECLARED range; naabu
    filters them against the ranges it ACTUALLY swept."""
    result = _sweep(
        responding_port=None, networks=set(), _known_ips_in_ranges=[HOST],
    )

    assert not _licenses_absence(result, HOST), (
        "an unswept range licenses no absence claim for the addresses in it"
    )


def test_absence_is_not_licensed_for_an_address_outside_every_swept_range():
    """Containment, not a bare pass-through. An address the executor offers
    that does not fall inside any swept CIDR gets nothing."""
    outside = "192.0.2.200"
    result = _sweep(responding_port=None, _known_ips_in_ranges=[outside])

    assert not _patch_for(result, outside), (
        "an address outside every swept range must not be absence-licensed "
        "just because it was offered"
    )


def test_an_incomplete_baseline_licenses_no_absence_for_swept_hosts():
    """planning#160 D3 still governs. A pass that did not complete may not
    make an absence claim for a swept host either."""
    result = _sweep(
        responding_port=None, complete=False, _known_ips_in_ranges=[HOST],
    )

    assert not _licenses_absence(result, HOST), (
        "an incomplete baseline licenses no absence claim at all"
    )


def test_the_fill_patch_never_mints_an_address_the_executor_did_not_name():
    """The fill loop builds `DiscoveredAsset`s, which `write_assets` upserts
    — so licensing absence for a whole swept range would mint a row for every
    address in it. Only addresses the executor names (which are, by
    construction, already persisted assets) may be filled."""
    result = _sweep(responding_port=None, _known_ips_in_ranges=[HOST])

    values = {a.value for a in result.assets}
    assert OTHER not in values, (
        "a silent address inside the swept range must not become an asset"
    )
    assert values <= {HOST}, f"unexpected assets minted by the sweep: {values!r}"


# ── 3. the executor seam (touches the database) ────────────────────────────

class _CaptureConnector:
    """Minimal Phase 1.5 stand-in. `observer = "naabu"` reuses the real
    seeded observer row so probe_authorisation's connector-declaration check
    resolves it — same trick as test_cidr_sweep.py's stub."""
    observer = "naabu"

    def __init__(self):
        self.calls: list[tuple[list, dict]] = []

    def port_scan(self, assets, config):
        self.calls.append((list(assets), config))
        return PhaseResult()


def _set_probe_mode(db, value):
    from app.models.app_settings import AppSetting
    if value is None:
        db.query(AppSetting).filter(AppSetting.key == "probe_authorisation_mode").delete()
        db.commit()
    else:
        settings_svc.set_value(db, "probe_authorisation_mode", value)


def _run_pipeline_with_stub(chunk_scope: dict):
    """Drive `_run_pipeline` against a throwaway chunk with a one-connector
    registry, so no real network call happens. The scan run id is bound to a
    name rather than generated inline: the probe gate stamps it on every
    decision row, and an id nobody kept is a row nobody can delete
    (planning#189)."""
    db = SessionLocal()
    stub = _CaptureConnector()
    naabu_row = connector_config.get_one(db, "naabu")
    had_naabu_row = naabu_row is not None
    original_enabled = naabu_row.enabled if naabu_row else None
    original_mode = settings_svc.get(db, "probe_authorisation_mode")
    scan_run_id = uuid.uuid4()
    try:
        connector_config.set_enabled(db, "naabu", True)
        _set_probe_mode(db, "log_only")
        scan_executor._run_pipeline(
            db, scan_run_id, chunk_scope, {}, "disabled", "standard",
            False, {"naabu": stub}, [], frozenset(),
        )
    finally:
        if had_naabu_row:
            connector_config.set_enabled(db, "naabu", original_enabled)
        _set_probe_mode(db, original_mode)
        db.close()
        _decision_log.cleanup_for_run(scan_run_id)
    return stub


def _with_persisted_host(fn):
    """Run `fn(cidr, host)` with one persisted `ip_address` asset inside a
    freshly drawn /29, then delete it. The address comes from
    `_docaddr.alloc_cidr()` so no other module can be handed the same range
    (planning#199), and the row is deleted by its own id rather than by value
    — `authorisation_decisions.asset_canonical_id` is ON DELETE SET NULL
    since planning#195, so a delete that reaches another test's row orphans
    it silently instead of raising."""
    cidr, host = alloc_cidr()
    db = SessionLocal()
    row = AssetCanonical(asset_type="ip_address", value=host)
    db.add(row)
    db.commit()
    asset_id = row.id
    db.close()
    try:
        return fn(cidr, host)
    finally:
        db = SessionLocal()
        db.query(AssetCanonical).filter(AssetCanonical.id == asset_id).delete()
        db.commit()
        db.close()


def test_a_persisted_swept_host_is_not_rediscovered_as_an_ordinary_asset():
    """planning#175's first question, answered by running the real pipeline:
    a host that only ever entered via a sweep does NOT come back as an
    ordinary `ip_address` asset on the next run. `_run_pipeline` builds
    `all_assets` from this run's discovery output plus the scope seeds and
    never loads persisted assets, so the issue is not self-resolving.

    This test is the reason the fix exists; if it ever starts failing,
    something now hydrates persisted assets into Phase 1.5 and the
    `_known_ips_in_ranges` seam should be reconsidered rather than kept."""
    def check(cidr, host):
        stub = _run_pipeline_with_stub({"domains": [], "ip_ranges": [cidr]})
        assert stub.calls, "Phase 1.5 never ran — check naabu enablement"
        assets, _ = stub.calls[0]
        assert host not in {a.value for a in assets}, (
            "a persisted host inside the declared range reached Phase 1.5 as "
            "an ordinary asset — planning#175 may now be self-resolving"
        )

    _with_persisted_host(check)


def test_the_executor_names_persisted_addresses_inside_declared_ranges():
    """The seam itself: every persisted `ip_address` asset contained by a
    declared range is offered to the Phase 1.5 connectors, so naabu can
    license absence for the ones whose range it actually swept."""
    def check(cidr, host):
        stub = _run_pipeline_with_stub({"domains": [], "ip_ranges": [cidr]})
        assert stub.calls, "Phase 1.5 never ran — check naabu enablement"
        _, config = stub.calls[0]
        assert host in (config.get("_known_ips_in_ranges") or []), (
            f"{host} is a persisted asset inside the declared {cidr} and must "
            f"be named: got {config.get('_known_ips_in_ranges')!r}"
        )

    _with_persisted_host(check)


def test_a_domain_only_chunk_names_no_addresses():
    """No declared ranges means no containment query and an empty list — the
    key is always present, like `_ip_ranges`, so connectors see one shape."""
    stub = _run_pipeline_with_stub({
        "domains": [], "ip_ranges": [alloc_cidr()[0]],
    })
    assert stub.calls, "Phase 1.5 never ran — check naabu enablement"
    _, config = stub.calls[0]
    assert config.get("_known_ips_in_ranges") == [], (
        "a range with no persisted assets inside it names nothing"
    )
