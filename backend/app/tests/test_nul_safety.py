"""NUL-byte safety: hostile scan data must neither blind a run nor reach JSONB.

Found live on dev: a banner_grab result carried NUL characters into a
`port_observation` claim's JSONB value. Postgres rejects U+0000 in JSONB, the
resulting exception was caught by the port-scan connector loop in
`scan_executor._run_pipeline` WITHOUT a rollback, and the session stayed in the
failed-transaction state — so every later step of the run failed while the run
was still marked completed.

Two independent fixes, each pinned separately:

  * Fix 2 (`app.core.database._json_serializer`) strips NUL from every JSONB
    write, so the DB error cannot happen through this route at all.
  * Fix 1 (`db.rollback()` in the per-connector excepts) contains ANY OTHER
    failure that poisons the session. With Fix 2 in place a NUL no longer
    triggers one, so the isolation test fails the session a different way
    (a division by zero in the database).

Run with:  backend/scripts/test.ps1 app/tests/test_nul_safety.py
"""

import uuid

from sqlalchemy import text

from app.connectors.base import DiscoveredAsset, PhaseResult
from app.core.database import SessionLocal, _json_serializer, _strip_nul
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.claim import AssetClaim
from app.models.scan_template import ScanTemplate
from app.services import app_settings as settings_svc
from app.tests import connector_helpers as ch
from app.services import scan_executor
from app.tests import _decision_log
from app.tests._docaddr import alloc

NUL = "\x00"


# ── 1. the serializer ──────────────────────────────────────────────────────

def test_strip_nul_is_recursive_and_leaves_other_values_alone():
    value = {
        "a" + NUL + "b": ["x" + NUL, ("y" + NUL, 3), {"k" + NUL: "v" + NUL}],
        "n": None, "t": True, "f": False, "i": 7, "x": 1.5,
    }
    assert _strip_nul(value) == {
        "ab": ["x", ["y", 3], {"k": "v"}],
        "n": None, "t": True, "f": False, "i": 7, "x": 1.5,
    }
    assert _strip_nul(NUL) == ""
    assert _strip_nul(0) == 0 and _strip_nul(None) is None


def test_json_serializer_output_has_no_nul_escape():
    out = _json_serializer({"k" + NUL: "a" + NUL + "b"})
    assert out == '{"k": "ab"}'
    assert "\\u0000" not in out


def test_a_jsonb_write_containing_nul_is_stored_without_it():
    db = SessionLocal()
    row = ScanTemplate(
        name="nul-safety-" + uuid.uuid4().hex[:8],
        scope={"domains": ["a" + NUL + "b.fabrikam.example"], "k" + NUL + "ey": ["x" + NUL]},
    )
    db.add(row)
    db.commit()
    row_id = row.id
    db.close()
    try:
        db = SessionLocal()
        try:
            stored = db.get(ScanTemplate, row_id)
            assert stored.scope == {"domains": ["ab.fabrikam.example"], "key": ["x"]}
        finally:
            db.close()
    finally:
        db = SessionLocal()
        db.query(ScanTemplate).filter(ScanTemplate.id == row_id).delete()
        db.commit()
        db.close()


# ── 2/3. the executor seam (touches the database) ──────────────────────────

class _PortScanner:
    """Phase 1.5 stand-in. `observer` reuses a real seeded observer row so
    probe_authorisation's connector-declaration check resolves it."""

    def __init__(self, observer, order, assets=None, fail_with=None):
        self.observer = observer
        self.port_scan_order = order
        self._assets = assets or []
        self._fail_with = fail_with
        self.calls = 0

    def port_scan(self, assets, config):
        self.calls += 1
        if self._fail_with is not None:
            self._fail_with()
        return PhaseResult(assets=list(self._assets))


def _port_asset(ip, banner, source):
    return DiscoveredAsset(
        asset_type="ip_address", value=ip, observer=source,
        asset_metadata={"open_ports": [{
            "port": 8080, "protocol": "tcp", "state": "open",
            "service": "http", "banner_snippet": banner, "sources": [source],
        }]},
    )


def _run(registry_factory):
    """Drive `_run_pipeline` with the connectors `registry_factory(db)` builds,
    enabling each by id and restoring afterwards. Returns (registry, ip). The
    scan run id is bound so its decision rows can be deleted (planning#189);
    the written asset is deleted by id, which cascades to its claims/state."""
    ip = alloc()
    # A /32 of the allocated address: the CIDR pool is small and shared, and
    # this test needs only a declared range to seed Phase 1.5, not containment.
    cidr = ip + "/32"
    db = SessionLocal()
    scan_run_id = uuid.uuid4()
    registry = registry_factory(db, ip)
    prior = {cid: ch.snapshot(db, cid) for cid in registry}
    original_mode = settings_svc.get(db, "probe_authorisation_mode")
    try:
        for cid in registry:
            ch.force_enabled(db, cid)
        settings_svc.set_value(db, "probe_authorisation_mode", "log_only")
        scan_executor._run_pipeline(
            db, scan_run_id, {"domains": [], "ip_ranges": [cidr]}, {},
            "disabled", "standard", False, registry, [], frozenset(),
        )
        db.rollback()
        return registry, ip, _read_ip(ip)
    finally:
        db.rollback()
        for cid, snap in prior.items():
            ch.restore(db, cid, snap)
        _restore_mode(db, original_mode)
        db.close()
        _decision_log.cleanup_for_run(scan_run_id)
        _delete_ip(ip)


def _restore_mode(db, value):
    from app.models.app_settings import AppSetting
    if value is None:
        db.query(AppSetting).filter(AppSetting.key == "probe_authorisation_mode").delete()
        db.commit()
    else:
        settings_svc.set_value(db, "probe_authorisation_mode", value)


def _read_ip(ip):
    """Snapshot (open_ports, claim_values) for `ip` before cleanup."""
    db = SessionLocal()
    try:
        row = db.query(AssetCanonical).filter(
            AssetCanonical.asset_type == "ip_address", AssetCanonical.value == ip,
        ).first()
        if row is None:
            return None
        state = db.get(AssetState, row.id)
        claims = db.query(AssetClaim).filter(AssetClaim.asset_canonical_id == row.id).all()
        return (
            list(state.open_ports) if state else None,
            [c.claim_value for c in claims],
        )
    finally:
        db.close()


def _delete_ip(ip):
    db = SessionLocal()
    db.query(AssetCanonical).filter(
        AssetCanonical.asset_type == "ip_address", AssetCanonical.value == ip,
    ).delete()
    db.commit()
    db.close()


def test_one_connectors_session_poisoning_failure_does_not_fail_the_next():
    """The first port-scan connector poisons the session (a statement that
    errors in the database); the second returns a normal open-port asset.
    Without the rollback in the port-scan except, the second connector's write
    runs on a failed transaction and nothing is stored.

    The failure is injected from inside `port_scan` against the executor's own
    session rather than from a write the executor makes, because the harness
    gives no way to make a DiscoveredAsset's write fail now that NUL is
    stripped. What it pins is the same: the session is unusable when the
    except runs."""
    holder = {}

    def poison():
        holder["db"].execute(text("SELECT 1/0"))

    def factory(db, ip):
        holder["db"] = db
        return {
            "naabu": _PortScanner("naabu", 100, fail_with=poison),
            "banner_grab": _PortScanner(
                "banner_grab", 200, assets=[_port_asset(ip, "SSH-2.0-test", "banner_grab")],
            ),
        }

    registry, ip, snapshot = _run(factory)

    assert registry["naabu"].calls == 1, "the failing connector never ran"
    assert registry["banner_grab"].calls == 1, "the second connector never ran"
    assert snapshot is not None, "the second connector's asset was not written"
    open_ports, _ = snapshot
    assert [p.get("port") for p in open_ports] == [8080], (
        "the second connector's port was not projected — the run was left blind"
    )


def test_nul_in_a_banner_is_written_without_it():
    def factory(db, ip):
        return {
            "banner_grab": _PortScanner(
                "banner_grab", 200,
                assets=[_port_asset(ip, "SSH" + NUL + "-2.0" + NUL, "banner_grab")],
            ),
        }

    registry, ip, snapshot = _run(factory)

    assert registry["banner_grab"].calls == 1
    assert snapshot is not None, "the NUL-bearing asset was not written at all"
    open_ports, claim_values = snapshot
    assert open_ports and open_ports[0]["banner_snippet"] == "SSH-2.0"
    assert NUL not in repr(open_ports) and NUL not in repr(claim_values)
    assert any("SSH-2.0" in repr(v) for v in claim_values), (
        "no claim carried the banner — the claim path was not reached"
    )
