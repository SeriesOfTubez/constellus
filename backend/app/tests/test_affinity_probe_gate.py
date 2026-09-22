"""Tests for the ownership/affinity-probe gate — planning#205.

`app.services.domain_affinity` sends real HTTP/TLS to target hosts through
exactly two network-egress functions, `_probe_worker` (via `check_affinity`)
and `probe_corroboration_candidates`, and before this issue neither ever
consulted `app.services.probe_authorisation`. planning#205 wires both
through the new `authorise_ownership_probe` gate.

⚠ THE TRAP this file exists to avoid: ~20 existing tests across
test_dangling_dns_routing.py / test_dangling_dns_widening.py /
test_ownership_stamping.py / test_phase_d_hosting_integration.py /
test_pregate_evidence.py / test_shared_infra_verifier.py monkeypatch by
REPLACING `domain_affinity.check_affinity` itself
(`da.check_affinity = lambda db, hostname, origin_ip, apexes, ports=None,
**kw: ...`). A gate test written that way would replace the very function
containing the gate call and prove nothing. Every test below instead stubs
`domain_affinity.httpx.post` — the actual network transport — and asserts
it was or was not called. `check_affinity`/`probe_corroboration_candidates`
themselves are never monkeypatched here.

Real `AssetCanonical` / `Target` / `TargetAssetLink` / `AssetState` rows via
`SessionLocal`, mirroring test_probe_authorisation.py's direct-seeding style
— the point is pinning the gate's behaviour, independent of the ingest path
that normally produces these rows. `_ = AssetType` — the real enum, not a
bare string, is used nowhere here because these tests seed `asset_type` as a
plain string directly on `AssetCanonical` (as every other direct-seeding
test in this suite does, `test_probe_authorisation.py` included); the
`str(AssetType.X)` hazard documented elsewhere in this suite is specific to
code that COMPARES against `asset.asset_type`, not to a literal column value.

Addresses: ONE /29 drawn via `_docaddr.alloc_cidr()` for the whole module,
six host addresses derived from it — one per real-DB scenario below, never
by interpolating a documentation prefix.

Run with:  backend/scripts/test.ps1 app/tests/test_affinity_probe_gate.py
"""

import ipaddress
import uuid
from datetime import datetime, timezone

from app.core.apex import apex_domain
from app.core.database import SessionLocal
from app.models.app_settings import AppSetting
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.authorisation_decision import AuthorisationDecision
from app.models.claim import AssetClaim, ClaimHistory
from app.models.observer import Observer
from app.models.target import Target
from app.models.target_asset_link import TargetAssetLink
from app.services import app_settings
from app.services import domain_affinity as da
from app.services import shared_infra_verifier as siv
from app.services.claim_emitter import get_current_claim
from app.tests import _decision_log, _docaddr

_MODE_KEY = "probe_authorisation_mode"

_CIDR, _ = _docaddr.alloc_cidr()
_HOSTS = [str(h) for h in ipaddress.ip_network(_CIDR, strict=False).hosts()]
# One /29 -> six host addresses. Six real-DB scenarios below, one address
# each — never reused, so no scenario's cleanup can race another's insert.
_IP_PRECLOSE, _IP_NO_PROBE, _IP_ORDINARY, _IP_CORROBORATION, _IP_E2E, _IP_UNPROJECTED = _HOSTS[:6]


# ── helpers (mirrors test_probe_authorisation.py's direct-seeding style) ───

def _mk_asset(db, asset_type: str, value: str, **kw) -> AssetCanonical:
    now = datetime.now(timezone.utc)
    row = AssetCanonical(
        id=uuid.uuid4(), asset_type=asset_type, value=value,
        first_seen_at=now, last_seen_at=now, **kw,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _mk_host_and_ip(db, ip: str) -> tuple[AssetCanonical, AssetCanonical]:
    """A dns_record A row owning `ip`, plus the ip_address row itself — the
    same two-canonical shape shared_infra_verifier.classify_ip_ownership
    passes as `asset_canonical_ids=[host.id, ip_asset.id]`."""
    host = _mk_asset(
        db, "dns_record", f"gate-{uuid.uuid4().hex[:10]}.example.com",
        record_type="A", content=ip,
    )
    ip_asset = _mk_asset(db, "ip_address", ip, parent_value=host.value)
    return host, ip_asset


def _mk_target(db, ma_pre_close: bool) -> Target:
    row = Target(
        id=uuid.uuid4(), type="domain",
        value=f"gate-target-{uuid.uuid4().hex[:10]}.example.com",
        ma_pre_close=ma_pre_close,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _link(db, target_id: uuid.UUID, asset_canonical_id: uuid.UUID) -> None:
    db.add(TargetAssetLink(target_id=target_id, asset_canonical_id=asset_canonical_id))
    db.commit()


def _set_state(db, asset_id: uuid.UUID, probe_class: str) -> None:
    now = datetime.now(timezone.utc)
    db.add(AssetState(asset_canonical_id=asset_id, attributes={"probe_class": probe_class}, projected_at=now))
    db.commit()


def _set_mode(db, value: str | None) -> None:
    if value is None:
        db.query(AppSetting).filter(AppSetting.key == _MODE_KEY).delete()
        db.commit()
    else:
        app_settings.set_value(db, _MODE_KEY, value)


def _cleanup(asset_ids: list[uuid.UUID], target_ids: list[uuid.UUID]) -> None:
    """Decision rows and claims BEFORE the asset, never after —
    `authorisation_decisions.asset_canonical_id` and the claim tables are
    both `ON DELETE SET NULL`/keyed off the asset id, and deleting the asset
    first would silently orphan them instead of removing them (the exact
    trap `test_zz_decision_log_hygiene.py` exists to catch)."""
    ids = [i for i in asset_ids if i is not None]
    db = SessionLocal()
    try:
        if ids:
            db.query(AuthorisationDecision).filter(AuthorisationDecision.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
            db.query(ClaimHistory).filter(ClaimHistory.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
            db.query(AssetClaim).filter(AssetClaim.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
            db.query(AssetState).filter(AssetState.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
            db.query(AssetCanonical).filter(AssetCanonical.id.in_(ids)).delete(synchronize_session=False)
        tids = [t for t in target_ids if t is not None]
        if tids:
            # target_asset_links cascade-deletes with either side (ON DELETE
            # CASCADE on both FKs) — no separate link cleanup needed.
            db.query(Target).filter(Target.id.in_(tids)).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


class _Response:
    """Minimal httpx.Response stand-in — same shape as
    test_worker_outage_absence.py's, the established pattern for stubbing
    this module's transport seam."""

    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def _install_post_spy():
    """Stub `domain_affinity.httpx.post` — the actual network transport,
    NOT `check_affinity`/`probe_corroboration_candidates` themselves (see
    module docstring, "THE TRAP"). Returns (calls, restore); `calls` records
    every invocation so a test can assert zero or nonzero. Not one of
    conftest.py's `_GUARDED_MODULES` (that list covers this suite's own
    service modules, not the third-party `httpx` module), so this uses the
    same manual try/finally restore test_worker_outage_absence.py does."""
    calls: list = []
    original = da.httpx.post

    def spy(url, **kwargs):
        calls.append((url, kwargs))
        if url.endswith("/affinity/corroborate"):
            return _Response({"hostnames": {}})
        return _Response({"ports": {}})

    da.httpx.post = spy

    def restore():
        da.httpx.post = original

    return calls, restore


# ── 1. pre-close M&A -> denied under BOTH modes, posture always-enforced ───

def test_pre_close_asset_denied_under_both_modes():
    ip = _IP_PRECLOSE
    db = SessionLocal()
    asset_ids: list = []
    target_ids: list = []
    try:
        host, ip_asset = _mk_host_and_ip(db, ip)
        asset_ids = [host.id, ip_asset.id]
        target = _mk_target(db, ma_pre_close=True)
        target_ids = [target.id]
        _link(db, target.id, ip_asset.id)

        apexes = {apex_domain(host.value)}
        calls, restore = _install_post_spy()
        try:
            for mode in ("log_only", "enforce"):
                _set_mode(db, mode)
                calls.clear()
                result = da.check_affinity(
                    db, host.value, ip_asset.value, apexes,
                    asset_canonical_ids=[host.id, ip_asset.id],
                )
                assert calls == [], f"httpx.post must not be called under {mode} for a pre-close asset"
                assert result.verdict == da.VERDICT_INDETERMINATE
                assert any("denied" in s for s in result.signals), (
                    "a gate denial must be distinguishable from a worker outage in signals"
                )
        finally:
            restore()
            _set_mode(db, None)
    finally:
        _cleanup(asset_ids, target_ids)
        db.close()


# ── 2. no_probe -> mode-gated; both modes write a decision row ─────────────

def test_no_probe_asset_mode_gated_and_always_logged():
    ip = _IP_NO_PROBE
    db = SessionLocal()
    asset_ids: list = []
    try:
        host, ip_asset = _mk_host_and_ip(db, ip)
        asset_ids = [host.id, ip_asset.id]
        _set_state(db, ip_asset.id, "no_probe")
        apexes = {apex_domain(host.value)}

        calls, restore = _install_post_spy()
        try:
            # log_only: computed-and-logged denial, but the probe PROCEEDS.
            _set_mode(db, "log_only")
            mark = _decision_log.watermark()
            calls.clear()
            result = da.check_affinity(
                db, host.value, ip_asset.value, apexes,
                asset_canonical_ids=[host.id, ip_asset.id],
            )
            assert len(calls) == 1, "log_only must still let a no_probe asset's probe proceed"
            log_only_row = (
                db.query(AuthorisationDecision)
                .filter(AuthorisationDecision.asset_canonical_id.in_([host.id, ip_asset.id]))
                .filter(AuthorisationDecision.decided_at >= mark)
                .one()
            )
            assert log_only_row.rule_fired == "probe_class:no_probe"
            assert log_only_row.asset_canonical_id == ip_asset.id, (
                "the decision row must be attached to the id that actually denied — "
                "the IP, which carries the no_probe state, not the host"
            )
            assert log_only_row.allowed is False, (
                "log_only still logs the REAL computed verdict, not a passthrough True"
            )

            # enforce: denied outright, no network call.
            _set_mode(db, "enforce")
            mark = _decision_log.watermark()
            calls.clear()
            result = da.check_affinity(
                db, host.value, ip_asset.value, apexes,
                asset_canonical_ids=[host.id, ip_asset.id],
            )
            assert calls == [], "enforce must deny a no_probe asset outright"
            assert result.verdict == da.VERDICT_INDETERMINATE

            # 7. Decision-row shape, pinned on this enforce-mode denial.
            enforce_row = (
                db.query(AuthorisationDecision)
                .filter(AuthorisationDecision.asset_canonical_id.in_([host.id, ip_asset.id]))
                .filter(AuthorisationDecision.decided_at >= mark)
                .one()
            )
            observer = db.query(Observer).filter(Observer.name == "domain_affinity").one()
            assert enforce_row.rule_fired == "probe_class:no_probe"
            assert enforce_row.evidence_snapshot["decision_scope"] == "ownership_probe"
            assert enforce_row.asset_canonical_id == ip_asset.id
            assert enforce_row.allowed is False
            assert enforce_row.observer_id == observer.id
        finally:
            restore()
            _set_mode(db, None)
    finally:
        _cleanup(asset_ids, [])
        db.close()


# ── 3. ordinary asset -> permitted, no decision row ─────────────────────────

def test_ordinary_asset_permitted_and_not_logged():
    ip = _IP_ORDINARY
    db = SessionLocal()
    asset_ids: list = []
    try:
        host, ip_asset = _mk_host_and_ip(db, ip)
        asset_ids = [host.id, ip_asset.id]
        apexes = {apex_domain(host.value)}

        calls, restore = _install_post_spy()
        try:
            _set_mode(db, "enforce")
            mark = _decision_log.watermark()
            da.check_affinity(
                db, host.value, ip_asset.value, apexes,
                asset_canonical_ids=[host.id, ip_asset.id],
            )
            assert len(calls) == 1, "an ordinary asset under ordinary posture must be probed"
            count = (
                db.query(AuthorisationDecision)
                .filter(AuthorisationDecision.asset_canonical_id.in_([host.id, ip_asset.id]))
                .filter(AuthorisationDecision.decided_at >= mark)
                .count()
            )
            assert count == 0, "a permit must not write a decision row"
        finally:
            restore()
            _set_mode(db, None)
    finally:
        _cleanup(asset_ids, [])
        db.close()


# ── 4. probe_corroboration_candidates with a pre-close IP -> denied ─────────

def test_corroboration_candidates_denied_for_pre_close_ip():
    ip = _IP_CORROBORATION
    db = SessionLocal()
    asset_ids: list = []
    target_ids: list = []
    try:
        ip_asset = _mk_asset(db, "ip_address", ip)
        asset_ids = [ip_asset.id]
        target = _mk_target(db, ma_pre_close=True)
        target_ids = [target.id]
        _link(db, target.id, ip_asset.id)

        calls, restore = _install_post_spy()
        try:
            _set_mode(db, "log_only")  # posture is always-enforced regardless
            result = da.probe_corroboration_candidates(
                db, ["othertenant.example.com"], ip, [443, 80],
                asset_canonical_ids=[ip_asset.id],
            )
            assert calls == [], "a pre-close corroboration candidate probe must never reach the network"
            assert result == {}
        finally:
            restore()
            _set_mode(db, None)
    finally:
        _cleanup(asset_ids, target_ids)
        db.close()


# ── 5/6. end-to-end inertness: BOTH egress functions, zero calls total,
#         and the denial never becomes an ownership verdict ────────────────

def test_classify_ip_ownership_pre_close_makes_zero_network_calls():
    """The inertness test (spec case 5) and the verdict test (spec case 6)
    share one fixture: a pre-close-linked IP with one owned hostname,
    classified end-to-end through the REAL classify_ip_ownership. This must
    fail if only `_probe_worker` is gated — a fresh test DB has no
    cloud_ranges dataset loaded, so `hosting.attempted` is False and Phase D
    never even reaches `corroborate_liveness`/`probe_corroboration_candidates`
    on ITS OWN; that path is exercised separately by
    test_phase_d_hosting_integration.py and test_ownership_stamping.py, and
    is not what this test is pinning. What this test pins is narrower and
    prior to Phase D: `check_affinity`'s own denial must not leak a single
    `httpx.post` call, for every hostname classify_ip_ownership loops over.
    """
    ip = _IP_E2E
    db = SessionLocal()
    asset_ids: list = []
    target_ids: list = []
    try:
        host, ip_asset = _mk_host_and_ip(db, ip)
        asset_ids = [host.id, ip_asset.id]
        target = _mk_target(db, ma_pre_close=True)
        target_ids = [target.id]
        _link(db, target.id, ip_asset.id)

        calls, restore = _install_post_spy()
        try:
            _set_mode(db, "log_only")
            result = siv.classify_ip_ownership(db, ip_asset)
            assert calls == [], (
                "classify_ip_ownership must make ZERO httpx.post calls for a "
                "pre-close M&A IP — this fails if only _probe_worker is gated "
                "and the denial routes into an ungated corroboration call"
            )
            assert result["verdict"] == "unverified"
            assert result["verdict"] not in ("confirmed_ours", "rejected_shared_infra"), (
                "a gate denial must read as 'no evidence', never as an "
                "ownership verdict this system did not actually establish"
            )
            claim = get_current_claim(db, ip_asset.id, "shared_infra_verifier", "affinity_confirmation")
            if claim is not None:
                assert claim.claim_value.get("verdict") != "confirmed_ours"
        finally:
            restore()
            _set_mode(db, None)
    finally:
        _cleanup(asset_ids, target_ids)
        db.close()


# ── 8. unprojected asset (no asset_state at all) -> permitted ──────────────

def test_unprojected_asset_permitted():
    """Deliberate difference from `_probe_class_cap`, documented in
    `authorise_ownership_probe`'s docstring: a missing `asset_state` DENIES
    under `_probe_class_cap` (`probe_class:unprojected`) but PERMITS here —
    denying it would block every first-run affinity probe under `enforce`."""
    ip = _IP_UNPROJECTED
    db = SessionLocal()
    asset_ids: list = []
    try:
        host, ip_asset = _mk_host_and_ip(db, ip)
        asset_ids = [host.id, ip_asset.id]
        apexes = {apex_domain(host.value)}
        assert db.get(AssetState, ip_asset.id) is None, "fixture sanity: no asset_state row"

        calls, restore = _install_post_spy()
        try:
            _set_mode(db, "enforce")
            mark = _decision_log.watermark()
            da.check_affinity(
                db, host.value, ip_asset.value, apexes,
                asset_canonical_ids=[host.id, ip_asset.id],
            )
            assert len(calls) == 1, "an unprojected asset must be permitted, not denied"
            count = (
                db.query(AuthorisationDecision)
                .filter(AuthorisationDecision.asset_canonical_id.in_([host.id, ip_asset.id]))
                .filter(AuthorisationDecision.decided_at >= mark)
                .count()
            )
            assert count == 0
        finally:
            restore()
            _set_mode(db, None)
    finally:
        _cleanup(asset_ids, [])
        db.close()


def _run():
    tests = [
        test_pre_close_asset_denied_under_both_modes,
        test_no_probe_asset_mode_gated_and_always_logged,
        test_ordinary_asset_permitted_and_not_logged,
        test_corroboration_candidates_denied_for_pre_close_ip,
        test_classify_ip_ownership_pre_close_makes_zero_network_calls,
        test_unprojected_asset_permitted,
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
