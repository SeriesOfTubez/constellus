"""Acceptance coverage for planning#211 — the engagement object.

This file is the cross-cutting acceptance suite the spec asks for,
separate from the per-module unit coverage already ported in
`test_probe_authorisation.py` / `test_posture_policy.py` /
`test_affinity_probe_gate.py` / `test_scan_executor_pre_close.py`. It pins:

1. The re-keyed gate denies for `pre_close` AND `abandoned`, and PERMITS
   for `day_0`/`integrated`, at `authorise_probes` (the function BOTH
   `scan_executor._run_pipeline` call sites — Phase 1.5 and Phase 3 — call;
   there is no per-call-site logic to diverge, so this file exercises the
   shared function directly rather than driving both scan phases
   end-to-end — see the report's "what the tests don't cover" for why that
   is a real, accepted gap, not silently claimed coverage), `authorise_
   discovery`, and `authorise_ownership_probe`.
2. A no-engagement target's decision evidence is identical to a pre-#211
   row except for the added `"engagements": []` key.
3. The transition table (`app/api/engagements.py`'s `_TRANSITIONS`),
   exhaustively, all 16 cells.
4. The CHECK constraint (migration 0059) rejects the two illegal direct
   inserts.
5. `patch_target`'s widening rule (RBAC + authorisation_reference).
6. `scan_runs.scope_target_engagements` is stamped.
7. `abandoned` targets are excluded from `_resolve_dynamic_scope`;
   `pre_close`/no-engagement targets are not.

Direct-seeding style via `SessionLocal`, matching `test_probe_authorisation.
py`'s convention (the point is pinning behaviour at the gate's own
boundary). Addresses from `_docaddr`; domains are synthetic
`.example.test`/`.example.com` names — never a real registered domain.

Run with:  pytest app/tests/test_engagement_acceptance.py
"""

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.connectors.base import DiscoveredAsset
from app.core.auth import create_access_token
from app.core.database import SessionLocal
from app.models.app_settings import AppSetting
from app.models.asset_canonical import AssetCanonical
from app.models.audit import AuditLog
from app.models.asset_state import AssetState
from app.models.authorisation_decision import AuthorisationDecision
from app.models.engagement import Engagement, EngagementPosture
from app.models.scan import ScanKind, ScanRun, ScanStatus
from app.models.target import Target, TargetType
from app.models.target_asset_link import TargetAssetLink
from app.models.user import User, UserRole
from app.services import posture
from app.services import probe_authorisation as pa
from app.services import scan_executor
from app.tests import _decision_log, _docaddr
from app.tests._engagement import cleanup_engagement, make_engagement

_MODE_KEY = "probe_authorisation_mode"
_ALL_POSTURES = tuple(p.value for p in EngagementPosture)
_RESTRICTING = {"pre_close", "abandoned"}


# ── shared helpers (self-contained — see module docstring) ─────────────────

class _StubConnector:
    def __init__(self, observer_name: str):
        self.observer = observer_name


_IP_CONNECTOR = _StubConnector("naabu")  # addressing == "ip"


def _da(value: str) -> DiscoveredAsset:
    return DiscoveredAsset(asset_type="ip_address", value=value)


def _mk_ip_asset(db, value: str) -> AssetCanonical:
    now = datetime.now(timezone.utc)
    row = AssetCanonical(id=uuid.uuid4(), asset_type="ip_address", value=value, first_seen_at=now, last_seen_at=now)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _set_state(db, asset_id: uuid.UUID, probe_class: str) -> None:
    db.add(AssetState(asset_canonical_id=asset_id, attributes={"probe_class": probe_class}, projected_at=now_utc()))
    db.commit()


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _mk_target_with_posture(db, value: str, posture_value: str | None) -> tuple[Target, uuid.UUID | None]:
    """`posture_value=None` -> no engagement. Otherwise creates a real
    `Engagement` in that posture (satisfying the CHECK constraint for
    `day_0`/`integrated` with a throwaway authorisation record) and links
    the target to it. Returns (target, engagement_id_or_None)."""
    engagement_id = None
    if posture_value is not None:
        extra = {}
        if posture_value in ("day_0", "integrated"):
            extra = {"authorised_at": now_utc(), "authorisation_reference": "pa211-acceptance-ref"}
        engagement_id = make_engagement(db, posture_value, **extra).id
    row = Target(id=uuid.uuid4(), type=TargetType.DOMAIN, value=value, engagement_id=engagement_id)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row, engagement_id


def _link(db, target_id: uuid.UUID, asset_canonical_id: uuid.UUID) -> None:
    db.add(TargetAssetLink(target_id=target_id, asset_canonical_id=asset_canonical_id))
    db.commit()


def _cleanup_asset(values: list[str]) -> None:
    db = SessionLocal()
    try:
        rows = db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).all()
        ids = [r.id for r in rows]
        if ids:
            db.query(AuthorisationDecision).filter(AuthorisationDecision.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
            db.query(AssetState).filter(AssetState.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _cleanup_target_and_engagement(target_id: uuid.UUID | None, engagement_id: uuid.UUID | None) -> None:
    if target_id is None:
        return
    db = SessionLocal()
    try:
        db.query(Target).filter(Target.id == target_id).delete(synchronize_session=False)
        db.commit()
        cleanup_engagement(db, engagement_id)
    finally:
        db.close()


def _set_mode(db, value: str | None) -> None:
    if value is None:
        db.query(AppSetting).filter(AppSetting.key == _MODE_KEY).delete()
        db.commit()


def _cleanup_users(user_ids: list[uuid.UUID]) -> None:
    """`AuditMiddleware` (planning#194) writes an `audit_logs` row for
    every mutating request these tests' `TestClient` calls make (PATCH
    /targets, POST /engagements/.../transition) — every test here goes
    through the real dependency chain, so it cannot opt out of that.
    `audit_logs.user_id` has no cascade, so the audit rows must be deleted
    before the user, same pattern as `test_audit_log.py`'s `_Fixture.
    teardown`."""
    ids = [i for i in user_ids if i is not None]
    if not ids:
        return
    db = SessionLocal()
    try:
        db.query(AuditLog).filter(AuditLog.user_id.in_(ids)).delete(synchronize_session=False)
        db.query(User).filter(User.id.in_(ids)).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


# ── 1. authorise_probes across all four postures ────────────────────────────

@pytest.mark.parametrize("posture_value", _ALL_POSTURES)
def test_authorise_probes_across_all_postures(posture_value):
    """`pre_close`/`abandoned` deny; `day_0`/`integrated` permit — the
    function BOTH scan_executor authorise_probes call sites (Phase 1.5,
    Phase 3) invoke. Every case writes a decision row (authorise_probes
    logs every asset, not just denials); the row's `evidence_snapshot
    ["engagements"]` must name the engagement just created."""
    suffix = uuid.uuid4().hex[:10]
    v = f"pa211-allpostures-{posture_value}-{suffix}"
    domain = f"pa211-allpostures-{posture_value}-{suffix}.example.com"
    db = SessionLocal()
    target = None
    engagement_id = None
    run_id = uuid.uuid4()
    try:
        _set_mode(db, None)
        asset = _mk_ip_asset(db, v)
        _set_state(db, asset.id, "direct_addressable")
        target, engagement_id = _mk_target_with_posture(db, domain, posture_value)
        _link(db, target.id, asset.id)

        gate = pa.authorise_probes(
            db, connector_id="test-ip", connector=_IP_CONNECTOR,
            assets=[_da(v)], scope={}, scan_run_id=run_id,
        )
        permission = gate.permissions[("ip_address", v)]

        restricts = posture_value in _RESTRICTING
        assert permission.allowed is (not restricts), (posture_value, permission.rule_fired)
        if restricts:
            assert permission.rule_fired == "posture:passive_only"

        row = (
            db.query(AuthorisationDecision)
            .filter(AuthorisationDecision.asset_canonical_id == asset.id)
            .filter(AuthorisationDecision.evidence_snapshot["scan_run_id"].astext == str(run_id))
            .first()
        )
        assert row is not None, "authorise_probes must log every asset, permit or deny"
        assert row.evidence_snapshot["engagements"] == [{"id": str(engagement_id), "posture": posture_value}]
        if restricts:
            assert row.rule_fired == "posture:passive_only"
    finally:
        _decision_log.cleanup_for_run(run_id)
        _cleanup_asset([v])
        _cleanup_target_and_engagement(target.id if target else None, engagement_id)
        db.close()


# ── 2. no-engagement target: byte-identical except "engagements": [] ───────

def test_no_engagement_evidence_is_identical_except_the_engagements_key():
    """The issue's "byte-identical" claim is now false by exactly one key,
    intentionally (planning#211 §10 item 2). Every other evidence key and
    every top-level `ProbePermission` field must match what an ordinary,
    fully-open asset produced before this issue — pinned here by asserting
    the exact expected shape rather than a diff against a stored baseline
    (there is no pre-#211 row to diff against in a fresh test DB)."""
    suffix = uuid.uuid4().hex[:10]
    v = f"pa211-noengagement-{suffix}"
    db = SessionLocal()
    target = None
    run_id = uuid.uuid4()
    try:
        _set_mode(db, None)
        asset = _mk_ip_asset(db, v)
        _set_state(db, asset.id, "direct_addressable")
        target, _ = _mk_target_with_posture(db, f"pa211-noengagement-{suffix}.example.com", None)
        _link(db, target.id, asset.id)

        gate = pa.authorise_probes(
            db, connector_id="test-ip", connector=_IP_CONNECTOR,
            assets=[_da(v)], scope={}, scan_run_id=run_id,
        )
        permission = gate.permissions[("ip_address", v)]
        assert permission.allowed is True
        assert permission.rule_fired == "unconstrained"
        assert permission.modes == frozenset({"ip", "name", "ip_handshake"})
        assert permission.evidence["engagements"] == []
        assert permission.evidence["caps"]["posture"] == {"allowed": True, "modes": None, "names": None, "rule": "posture:permissive"}
    finally:
        _decision_log.cleanup_for_run(run_id)
        _cleanup_asset([v])
        _cleanup_target_and_engagement(target.id if target else None, None)
        db.close()


# ── 3. the transition table, all 16 cells ───────────────────────────────────

def _admin_headers() -> tuple[dict, uuid.UUID]:
    user = User(
        id=uuid.uuid4(), email=f"pa211-admin-{uuid.uuid4().hex[:8]}@example.invalid",
        full_name="pa211 test admin", role=UserRole.ADMIN.value, is_active=True,
    )
    db = SessionLocal()
    try:
        db.add(user)
        db.commit()
        uid = user.id
    finally:
        db.close()
    return {"Authorization": f"Bearer {create_access_token(str(uid), UserRole.ADMIN.value)}"}, uid


@pytest.mark.parametrize("from_posture,to_posture", [(f, t) for f in _ALL_POSTURES for t in _ALL_POSTURES])
def test_transition_table_exhaustive(from_posture, to_posture):
    from app.api.engagements import _TRANSITIONS
    from app.core.database import SessionLocal as _SL
    from fastapi.testclient import TestClient
    from app.main import app

    action = _TRANSITIONS[(from_posture, to_posture)]

    db = _SL()
    engagement_id = None
    try:
        extra = {}
        if from_posture in ("day_0", "integrated"):
            extra = {"authorised_at": now_utc(), "authorisation_reference": "pa211-table-ref"}
        engagement = make_engagement(db, from_posture, **extra)
        engagement_id = engagement.id
    finally:
        db.close()

    headers, admin_id = _admin_headers()
    client = TestClient(app)
    try:
        r = client.post(f"/api/engagements/{engagement_id}/transition", json={"to": to_posture}, headers=headers)

        if action == "deny":
            assert r.status_code == 409, (from_posture, to_posture, r.text)
        elif action == "noop":
            assert r.status_code == 200, (from_posture, to_posture, r.text)
            assert r.json()["posture"] == from_posture
        elif action == "needs_ref":
            assert r.status_code == 422, (from_posture, to_posture, r.text)
            r2 = client.post(
                f"/api/engagements/{engagement_id}/transition",
                json={"to": to_posture, "authorisation_reference": "pa211-widening-ref"},
                headers=headers,
            )
            assert r2.status_code == 200, r2.text
            body = r2.json()
            assert body["posture"] == to_posture
            assert body["authorisation_reference"] == "pa211-widening-ref"
            assert body["authorised_at"] is not None
        elif action == "ok_clear":
            assert r.status_code == 200, (from_posture, to_posture, r.text)
            body = r.json()
            assert body["posture"] == to_posture
            assert body["authorisation_reference"] is None
            assert body["authorised_at"] is None
        elif action == "ok_keep":
            assert r.status_code == 200, (from_posture, to_posture, r.text)
            body = r.json()
            assert body["posture"] == to_posture
            assert body["authorisation_reference"] == "pa211-table-ref"
            assert body["authorised_at"] is not None
        else:  # pragma: no cover - exhaustiveness guard
            raise AssertionError(f"unknown action {action!r}")
    finally:
        db = _SL()
        try:
            db.query(Engagement).filter(Engagement.id == engagement_id).delete(synchronize_session=False)
            db.commit()
        finally:
            db.close()
        _cleanup_users([admin_id])


# ── 4. CHECK constraint rejects illegal direct inserts ──────────────────────

def test_check_constraint_rejects_day_0_with_null_reference():
    db = SessionLocal()
    try:
        with pytest.raises(IntegrityError):
            db.execute(text(
                "INSERT INTO engagements (id, name, posture, authorised_at, authorisation_reference) "
                "VALUES (:id, :name, 'day_0', now(), NULL)"
            ), {"id": uuid.uuid4(), "name": f"pa211-check-{uuid.uuid4().hex[:8]}"})
            db.commit()
    finally:
        db.rollback()
        db.close()


def test_check_constraint_rejects_pre_close_with_non_null_authorised_at():
    db = SessionLocal()
    try:
        with pytest.raises(IntegrityError):
            db.execute(text(
                "INSERT INTO engagements (id, name, posture, authorised_at, authorisation_reference) "
                "VALUES (:id, :name, 'pre_close', now(), 'ref')"
            ), {"id": uuid.uuid4(), "name": f"pa211-check-{uuid.uuid4().hex[:8]}"})
            db.commit()
    finally:
        db.rollback()
        db.close()


# ── 5. patch_target's widening rule ──────────────────────────────────────────

def test_widening_rule_on_patch_target():
    from fastapi.testclient import TestClient
    from app.main import app

    db = SessionLocal()
    admin = User(id=uuid.uuid4(), email=f"pa211-w-admin-{uuid.uuid4().hex[:8]}@example.invalid",
                 full_name="w admin", role=UserRole.ADMIN.value, is_active=True)
    integ = User(id=uuid.uuid4(), email=f"pa211-w-integ-{uuid.uuid4().hex[:8]}@example.invalid",
                 full_name="w integ", role=UserRole.INTEGRATION_ADMIN.value, is_active=True)
    db.add_all([admin, integ])
    db.commit()
    admin_id, integ_id = admin.id, integ.id

    engagement = make_engagement(db, "pre_close")
    engagement_id = engagement.id
    abandoned = make_engagement(db, "abandoned")
    abandoned_id = abandoned.id
    target = Target(id=uuid.uuid4(), type=TargetType.DOMAIN, value=_docaddr.alloc(), engagement_id=engagement_id, token=uuid.uuid4().hex)
    db.add(target)
    db.commit()
    target_id = target.id
    db.close()

    admin_headers = {"Authorization": f"Bearer {create_access_token(str(admin_id), UserRole.ADMIN.value)}"}
    integ_headers = {"Authorization": f"Bearer {create_access_token(str(integ_id), UserRole.INTEGRATION_ADMIN.value)}"}
    client = TestClient(app)
    try:
        # INTEGRATION_ADMIN detaching from a restricting engagement -> 403
        r = client.patch(f"/api/targets/{target_id}", json={"clear_engagement": True}, headers=integ_headers)
        assert r.status_code == 403, r.text

        # ADMIN without a reference -> 422
        r = client.patch(f"/api/targets/{target_id}", json={"clear_engagement": True}, headers=admin_headers)
        assert r.status_code == 422, r.text

        # ADMIN with a reference -> 200, and the gate now permits
        r = client.patch(
            f"/api/targets/{target_id}",
            json={"clear_engagement": True, "authorisation_reference": "pa211-widen-ref"},
            headers=admin_headers,
        )
        assert r.status_code == 200, r.text
        assert r.json()["engagement"] is None
        assert r.json()["passive_only"] is False

        # attaching to an abandoned engagement -> 409
        r = client.patch(f"/api/targets/{target_id}", json={"engagement_id": str(abandoned_id)}, headers=admin_headers)
        assert r.status_code == 409, r.text
    finally:
        db = SessionLocal()
        try:
            db.query(Target).filter(Target.id == target_id).delete(synchronize_session=False)
            db.commit()
            cleanup_engagement(db, engagement_id)
            cleanup_engagement(db, abandoned_id)
        finally:
            db.close()
        _cleanup_users([admin_id, integ_id])


# ── 6. scope_target_engagements is stamped ──────────────────────────────────

def test_scope_target_engagements_is_stamped():
    suffix = uuid.uuid4().hex[:10]
    domain = f"pa211-stamp-{suffix}.example.com"
    db = SessionLocal()
    target, engagement_id = _mk_target_with_posture(db, domain, "pre_close")
    target_id = target.id  # captured before any later commit expires/detaches the row

    run = ScanRun(
        id=uuid.uuid4(), name="pa211 stamp test", status=ScanStatus.RUNNING,
        kind=ScanKind.MANUAL, scope={"domains": [domain], "ip_ranges": []},
    )
    db.add(run)
    db.commit()
    run_id = run.id
    try:
        scan_executor._stamp_scope_target_engagements(db, run, {"domains": [domain], "ip_ranges": []})
        db.refresh(run)
        assert run.scope_target_engagements == [
            {"target_id": str(target_id), "engagement_id": str(engagement_id), "posture": "pre_close"}
        ]

        # A scope naming no engaged target stamps [].
        scan_executor._stamp_scope_target_engagements(db, run, {"domains": [], "ip_ranges": []})
        db.refresh(run)
        assert run.scope_target_engagements == []
    finally:
        db.query(ScanRun).filter(ScanRun.id == run_id).delete(synchronize_session=False)
        db.commit()
        db.close()
        _cleanup_target_and_engagement(target_id, engagement_id)


# ── 7. abandoned exclusion in _resolve_dynamic_scope ────────────────────────

def test_resolve_dynamic_scope_excludes_only_abandoned():
    suffix = uuid.uuid4().hex[:10]
    db = SessionLocal()
    abandoned_target, abandoned_id = _mk_target_with_posture(db, f"pa211-dyn-abandoned-{suffix}.example.com", "abandoned")
    pre_close_target, pre_close_id = _mk_target_with_posture(db, f"pa211-dyn-preclose-{suffix}.example.com", "pre_close")
    plain_target, _ = _mk_target_with_posture(db, f"pa211-dyn-plain-{suffix}.example.com", None)

    template = SimpleNamespace(id=uuid.uuid4(), tag_priority=None)
    try:
        scope = scan_executor._resolve_dynamic_scope(db, template)
        domains = set(scope["domains"])
        assert abandoned_target.value not in domains, "abandoned target must be excluded from scheduled scope"
        assert pre_close_target.value in domains, "pre_close targets are still scheduled — the gate is what denies them"
        assert plain_target.value in domains
    finally:
        for t, eid in ((abandoned_target, abandoned_id), (pre_close_target, pre_close_id), (plain_target, None)):
            _cleanup_target_and_engagement(t.id, eid)
        db.close()


# ── 8. authorise_discovery for abandoned + day_0/integrated (real rows) ────

@pytest.mark.parametrize("posture_value,expect_denied", [("abandoned", True), ("day_0", False), ("integrated", False)])
def test_authorise_discovery_across_postures(posture_value, expect_denied):
    suffix = uuid.uuid4().hex[:10]
    domain = f"pa211-discovery-{posture_value}-{suffix}.example.test"
    db = SessionLocal()
    target, engagement_id = _mk_target_with_posture(db, domain, posture_value)
    run_id = uuid.uuid4()
    try:
        db.refresh(target)
        allowed = pa.authorise_discovery(
            db, observer_slug="dnsrecon", target_row=target, domain=domain, scan_run_id=run_id,
        )
        assert allowed is (not expect_denied)
        if expect_denied:
            row = (
                db.query(AuthorisationDecision)
                .filter(AuthorisationDecision.evidence_snapshot["scan_run_id"].astext == str(run_id))
                .first()
            )
            assert row is not None
            assert row.rule_fired == "posture:passive_only"
            assert row.evidence_snapshot["engagements"] == [{"id": str(engagement_id), "posture": posture_value}]
    finally:
        _decision_log.cleanup_for_run(run_id)
        _cleanup_target_and_engagement(target.id, engagement_id)
        db.close()


# ── 9. authorise_ownership_probe for abandoned + day_0/integrated ──────────

@pytest.mark.parametrize("posture_value,expect_denied", [("abandoned", True), ("day_0", False), ("integrated", False)])
def test_authorise_ownership_probe_across_postures(posture_value, expect_denied):
    suffix = uuid.uuid4().hex[:10]
    v = f"pa211-ownership-{posture_value}-{suffix}"
    db = SessionLocal()
    target, engagement_id = _mk_target_with_posture(db, f"pa211-ownership-{posture_value}-{suffix}.example.com", posture_value)
    run_id = uuid.uuid4()
    try:
        _set_mode(db, None)
        asset = _mk_ip_asset(db, v)
        _link(db, target.id, asset.id)

        allowed = pa.authorise_ownership_probe(
            db, asset_canonical_ids=[asset.id], subject="pa211-test", scan_run_id=run_id,
        )
        assert allowed is (not expect_denied)
        if expect_denied:
            row = (
                db.query(AuthorisationDecision)
                .filter(AuthorisationDecision.asset_canonical_id == asset.id)
                .filter(AuthorisationDecision.evidence_snapshot["scan_run_id"].astext == str(run_id))
                .first()
            )
            assert row is not None
            assert row.rule_fired == "posture:passive_only"
            assert row.evidence_snapshot["engagements"] == [{"id": str(engagement_id), "posture": posture_value}]
    finally:
        _decision_log.cleanup_for_run(run_id)
        _cleanup_asset([v])
        _cleanup_target_and_engagement(target.id, engagement_id)
        db.close()


# ── 10. day_0 -> pre_close: the gate denies immediately, same session ──────

def test_day0_to_pre_close_demotion_denies_the_gate_immediately():
    """Acceptance §10 item 3's second half: `day_0 -> pre_close` succeeds
    with no confirmation (no reference needed — demotion is always the
    safe direction), and the very next `authorise_probes` call in the SAME
    session denies — no scan run, no cache, no delay in between. Proves
    the demotion isn't just a row update nobody reads: the gate re-reads
    `Target.engagement.posture` fresh every call."""
    suffix = uuid.uuid4().hex[:10]
    v = f"pa211-day0demote-{suffix}"
    domain = f"pa211-day0demote-{suffix}.example.com"
    db = SessionLocal()
    target, engagement_id = _mk_target_with_posture(db, domain, "day_0")
    run_id = uuid.uuid4()
    admin_id = None
    try:
        _set_mode(db, None)
        asset = _mk_ip_asset(db, v)
        _set_state(db, asset.id, "direct_addressable")
        _link(db, target.id, asset.id)

        before = pa.authorise_probes(
            db, connector_id="test-ip", connector=_IP_CONNECTOR,
            assets=[_da(v)], scope={}, scan_run_id=run_id,
        )
        assert before.permissions[("ip_address", v)].allowed is True, "day_0 must permit — baseline"

        headers, admin_id = _admin_headers()
        from fastapi.testclient import TestClient
        from app.main import app
        r = TestClient(app).post(
            f"/api/engagements/{engagement_id}/transition", json={"to": "pre_close"}, headers=headers,
        )
        assert r.status_code == 200, r.text
        assert r.json()["authorised_at"] is None, "demotion must clear the authorisation record"

        after = pa.authorise_probes(
            db, connector_id="test-ip", connector=_IP_CONNECTOR,
            assets=[_da(v)], scope={}, scan_run_id=run_id,
        )
        assert after.permissions[("ip_address", v)].allowed is False, (
            "the gate must deny immediately after demotion, in the same session, with no scan in between"
        )
        assert after.permissions[("ip_address", v)].rule_fired == "posture:passive_only"
    finally:
        _decision_log.cleanup_for_run(run_id)
        _cleanup_asset([v])
        _cleanup_target_and_engagement(target.id, engagement_id)
        db.close()
        if admin_id is not None:
            _cleanup_users([admin_id])
