"""Deleting an asset that the probe-authorisation gate has evaluated must
succeed, not raise (planning#195).

`authorisation_decisions.asset_canonical_id` FK'd to `assets_canonical.id`
with `NO ACTION` — the only child of `assets_canonical` that did not
cascade (every sibling — `asset_claims`, `asset_state`,
`asset_hygiene_score`, `findings_canonical`, `target_asset_links` — is
`ON DELETE CASCADE`). Measured on dev before this fix: **all 4 assets in
the database were undeletable** — any asset the gate had ever logged a
decision about raised `ForeignKeyViolation` on delete, through three
reachable paths: the admin single-asset delete (`api/assets.py:
delete_asset`), the bulk apex delete (`delete_assets_by_apex`), and the
target-cascade delete (`api/targets.py:_soft_cascade_target_assets`, which
also takes the surrounding target delete down with it).

planning#195 changed the FK to `ON DELETE SET NULL`: the decision row
survives, only its reference is cleared. This file pins that behaviour at
three levels — the raw delete (test 1), the evidence self-description that
makes an orphaned row still readable (test 2, Part 3 of the fix), the
decision-log hygiene-guard interaction the issue was filed worrying about
(test 3) — and exercises both of the two production delete paths that
previously failed (test 4: the admin HTTP route; test 5: the target-cascade
bulk path).

Every test creates its own asset(s) and decision row(s) and cleans up by
id in a `finally` block: `AssetCanonical`/`Target`/`TargetAssetLink` rows
by id (idempotent — a no-op if the delete under test already removed
them), and `authorisation_decisions` rows via
`_decision_log.cleanup_for_run(run_id)`, keyed on a real, freshly minted
`scan_run_id` stamped into `evidence_snapshot` — never a synthetic run id
attached to a residue-shaped row (see `_decision_log`'s own docstring for
why that distinction matters on a suite that runs against the live dev
DB).

This file is a decision-log writer and is registered in
`test_zz_decision_log_hygiene.py`'s `_DECISION_WRITING_TESTS`.

## ⚠ What SET NULL changed for EVERY test in this suite, not just this file

Before planning#195 the FK was `NO ACTION`, so deleting an asset that had
decision rows RAISED. That error was load-bearing as a test-suite safety
net: it meant a cleanup could not delete an asset out from under its own
decision rows without failing loudly, and it meant one test file could not
quietly destroy another's rows by a value collision.

`ON DELETE SET NULL` converts that loud failure into a SILENT ORPHAN. The
row survives with `asset_canonical_id = NULL`, so any cleanup keyed on the
asset id — which is most of them, including
`test_probe_authorisation.py::_cleanup` — stops matching it and the row
leaks. Two consequences a future test author needs:

  1. **Delete decision rows BEFORE the asset they reference, never after.**
     `_cleanup` already gets this right (it deletes `AuthorisationDecision`
     by asset id first, then the asset), and it is now right for a reason
     it was not written for. Cleaning up by `scan_run_id` instead — what
     this file does — is immune to the ordering entirely and is the safer
     idiom for anything new.
  2. **Any handler that deletes assets by VALUE is now a cross-file
     hazard.** `_soft_cascade_target_assets` and `delete_assets_by_apex`
     both end in `_sweep_cname_descendants`, which deletes every asset
     whose `parent_value` matches — so a test driving either one with a
     colliding address reaches another file's rows and orphans their
     decision rows without raising. The two tests here that call those
     handlers therefore use unique non-IP values rather than
     `_docaddr.alloc()`, whose pool is knowingly overlapped
     (planning#171); each one says so at its call site.

The hygiene guards still catch the resulting leak — `unreachable_count()`
if the orphan had no run id, the total-count guard if it did — so this is a
"you will find out" hazard rather than a silent one. But it is found one
run later, by a test that did nothing wrong.

Run with:  python -m app.tests.test_asset_delete_with_decisions
       or: pytest app/tests/test_asset_delete_with_decisions.py
"""

import uuid
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import assets as assets_api
from app.api import targets as targets_api
from app.api.deps import get_current_user
from app.connectors.base import DiscoveredAsset
from app.core.database import SessionLocal, get_db
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.authorisation_decision import AuthorisationDecision
from app.models.target import Target
from app.models.target_asset_link import TargetAssetLink
from app.models.user import User, UserRole
from app.services import probe_authorisation as pa
from app.tests import _decision_log
from app.tests._docaddr import alloc as _alloc_ip


# ── helpers ──────────────────────────────────────────────────────────────
#
# Deliberately NOT imported from `test_probe_authorisation.py`, even though
# `_StubConnector`/`_IP_CONNECTOR`/`_da` there are exactly this shape: no
# test file in this suite imports from another (each is independently
# runnable as `python -m app.tests.<module>`), so this file follows that
# convention rather than being the first cross-file import.

def _mk_ip_asset(db, value: str) -> AssetCanonical:
    now = datetime.now(timezone.utc)
    row = AssetCanonical(
        id=uuid.uuid4(), asset_type="ip_address", value=value,
        first_seen_at=now, last_seen_at=now,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _set_state(db, asset_id: uuid.UUID, probe_class: str) -> None:
    db.add(AssetState(
        asset_canonical_id=asset_id,
        attributes={"probe_class": probe_class},
        projected_at=datetime.now(timezone.utc),
    ))
    db.commit()


def _mk_decision_row(db, asset_id: uuid.UUID, scan_run_id: uuid.UUID) -> AuthorisationDecision:
    """A decision row referencing `asset_id`, written directly (not through
    the gate) — tests 1 and 3 only need a row with the right shape, not a
    real gate verdict. Carries a REAL `scan_run_id` so it is never
    residue-shaped (see this module's docstring and `_decision_log.py`)."""
    row = AuthorisationDecision(
        id=uuid.uuid4(),
        asset_canonical_id=asset_id,
        allowed=True,
        probe_modes=["ip"],
        authorised_names=[],
        rule_fired="probe_class:direct_addressable",
        evidence_snapshot={
            "connector_id": "test-pa195",
            "observer": "naabu",
            "decision_scope": "asset",
            "scan_run_id": str(scan_run_id),
        },
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


class _StubConnector:
    """Minimal Phase 1.5 connector stand-in, mirroring
    `test_probe_authorisation.py`'s `_StubConnector` — the gate only ever
    reads `.observer` off whatever it's handed."""

    def __init__(self, observer_name: str):
        self.observer = observer_name


_IP_CONNECTOR = _StubConnector("naabu")  # addressing == "ip"


def _da(value: str) -> DiscoveredAsset:
    return DiscoveredAsset(asset_type="ip_address", value=value)


def _cleanup_asset(asset_id: uuid.UUID | None) -> None:
    """Idempotent: a no-op if the delete under test already removed the
    row, which is the expected outcome for every test below."""
    if asset_id is None:
        return
    db = SessionLocal()
    try:
        db.query(AssetCanonical).filter(AssetCanonical.id == asset_id).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _cleanup_target(target_id: uuid.UUID | None) -> None:
    if target_id is None:
        return
    db = SessionLocal()
    try:
        db.query(Target).filter(Target.id == target_id).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _admin_client() -> TestClient:
    """A minimal app carrying the real `assets` router, matching
    `test_api_rbac.py`'s harness: `dependency_overrides` for `get_db` (a
    real session against the dev DB) and `get_current_user` (an
    unpersisted ADMIN `User` — `require_role` only reads attributes off
    it, so there is no reason to write a users row for this)."""
    app = FastAPI()
    app.include_router(assets_api.router, prefix="/api/assets")

    def _db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _db
    admin = User(
        id=uuid.uuid4(),
        email=f"pa195-admin-{uuid.uuid4().hex[:8]}@example.invalid",
        full_name="pa195 admin",
        role=UserRole.ADMIN.value,
        is_active=True,
    )
    app.dependency_overrides[get_current_user] = lambda: admin
    return TestClient(app)


# ── 1. the core behaviour: delete succeeds, row survives, orphaned ────────

def test_deleting_an_asset_with_decision_rows_succeeds_and_orphans_them():
    """Before planning#195, `db.delete(asset)` on an asset with a decision
    row raised `ForeignKeyViolation` (FK was `NO ACTION`) and the delete
    never committed. After: the delete succeeds, the decision row still
    exists, its `asset_canonical_id` is now NULL, and every other field
    (`rule_fired`, `evidence_snapshot`) is untouched — SET NULL clears
    exactly the one column it names, nothing else."""
    run_id = uuid.uuid4()
    db = SessionLocal()
    asset_id = None
    try:
        asset = _mk_ip_asset(db, _alloc_ip())
        asset_id = asset.id
        decision = _mk_decision_row(db, asset.id, run_id)
        decision_id = decision.id
        original_evidence = dict(decision.evidence_snapshot)
        original_rule = decision.rule_fired

        db.delete(asset)
        db.commit()  # must NOT raise ForeignKeyViolation

        db.expire_all()
        assert db.get(AssetCanonical, asset_id) is None, "the asset itself must be gone"

        reread = db.get(AuthorisationDecision, decision_id)
        assert reread is not None, "the decision row must survive the asset delete"
        assert reread.asset_canonical_id is None, "SET NULL must clear the FK reference"
        assert reread.rule_fired == original_rule, "SET NULL must not touch unrelated columns"
        assert reread.evidence_snapshot == original_evidence, "evidence_snapshot must be untouched"
    finally:
        db.close()
        _cleanup_asset(asset_id)
        _decision_log.cleanup_for_run(run_id)


# ── 2. Part 3's payoff: the orphaned row still says what it was about ────

def test_the_orphaned_row_still_says_what_it_was_about():
    """Drives a real `authorise_probes` call so `evidence_snapshot` is
    built by `_compose`, not hand-written, then deletes the asset and
    checks the surviving row still names its subject via the
    `asset_type`/`asset_value` keys `_compose` now writes (planning#195
    Part 3). This is what makes SET NULL non-lossy: without those keys, an
    orphaned row would retain no trace of what it was ever about."""
    run_id = uuid.uuid4()
    v = _alloc_ip()
    db = SessionLocal()
    asset_id = None
    try:
        asset = _mk_ip_asset(db, v)
        asset_id = asset.id
        _set_state(db, asset.id, "direct_addressable")

        gate = pa.authorise_probes(
            db, connector_id="test-pa195", connector=_IP_CONNECTOR,
            assets=[_da(v)], scope={}, scan_run_id=run_id,
        )
        assert gate.permissions[("ip_address", v)].allowed is True

        row = (
            db.query(AuthorisationDecision)
            .filter(AuthorisationDecision.asset_canonical_id == asset.id)
            .one()
        )
        decision_id = row.id

        db.delete(asset)
        db.commit()

        db.expire_all()
        reread = db.get(AuthorisationDecision, decision_id)
        assert reread.asset_canonical_id is None
        assert reread.evidence_snapshot["asset_value"] == v, (
            "the orphaned row must still say which asset it was about"
        )
        assert reread.evidence_snapshot["asset_type"] == "ip_address"
    finally:
        db.close()
        _cleanup_asset(asset_id)
        _decision_log.cleanup_for_run(run_id)


# ── 3. measured finding 1: an orphaned row is not residue ────────────────

def test_an_orphaned_row_is_not_residue():
    """Pins the interaction planning#195 was filed worrying about:
    `_decision_log._unreachable` matches `asset_canonical_id IS NULL AND
    no scan_run_id`. The issue worried a SET NULL orphan would start
    matching that shape. It cannot, for a real row: SET NULL clears only
    `asset_canonical_id`, never `evidence_snapshot`, so a row that carried
    a `scan_run_id` before being orphaned still carries it afterward and
    still fails the residue predicate's second term. This is a non-problem
    for real rows specifically BECAUSE real rows always carry a run id
    (measured on dev: 92/92) — a test that deliberately omits one, by
    contrast, WOULD create genuine residue this way; that is a feature of
    the guard, not a bug in this fix (see `_decision_log`'s module
    docstring)."""
    run_id = uuid.uuid4()
    db = SessionLocal()
    asset_id = None
    try:
        before = _decision_log.unreachable_count()

        asset = _mk_ip_asset(db, _alloc_ip())
        asset_id = asset.id
        _mk_decision_row(db, asset.id, run_id)

        db.delete(asset)
        db.commit()

        after = _decision_log.unreachable_count()
        assert after == before, (
            f"orphaning a run-id-carrying decision row changed unreachable_count() "
            f"({before} -> {after}) — it must not, because the row still carries "
            "its scan_run_id and so still fails _unreachable's second term."
        )
    finally:
        db.close()
        _cleanup_asset(asset_id)
        _decision_log.cleanup_for_run(run_id)


# ── 4. through the HTTP layer: the admin delete route ─────────────────────

def test_admin_delete_asset_route_returns_success_not_500():
    """The acceptance criterion is explicitly "through the admin delete
    path, not just at the schema level" — `api/assets.py:delete_asset`
    does a bare `db.delete(asset)` + `db.commit()` with no exception
    handler, so before planning#195 this route returned an unhandled 500
    for any asset the gate had evaluated. `delete_asset` declares
    `status_code=204` (confirmed against `app/api/assets.py`), so success
    here is 204, not merely "any 2xx" — asserted as both."""
    run_id = uuid.uuid4()
    v = _alloc_ip()
    db = SessionLocal()
    asset_id = None
    decision_id = None
    try:
        asset = _mk_ip_asset(db, v)
        asset_id = asset.id
        decision = _mk_decision_row(db, asset.id, run_id)
        decision_id = decision.id
    finally:
        db.close()

    client = _admin_client()
    r = client.delete(f"/api/assets/{asset_id}")
    assert 200 <= r.status_code < 300, f"expected 2xx, got {r.status_code}: {r.text}"
    assert r.status_code == 204, f"delete_asset declares status_code=204; got {r.status_code}: {r.text}"

    check = SessionLocal()
    try:
        assert check.get(AssetCanonical, asset_id) is None, "the asset must be gone"
        reread = check.get(AuthorisationDecision, decision_id)
        assert reread is not None, "the decision row must survive"
        assert reread.asset_canonical_id is None, "and be orphaned, not deleted with the asset"
    finally:
        check.close()
        _cleanup_asset(asset_id)
        _decision_log.cleanup_for_run(run_id)


# ── 5. the path most likely to bite in production: target cascade ────────

def test_target_cascade_does_not_fail_the_batch_on_a_gated_asset():
    """Before planning#195, one gated asset's `ForeignKeyViolation` failed
    the WHOLE batch delete in `_soft_cascade_target_assets` — and because
    that function runs inside `bulk_delete_targets`/`delete_target`, it
    took the surrounding target delete down with it too. This creates a
    target with TWO linked assets, puts a decision row on only one of
    them, and asserts the batch delete covers both — the gated asset no
    longer poisons its ungated sibling's delete."""
    suffix = uuid.uuid4().hex[:10]
    target_value = f"pa195-target-{suffix}.example.test"
    run_id = uuid.uuid4()
    db = SessionLocal()
    target_id = None
    asset_gated_id = None
    asset_plain_id = None
    try:
        target = Target(id=uuid.uuid4(), type="domain", value=target_value)
        db.add(target)
        db.commit()
        db.refresh(target)
        target_id = target.id

        # NOT `_docaddr.alloc()` here, unlike the tests above, and the
        # reason is specific to this code path: `_soft_cascade_target_assets`
        # ends in `_sweep_cname_descendants(db, seed_values)`, which deletes
        # every asset whose `parent_value` is one of the values being
        # deleted — by VALUE, recursively, up to 8 levels. `_docaddr`'s pool
        # is knowingly overlapped by `test_cloud_inventory_claim`'s
        # `192.0.2.{n % 200 + 10}` window (planning#171, documented in
        # `_docaddr.py`'s own docstring), so a colliding draw would make this
        # test delete ANOTHER file's asset mid-run. That was survivable
        # before planning#195 — the FK raised — but now the victim's
        # decision rows would silently orphan instead, which is a leak this
        # file's own run-id cleanup cannot reach. A unique non-IP value
        # cannot collide with anything, and nothing here parses it as an
        # address (`test_probe_authorisation.py` uses non-IP values for
        # `ip_address` rows the same way).
        asset_gated = _mk_ip_asset(db, f"pa195-cascade-gated-{suffix}")
        asset_plain = _mk_ip_asset(db, f"pa195-cascade-plain-{suffix}")
        asset_gated_id = asset_gated.id
        asset_plain_id = asset_plain.id

        db.add(TargetAssetLink(target_id=target.id, asset_canonical_id=asset_gated.id))
        db.add(TargetAssetLink(target_id=target.id, asset_canonical_id=asset_plain.id))
        db.commit()

        _mk_decision_row(db, asset_gated.id, run_id)

        count = targets_api._soft_cascade_target_assets(db, [target.id])
        db.commit()
        assert count == 2, f"expected both assets counted in the batch, got {count}"

        db.expire_all()
        remaining = (
            db.query(AssetCanonical)
            .filter(AssetCanonical.id.in_([asset_gated_id, asset_plain_id]))
            .count()
        )
        assert remaining == 0, "both assets must be gone, including the gated one"

        reread = (
            db.query(AuthorisationDecision)
            .filter(AuthorisationDecision.evidence_snapshot["scan_run_id"].astext == str(run_id))
            .one()
        )
        assert reread.asset_canonical_id is None, "the decision row must survive, orphaned"

        db.delete(target)
        db.commit()
        target_id = None
    finally:
        db.close()
        _cleanup_asset(asset_gated_id)
        _cleanup_asset(asset_plain_id)
        _cleanup_target(target_id)
        _decision_log.cleanup_for_run(run_id)


def test_delete_by_apex_batch_survives_a_gated_asset():
    """The third reachable path planning#195 names, and the one the other
    tests here leave uncovered.

    `delete_assets_by_apex` (`api/assets.py:267`) is the apex-group bulk
    delete behind the UI's "delete this apex" action. It shares
    `_soft_cascade_target_assets`'s shape — one `.delete(
    synchronize_session=False)` over a batch of ids — so before
    planning#195 a single gated asset anywhere in the group raised
    `ForeignKeyViolation` and took the entire group's delete with it,
    including every ungated sibling. That is the worst-blast-radius
    version of this defect: the larger the apex group, the more assets one
    gated row could block.

    Called directly with `_=None` rather than through `TestClient`,
    unlike `test_admin_delete_asset_route_returns_success_not_500` above.
    That is the suite's ordinary API-test convention and it is the right
    one HERE because the thing under test is the handler's delete
    behaviour, not its auth wiring — `test_api_rbac.py`'s docstring
    explains that `_=None` cannot test a route's *dependencies*, which is
    a different question from whether its body works.

    `exclude_from_connector=False` deliberately: the connector-exclusion
    half of this handler writes to `connector_config`, which is shared
    state this test has no business touching.
    """
    suffix = uuid.uuid4().hex[:10]
    run_id = uuid.uuid4()
    db = SessionLocal()
    asset_gated_id = None
    asset_plain_id = None
    try:
        # Unique non-IP values, not `_docaddr.alloc()` — same reason as
        # `test_target_cascade_does_not_fail_the_batch_on_a_gated_asset`
        # below: this handler also ends in `_sweep_cname_descendants`,
        # which deletes by `parent_value`, so a colliding address would
        # reach another test file's rows.
        asset_gated = _mk_ip_asset(db, f"pa195-apex-gated-{suffix}")
        asset_plain = _mk_ip_asset(db, f"pa195-apex-plain-{suffix}")
        asset_gated_id = asset_gated.id
        asset_plain_id = asset_plain.id
        _mk_decision_row(db, asset_gated.id, run_id)

        result = assets_api.delete_assets_by_apex(
            assets_api.DeleteByApexRequest(
                apex=f"pa195-apex-{suffix}.example.test",
                asset_ids=[asset_gated_id, asset_plain_id],
                exclude_from_connector=False,
            ),
            db=db,
            _=None,
        )
        assert result["deleted"] >= 2, f"both assets must be counted as deleted: {result!r}"

        db.expire_all()
        remaining = (
            db.query(AssetCanonical)
            .filter(AssetCanonical.id.in_([asset_gated_id, asset_plain_id]))
            .count()
        )
        assert remaining == 0, (
            "both assets must be gone — before planning#195 the gated one's FK "
            "violation aborted the whole batch, taking its ungated sibling with it"
        )

        reread = (
            db.query(AuthorisationDecision)
            .filter(AuthorisationDecision.evidence_snapshot["scan_run_id"].astext == str(run_id))
            .one()
        )
        assert reread.asset_canonical_id is None, "the decision row must survive, orphaned"
    finally:
        db.close()
        _cleanup_asset(asset_gated_id)
        _cleanup_asset(asset_plain_id)
        _decision_log.cleanup_for_run(run_id)


def _run():
    tests = [
        test_deleting_an_asset_with_decision_rows_succeeds_and_orphans_them,
        test_the_orphaned_row_still_says_what_it_was_about,
        test_an_orphaned_row_is_not_residue,
        test_admin_delete_asset_route_returns_success_not_500,
        test_target_cascade_does_not_fail_the_batch_on_a_gated_asset,
        test_delete_by_apex_batch_survives_a_gated_asset,
    ]
    for fn in tests:
        fn()
        print(f"ok  {fn.__name__}")
    print("all passed")


if __name__ == "__main__":
    _run()
