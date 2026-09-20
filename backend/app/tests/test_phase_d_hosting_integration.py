"""Real-DB integration proof for planning#188's two acceptance criteria that
test_shared_infra_verifier.py structurally cannot demonstrate, because that
file fakes `classify_ip` and the `_read_cache`/`_write_cache` pair.

Before this issue, `hosting_classifier.classify_ip` asked a third-party
API whose free tier had stopped returning the field the answer was read
from, so classify_ip always returned `attempted=False`. Two consequences
were dead code paths:

  1. Phase D's `ownership_unverifiable` verdict (shared_infra_verifier.py)
     was unreachable — it can only fire when `hosting.attempted` is True.
  2. `shared_infra_verifier` never cached an ownership verdict on the normal
     path — `attempted=False` forces `cacheable = False` on every call.

Here `classify_ip` and `_read_cache`/`_write_cache` are all REAL (a local
`cloud_ranges` lookup, no network) — only `domain_affinity.check_affinity`,
`shared_infra_verifier._owned_hostnames_for_ip`, and
`origin_corroboration.corroborate_liveness` are stubbed, since those are
Phase D's own concerns, not planning#188's.

Real dev DB — no test database. Every row this suite creates (the ip asset,
its claims, the CloudRange rows) is tracked and deleted in a `finally`.
`_owned_hostnames_for_ip` is stubbed, so the "owned hostname" is a bare
SimpleNamespace — it never needs a DB row. The ip_asset MUST be a real
persisted AssetCanonical row, because the real classify_ip and the real
_write_cache both resolve it by id/value.

Run with:  python -m app.tests.test_phase_d_hosting_integration
       or: pytest app/tests/test_phase_d_hosting_integration.py
"""

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.claim import AssetClaim, ClaimHistory
from app.models.cloud_range import CloudRange
from app.models.observer import Observer
from app.services import claim_emitter
from app.services import cloud_ranges
from app.services import domain_affinity as da
from app.services import hosting_classifier as hc
from app.services import origin_corroboration as oc
from app.services import shared_infra_verifier as siv


def _make_ip_asset(db, ip: str) -> AssetCanonical:
    now = datetime.now(timezone.utc)
    row = AssetCanonical(
        id=uuid.uuid4(), asset_type="ip_address", value=ip, parent_value=None,
        first_seen_at=now, last_seen_at=now,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _cleanup(value: str) -> None:
    db = SessionLocal()
    try:
        rows = db.query(AssetCanonical).filter(AssetCanonical.value == value).all()
        ids = [r.id for r in rows]
        if ids:
            db.query(ClaimHistory).filter(ClaimHistory.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.value == value).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _insert_range(db, prefix, provider, service_class, service_raw=None, source="test"):
    row = CloudRange(
        id=uuid.uuid4(), prefix=prefix, ip_version=4, provider=provider,
        service_raw=service_raw, service_class=service_class, region=None, source=source,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _cleanup_ranges(db, ids):
    db.rollback()
    if ids:
        db.query(CloudRange).filter(CloudRange.id.in_(ids)).delete(synchronize_session=False)
        db.commit()


def _owned_host():
    return SimpleNamespace(id=uuid.uuid4(), value="itsupport.contoso.com")


def _affinity_indeterminate(hostname, origin_ip, apexes, ports=None):
    return da.AffinityResult(
        hostname=hostname, origin_ip=origin_ip, verdict=da.VERDICT_INDETERMINATE,
        signals=[], matrix={"443": {"owned": {}}},
    )



def _install_loaded_dataset() -> None:
    """Make `cloud_ranges.dataset_state` report a loaded mirror for THIS test.

    The tests below insert their own CloudRange rows, so `lookup` works
    anywhere — but `classify_ip` also reads `dataset_state`, the single-row
    freshness/provenance marker, and returns `attempted=False` when it is
    absent. On the dev DB that row exists (a real mirror is loaded), so
    assuming it is there passes locally and fails in CI, whose database is
    migrated but empty. That is the assumption, not the environment, being
    wrong: a test that needs a loaded dataset must provide one.

    `cloud_ranges` is in conftest.py's _GUARDED_MODULES, so this is restored
    after each test. Monkeypatched rather than inserted because
    cloud_ranges_meta is a single-row table holding the REAL mirror on the
    dev DB — writing to it would clobber live provenance.
    """
    state = cloud_ranges.DatasetState(
        dataset_sha256="testsha", generated_at=datetime.now(timezone.utc),
        record_count=1, stale=False,
    )
    cloud_ranges.dataset_state = lambda db: state

def test_phase_d_reaches_ownership_unverifiable_from_a_real_cloud_range():
    suffix = uuid.uuid4().hex[:10]
    ip = f"203.0.113.{10 + (int(suffix[:2], 16) % 60)}"
    range_id = None

    _install_loaded_dataset()
    db = SessionLocal()
    try:
        ip_asset = _make_ip_asset(db, ip)
        range_id = _insert_range(db, f"{ip}/32", "testcloud", "compute", service_raw="raw").id

        da.check_affinity = _affinity_indeterminate
        siv._owned_hostnames_for_ip = lambda db, ip: [_owned_host()]
        oc.corroborate_liveness = lambda db, origin_ip, subject_value, owned_apexes: oc.CorroborationResult(
            attempted=True, origin_serves_others=True, corroborating_hostname="othertenant.example",
            evidence="tls_san_match", hostnames_probed=["othertenant.example"],
        )

        result = siv.classify_ip_ownership(db, ip_asset)
        assert result["verdict"] == "ownership_unverifiable"
        assert result["evidence"]["hosting_class"]["provider"] == "testcloud"
    finally:
        db.close()
        _cleanup(ip)
        if range_id is not None:
            db2 = SessionLocal()
            try:
                _cleanup_ranges(db2, [range_id])
            finally:
                db2.close()


def test_shared_infra_verifier_caches_again_on_the_normal_path():
    """The observable proof the fix worked. Under the retired third-party
    lookup this affinity_confirmation claim was never written, because
    attempted=False forced cacheable=False on every single call."""
    suffix = uuid.uuid4().hex[:10]
    ip = f"203.0.113.{80 + (int(suffix[:2], 16) % 60)}"
    range_id = None

    _install_loaded_dataset()
    db = SessionLocal()
    try:
        ip_asset = _make_ip_asset(db, ip)
        range_id = _insert_range(db, f"{ip}/32", "testcloud", "compute", service_raw="raw").id

        da.check_affinity = _affinity_indeterminate
        siv._owned_hostnames_for_ip = lambda db, ip: [_owned_host()]
        oc.corroborate_liveness = lambda db, origin_ip, subject_value, owned_apexes: oc.CorroborationResult(
            attempted=True, origin_serves_others=False,
        )

        result = siv.classify_ip_ownership(db, ip_asset)
        assert result["verdict"] == "unverified"

        claim = claim_emitter.get_current_claim(
            db, ip_asset.id, "shared_infra_verifier", "affinity_confirmation",
        )
        assert claim is not None
    finally:
        db.close()
        _cleanup(ip)
        if range_id is not None:
            db2 = SessionLocal()
            try:
                _cleanup_ranges(db2, [range_id])
            finally:
                db2.close()


def test_no_dataset_still_suppresses_the_cache():
    """The guard still works, for the right reason: no cloud_ranges dataset
    loaded is our own outage, not a real 'not a datacenter' determination,
    so it must never be cached. Same rule as before planning#188, but the
    cause it guards against is now systemic rather than per-IP."""
    suffix = uuid.uuid4().hex[:10]
    ip = f"203.0.113.{140 + (int(suffix[:2], 16) % 60)}"

    db = SessionLocal()
    try:
        ip_asset = _make_ip_asset(db, ip)

        da.check_affinity = _affinity_indeterminate
        siv._owned_hostnames_for_ip = lambda db, ip: [_owned_host()]

        def _should_not_be_called(*a, **k):
            raise AssertionError("corroborate_liveness must not be called when the hosting lookup itself failed")
        oc.corroborate_liveness = _should_not_be_called

        # Delete any pre-existing affinity_confirmation claim for this asset
        # first so the "no claim was written" assertion means something.
        observer_id = db.query(Observer.id).filter(Observer.name == "shared_infra_verifier").scalar()
        if observer_id is not None:
            db.query(AssetClaim).filter(
                AssetClaim.asset_canonical_id == ip_asset.id,
                AssetClaim.observer_id == observer_id,
                AssetClaim.claim_type == "affinity_confirmation",
            ).delete(synchronize_session=False)
            db.commit()

        hc.cloud_ranges.dataset_state = lambda db: None

        result = siv.classify_ip_ownership(db, ip_asset)
        assert result["verdict"] == "unverified"

        claim = claim_emitter.get_current_claim(
            db, ip_asset.id, "shared_infra_verifier", "affinity_confirmation",
        )
        assert claim is None
    finally:
        db.close()
        _cleanup(ip)


def _run():
    tests = [
        test_phase_d_reaches_ownership_unverifiable_from_a_real_cloud_range,
        test_shared_infra_verifier_caches_again_on_the_normal_path,
        test_no_dataset_still_suppresses_the_cache,
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
