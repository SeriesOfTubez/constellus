"""Tests for the Tier 0 tenancy enricher (planning#181).

Real dev DB, no isolation. Every asset/range row this suite creates is
tracked by id/value and deleted in a finally block; `cloud_ranges_meta` is
snapshotted and restored exactly, never table-wide deleted (a real loaded
dataset would be wiped by that). `cloud_ranges`/`tenancy_enricher` are in
conftest.py's `_GUARDED_MODULES`, so raw-assignment monkeypatches here
(`cloud_ranges.dataset_state = ...`, `cr._download_dataset_to_file = ...`
style) are auto-restored between tests.

IP addresses are RFC 5737 documentation ranges per the repo's gitleaks
non-reserved-public-ipv4 rule (planning#171).

Run with:  python -m app.tests.test_tenancy_enricher
       or: pytest app/tests/test_tenancy_enricher.py
"""

import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from sqlalchemy import bindparam, text

from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.claim import ClaimHistory
from app.models.cloud_range import CloudRange
from app.services import cloud_ranges
from app.services import tenancy_enricher as te
from app.services.claim_emitter import get_current_claim, upsert_single_claim


# ── helpers ──────────────────────────────────────────────────────────────

def _make_ip_asset(db, ip: str, first_seen_at: datetime | None = None) -> AssetCanonical:
    now = first_seen_at or datetime.now(timezone.utc)
    row = AssetCanonical(
        id=uuid.uuid4(), asset_type="ip_address", value=ip, parent_value=None,
        first_seen_at=now, last_seen_at=now,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _cleanup(values: list[str]) -> None:
    db = SessionLocal()
    try:
        rows = db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).all()
        ids = [r.id for r in rows]
        if ids:
            db.query(ClaimHistory).filter(ClaimHistory.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).delete(synchronize_session=False)
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


def _tick_isolated(own_values: list[str]) -> None:
    """Run `tick()` without leaving claims on assets this test doesn't own.

    `tick()` deliberately sweeps ip_address assets across the WHOLE table (up
    to IPS_PER_TICK) — that is its job in production. Called bare from a test
    against the shared dev DB, it therefore durably stamps `tenancy` claims
    onto real, unrelated assets, and those claims carry THIS test's fake
    `dataset_sha256`/`dataset_generated_at`. That is worse than ordinary test
    residue: the provenance those fields exist to preserve would be fabricated,
    and planning#182's gate reads exactly these claims.

    So: snapshot which assets already had a tenancy claim, run the tick, then
    drop any claim it added to an asset that is not one of `own_values`
    (planning#163 — snapshot-and-restore, assert on your own rows).
    """
    db = SessionLocal()
    try:
        db.rollback()
        before = {
            r[0] for r in db.execute(text(
                "SELECT cl.asset_canonical_id FROM asset_claims cl "
                "JOIN observers o ON o.id = cl.observer_id "
                "WHERE o.name = 'tenancy_enricher' AND cl.claim_type = 'tenancy'"
            )).all()
        }
    finally:
        db.close()

    te.tick()

    db = SessionLocal()
    try:
        db.rollback()
        rows = db.execute(text(
            "SELECT cl.id, cl.asset_canonical_id, ac.value FROM asset_claims cl "
            "JOIN observers o ON o.id = cl.observer_id "
            "JOIN assets_canonical ac ON ac.id = cl.asset_canonical_id "
            "WHERE o.name = 'tenancy_enricher' AND cl.claim_type = 'tenancy'"
        )).all()
        own = set(own_values)
        stray_claims = [r[0] for r in rows if r[1] not in before and r[2] not in own]
        stray_assets = [r[1] for r in rows if r[1] not in before and r[2] not in own]
        if stray_claims:
            db.execute(
                text(
                    "DELETE FROM claim_history WHERE claim_type = 'tenancy' "
                    "AND asset_canonical_id IN :ids"
                ).bindparams(bindparam("ids", expanding=True)),
                {"ids": stray_assets},
            )
            db.execute(
                text("DELETE FROM asset_claims WHERE id IN :ids").bindparams(
                    bindparam("ids", expanding=True)
                ),
                {"ids": stray_claims},
            )
            db.commit()
    finally:
        db.close()


def _snapshot_meta(db):
    db.rollback()
    return db.execute(text(
        "SELECT dataset_sha256, generated_at, record_count, refreshed_at, manifest "
        "FROM cloud_ranges_meta WHERE id = true"
    )).first()


def _restore_meta(db, snapshot):
    db.rollback()
    db.execute(text("DELETE FROM cloud_ranges_meta"))
    if snapshot is not None:
        import json
        db.execute(text(
            "INSERT INTO cloud_ranges_meta (id, dataset_sha256, generated_at, record_count, refreshed_at, manifest) "
            "VALUES (true, :sha, :gen, :cnt, :ref, CAST(:manifest AS jsonb))"
        ), {
            "sha": snapshot.dataset_sha256, "gen": snapshot.generated_at,
            "cnt": snapshot.record_count, "ref": snapshot.refreshed_at,
            "manifest": json.dumps(snapshot.manifest),
        })
    db.commit()


@contextmanager
def _seeded_meta(db, sha="test-dataset-sha", generated_at=None):
    """Snapshot cloud_ranges_meta, install a known-good row for the
    duration of the block, then restore exactly what was there before."""
    snapshot = _snapshot_meta(db)
    db.execute(text("DELETE FROM cloud_ranges_meta"))
    db.execute(text(
        "INSERT INTO cloud_ranges_meta (id, dataset_sha256, generated_at, record_count, refreshed_at, manifest) "
        "VALUES (true, :sha, :gen, 3, now(), '{}'::jsonb)"
    ), {"sha": sha, "gen": generated_at or datetime.now(timezone.utc)})
    db.commit()
    try:
        yield
    finally:
        _restore_meta(db, snapshot)


# ── tenancy_for_match: pure mapping ──────────────────────────────────────

def test_tenancy_for_match_mapping():
    def _match(service_class):
        return cloud_ranges.CloudRangeMatch(
            prefix="192.0.2.0/24", provider="test-provider", service_raw="raw",
            service_class=service_class, region=None, source="test",
        )

    assert te.tenancy_for_match(None) == (te.UNDETERMINED, "no_matching_prefix")
    assert te.tenancy_for_match(_match("compute")) == (te.SINGLE_TENANT, "provider_service_class_compute")
    assert te.tenancy_for_match(_match("edge")) == (te.NOT_SINGLE_TENANT, "provider_service_class_edge")
    assert te.tenancy_for_match(_match("storage")) == (te.NOT_SINGLE_TENANT, "provider_service_class_storage")
    assert te.tenancy_for_match(_match("managed")) == (te.NOT_SINGLE_TENANT, "provider_service_class_managed")
    assert te.tenancy_for_match(_match("unknown")) == (te.UNDETERMINED, "service_class_unknown")


# ── tri-state end to end ─────────────────────────────────────────────────

def test_tick_tri_state_end_to_end():
    ip_compute = "192.0.2.10"
    ip_edge = "198.51.100.10"
    ip_unknown = "203.0.113.10"
    values = [ip_compute, ip_edge, ip_unknown]

    db = SessionLocal()
    range_ids = []
    try:
        with _seeded_meta(db):
            r1 = _insert_range(db, f"{ip_compute}/32", "aws", "compute", service_raw="EC2")
            r2 = _insert_range(db, f"{ip_edge}/32", "cloudflare", "edge", service_raw="CLOUDFRONT")
            r3 = _insert_range(db, f"{ip_unknown}/32", "azure", "unknown", service_raw="AzureCloud.eastus")
            range_ids = [r1.id, r2.id, r3.id]

            _make_ip_asset(db, ip_compute)
            _make_ip_asset(db, ip_edge)
            _make_ip_asset(db, ip_unknown)

            _tick_isolated([ip_compute, ip_edge, ip_unknown])

            asset_compute = db.query(AssetCanonical).filter(AssetCanonical.value == ip_compute).one()
            asset_edge = db.query(AssetCanonical).filter(AssetCanonical.value == ip_edge).one()
            asset_unknown = db.query(AssetCanonical).filter(AssetCanonical.value == ip_unknown).one()

            claim_compute = get_current_claim(db, asset_compute.id, "tenancy_enricher", "tenancy")
            claim_edge = get_current_claim(db, asset_edge.id, "tenancy_enricher", "tenancy")
            claim_unknown = get_current_claim(db, asset_unknown.id, "tenancy_enricher", "tenancy")

            assert claim_compute is not None
            assert claim_compute.claim_value["tenancy"] == te.SINGLE_TENANT
            assert claim_compute.claim_value["decided_by_tier"] == 0

            assert claim_edge is not None
            assert claim_edge.claim_value["tenancy"] == te.NOT_SINGLE_TENANT

            assert claim_unknown is not None
            assert claim_unknown.claim_value["tenancy"] == te.UNDETERMINED
            assert claim_unknown.claim_value["reason"] == "service_class_unknown"
            assert claim_unknown.claim_value["decided_by_tier"] is None

            for claim in (claim_compute, claim_edge, claim_unknown):
                assert claim.claim_value["dataset_sha256"] == "test-dataset-sha"
                assert claim.claim_value["dataset_generated_at"] is not None
    finally:
        db2 = SessionLocal()
        _cleanup_ranges(db2, range_ids)
        db2.close()
        db.close()
        _cleanup(values)


# ── unenriched vs enriched-no-answer ─────────────────────────────────────

def test_unenriched_is_distinguishable_from_enriched_no_answer():
    """planning#181's whole acceptance criterion: before the tick the asset
    has NO tenancy claim at all (unenriched); after, it has one reading
    'undetermined' (enriched, no answer). These must never collapse into
    the same observable state."""
    ip = "203.0.113.20"
    db = SessionLocal()
    try:
        # This test asserts the no-answer half, so the IP must genuinely match
        # nothing. It does: planning#183 dropped every non-global prefix from
        # the published dataset, so RFC 5737 — the only address space the
        # gitleaks rule lets this suite use — is no longer claimed by Vultr's
        # feed as `compute`.
        with _seeded_meta(db):
            asset = _make_ip_asset(db, ip)

            before = get_current_claim(db, asset.id, "tenancy_enricher", "tenancy")
            assert before is None, "planning#181: an unenriched asset must have NO tenancy claim row"

            _tick_isolated([ip])

            after = get_current_claim(db, asset.id, "tenancy_enricher", "tenancy")
            assert after is not None, "planning#181: after enrichment a claim row must exist"
            assert after.claim_value["tenancy"] == te.UNDETERMINED
    finally:
        db.close()
        _cleanup([ip])


# ── no dataset writes nothing ────────────────────────────────────────────

def test_no_dataset_writes_nothing():
    ip = "203.0.113.30"
    db = SessionLocal()
    try:
        asset = _make_ip_asset(db, ip)
        cloud_ranges.dataset_state = lambda db: None

        _tick_isolated([ip])

        claim = get_current_claim(db, asset.id, "tenancy_enricher", "tenancy")
        assert claim is None, "no cloud-ranges dataset must leave the asset unenriched, not 'undetermined'"
    finally:
        db.close()
        _cleanup([ip])


# ── retry timing ──────────────────────────────────────────────────────────

def test_undetermined_retries_at_6h_decided_does_not_refresh_before_7d():
    ip_undetermined = "203.0.113.40"
    ip_decided = "203.0.113.41"
    values = [ip_undetermined, ip_decided]
    db = SessionLocal()
    try:
        with _seeded_meta(db):
            asset_u = _make_ip_asset(db, ip_undetermined)
            asset_d = _make_ip_asset(db, ip_decided)

            old_enough = datetime.now(timezone.utc) - timedelta(hours=7)
            upsert_single_claim(
                db, asset_u.id, "tenancy_enricher", "tenancy",
                {"tenancy": te.UNDETERMINED, "decided_by_tier": None, "reason": "no_matching_prefix",
                 "provider": None, "service_raw": None, "service_class": None, "prefix": None,
                 "dataset_sha256": "old-sha", "dataset_generated_at": old_enough.isoformat()},
                old_enough,
            )
            not_stale_enough = datetime.now(timezone.utc) - timedelta(days=2)
            upsert_single_claim(
                db, asset_d.id, "tenancy_enricher", "tenancy",
                {"tenancy": te.SINGLE_TENANT, "decided_by_tier": 0, "reason": "provider_service_class_compute",
                 "provider": "aws", "service_raw": "EC2", "service_class": "compute", "prefix": "203.0.113.41/32",
                 "dataset_sha256": "old-sha", "dataset_generated_at": not_stale_enough.isoformat()},
                not_stale_enough,
            )
            db.commit()

            selected = te._select_assets_to_enrich(db, 200)
            selected_ids = {a.id for a in selected}
            assert asset_u.id in selected_ids, "an undetermined claim older than 6h must be selected for retry"
            assert asset_d.id not in selected_ids, "a decided claim only 2 days old must not be refreshed before 7d"
    finally:
        db.close()
        _cleanup(values)


# ── queue order ────────────────────────────────────────────────────────────

def test_queue_order_newly_discovered_first():
    ip_new = "203.0.113.50"
    ip_due_refresh = "203.0.113.51"
    values = [ip_new, ip_due_refresh]
    db = SessionLocal()
    try:
        asset_new = _make_ip_asset(db, ip_new)  # first_seen_at = now, no claim
        asset_old = _make_ip_asset(db, ip_due_refresh)
        stale = datetime.now(timezone.utc) - te.REFRESH_AFTER - timedelta(days=1)
        upsert_single_claim(
            db, asset_old.id, "tenancy_enricher", "tenancy",
            {"tenancy": te.SINGLE_TENANT, "decided_by_tier": 0, "reason": "provider_service_class_compute",
             "provider": "aws", "service_raw": "EC2", "service_class": "compute", "prefix": "203.0.113.51/32",
             "dataset_sha256": "old-sha", "dataset_generated_at": stale.isoformat()},
            stale,
        )
        db.commit()

        selected = te._select_assets_to_enrich(db, 1)
        assert len(selected) == 1
        assert selected[0].id == asset_new.id, "the never-enriched asset must come back before a due-for-refresh one"
    finally:
        db.close()
        _cleanup(values)


# ── no ownership field ────────────────────────────────────────────────────

def test_claim_value_carries_no_ownership_field():
    ip = "203.0.113.60"
    db = SessionLocal()
    try:
        with _seeded_meta(db):
            asset = _make_ip_asset(db, ip)
            _tick_isolated([ip])
            claim = get_current_claim(db, asset.id, "tenancy_enricher", "tenancy")
            assert claim is not None
            forbidden = {"owner", "confirmed_ours", "estate", "ours"}
            present = forbidden & set(claim.claim_value.keys())
            assert not present, (
                f"tenancy claim must never carry an ownership field (planning#178 separate-caps "
                f"constraint) — found: {present}"
            )
    finally:
        db.close()
        _cleanup([ip])


def _run():
    tests = [
        test_tenancy_for_match_mapping,
        test_tick_tri_state_end_to_end,
        test_unenriched_is_distinguishable_from_enriched_no_answer,
        test_no_dataset_writes_nothing,
        test_undetermined_retries_at_6h_decided_does_not_refresh_before_7d,
        test_queue_order_newly_discovered_first,
        test_claim_value_carries_no_ownership_field,
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
