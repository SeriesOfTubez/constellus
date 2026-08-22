"""Concurrency repro/regression for asset_writer / finding_writer
(planning#86).

Before this fix, _upsert_canonical_batch / _upsert_findings_canonical did
SELECT -> decide insert-vs-update in Python -> bulk_save_objects, with no
locking and no ON CONFLICT handling. Two concurrent scans racing to write
the same brand-new key could raise IntegrityError and abort the whole
batch's transaction; two concurrent writers racing to update the same
existing row could last-write-wins clobber each other's JSONB metadata.

This spins up two real threads, each with its own DB session (mirroring
two concurrent scan-run chunks), racing to write the SAME brand-new asset
and finding key with DIFFERENT metadata slices, then asserts: no exception
propagated, exactly one row exists, and the merged data reflects contributions
from BOTH threads (not last-write-wins).

Requires a live DB connection — this is an integration test, not a pure-unit
test like the rest of app/tests/. Run inside the backend container, where
DATABASE_URL is already configured.

Run with:  python -m app.tests.test_writer_concurrency        (from /app)
       or: pytest app/tests/test_writer_concurrency.py
"""

import threading
import uuid

from app.connectors.base import DiscoveredAsset, DiscoveredFinding
from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.finding_canonical import FindingCanonical
from app.services.asset_writer import write_assets
from app.services.finding_writer import write_findings


def _cleanup(value_prefix: str, fingerprint_prefix: str) -> None:
    db = SessionLocal()
    try:
        db.query(AssetCanonical).filter(AssetCanonical.value.like(f"{value_prefix}%")).delete(synchronize_session=False)
        db.query(FindingCanonical).filter(
            FindingCanonical.detail["fingerprint"].astext.like(f"{fingerprint_prefix}%")
        ).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def test_concurrent_new_asset_insert_merges_both_writes():
    """Two threads race to insert the SAME brand-new dns_record key with
    different open_ports slices. Neither should raise; the surviving row
    must carry both threads' ports (not just whichever committed last).

    planning#144 L3c-4: the ports are read from `asset_state.open_ports`
    (projected from each thread's port_observation claim) rather than the
    dropped asset_metadata column, and the two threads are attributed to
    DIFFERENT observers.

    That second change is not cosmetic. The claims layer is keyed
    (asset, observer, claim_type), so a port list is now per-observer and
    re-observation REPLACES it — two concurrent writes from the SAME
    observer are deliberately last-write-wins, because "naabu's current
    view of this asset's ports" is a single value and that is exactly what
    lets a closed port disappear. Cross-observer merge is the guarantee
    that actually matters here (and the realistic case: concurrent scans
    run different probers), so that is what this pins. The threads used to
    share a fake `sources: ["test"]` observer, which the claims path drops
    outright as unknown — a real seeded observer is required now.
    """
    suffix = uuid.uuid4().hex[:10]
    value = f"concurrency-asset-{suffix}.example.com"
    errors: list[Exception] = []

    def _write(observer: str, port: int):
        db = SessionLocal()
        try:
            write_assets(db, uuid.uuid4(), [
                DiscoveredAsset(
                    asset_type="dns_record", value=value, parent_value=None,
                    asset_metadata={
                        "sources": [observer],
                        "record_type": "A", "content": "203.0.113.10",
                        # No last_seen_at on purpose: the projector prunes
                        # ports older than the naabu claim's own
                        # last_observed_at, and any timestamp written here
                        # is stale relative to the `now` write_assets stamps
                        # afterwards. An entry with no timestamp is kept
                        # unconditionally, which keeps this test about
                        # concurrency rather than about pruning (same
                        # reasoning as test_serializer_bridge's seed).
                        "open_ports": [{"port": port, "sources": [observer]}],
                    },
                ),
            ])
        except Exception as exc:  # pragma: no cover - failure path under test
            errors.append(exc)
        finally:
            db.close()

    barrier = threading.Barrier(2)

    def _synced_write(observer: str, port: int):
        barrier.wait(timeout=5)
        _write(observer, port)

    t1 = threading.Thread(target=_synced_write, args=("naabu", 8080))
    t2 = threading.Thread(target=_synced_write, args=("tlsx", 8443))
    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)

    try:
        assert not errors, f"writer raised under concurrency: {errors}"

        db = SessionLocal()
        try:
            rows = db.query(AssetCanonical).filter(AssetCanonical.value == value).all()
            assert len(rows) == 1, f"expected exactly 1 row, got {len(rows)}"
            state = (
                db.query(AssetState)
                .filter(AssetState.asset_canonical_id == rows[0].id)
                .one_or_none()
            )
            assert state is not None, "expected a projected asset_state row"
            ports = {p["port"] for p in (state.open_ports or [])}
            assert ports == {8080, 8443}, f"expected both threads' ports merged, got {ports}"
        finally:
            db.close()
    finally:
        _cleanup(f"concurrency-asset-{suffix}", "__no_match__")


def test_concurrent_new_finding_insert_no_duplicate():
    """Two threads race to insert the SAME brand-new finding key (same
    asset/finding_type/source/fingerprint) with different severities.
    Neither should raise; exactly one row should survive."""
    suffix = uuid.uuid4().hex[:10]
    asset_value = f"concurrency-finding-host-{suffix}.example.com"
    fingerprint = f"concurrency-fp-{suffix}"
    errors: list[Exception] = []

    # Seed the asset first (outside the race) so both threads resolve to the
    # same asset_canonical_id.
    db = SessionLocal()
    try:
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(asset_type="dns_record", value=asset_value, parent_value=None,
                             asset_metadata={"record_type": "A", "content": "203.0.113.11"}),
        ])
    finally:
        db.close()

    def _write(severity: str):
        db = SessionLocal()
        try:
            write_findings(db, uuid.uuid4(), [
                DiscoveredFinding(
                    asset_value=asset_value, finding_type="exposure", source="test",
                    severity=severity, title="Concurrency test finding", description="d",
                    detail={"fingerprint": fingerprint},
                ),
            ])
        except Exception as exc:  # pragma: no cover - failure path under test
            errors.append(exc)
        finally:
            db.close()

    barrier = threading.Barrier(2)

    def _synced_write(severity: str):
        barrier.wait(timeout=5)
        _write(severity)

    t1 = threading.Thread(target=_synced_write, args=("high",))
    t2 = threading.Thread(target=_synced_write, args=("critical",))
    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)

    try:
        assert not errors, f"writer raised under concurrency: {errors}"

        db = SessionLocal()
        try:
            rows = db.query(FindingCanonical).filter(
                FindingCanonical.detail["fingerprint"].astext == fingerprint
            ).all()
            assert len(rows) == 1, f"expected exactly 1 finding row, got {len(rows)}"
            assert rows[0].severity in ("high", "critical")
        finally:
            db.close()
    finally:
        _cleanup(f"concurrency-finding-host-{suffix}", f"concurrency-fp-{suffix}")


def _run():
    tests = [
        test_concurrent_new_asset_insert_merges_both_writes,
        test_concurrent_new_finding_insert_no_duplicate,
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
