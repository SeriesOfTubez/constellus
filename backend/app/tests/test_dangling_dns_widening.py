"""Integration tests for dangling_dns_analyzer's target-scope widening and
cadence/budget gate — planning#114, epic#81 Phase D follow-up L2.

Two layers, per the issue's own test plan:
  - Gate-computation tests call `_compute_gate_open_ids` directly against a
    real DB session with minimal real `dns_record` rows (`_syn_record` below)
    — needed for its "has an open finding" subquery, and (planning#144
    L3b-3) for `asset_state`'s FK when seeding a `dangling_probe_at` stamp.
  - End-to-end tests call `analyze_dangling_dns` itself against real
    dns_record/ip_address assets + real findings (write_assets/write_findings),
    with domain_affinity/origin_corroboration/takeover_fingerprint
    monkeypatched — mirrors test_ownership_stamping.py's pattern.

Run with:  python -m app.tests.test_dangling_dns_widening
       or: pytest app/tests/test_dangling_dns_widening.py
"""

import uuid
from datetime import datetime, timedelta, timezone

from app.connectors.base import DiscoveredAsset, DiscoveredFinding
from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.finding_canonical import FindingCanonical
from app.models.target import Target, TargetType
from app.services import dangling_dns_analyzer as dda
from app.services import domain_affinity as da
from app.services import origin_corroboration as oc
from app.services import projector
from app.services import takeover_fingerprint as tf
from app.services.asset_writer import write_assets
from app.services.finding_writer import write_findings


def _syn_record(db, *, cdn: str | None = None) -> AssetCanonical:
    """A real, minimal dns_record AssetCanonical row (not a bare
    SimpleNamespace, as this predated planning#144 L3b-3) — `_stamp` below
    needs `asset_state`'s FK to a real `assets_canonical` row to seed a
    `dangling_probe_at` stamp against.

    planning#144 L3c-3: `cdn` is seeded onto `asset_state.attributes` (where
    the projector now puts it, sourced from dns_resolve's `cdn_boundary`
    claim) rather than onto `asset_metadata`, which the analyzer no longer
    reads. Same route as `_stamp`."""
    now = datetime.now(timezone.utc)
    row = AssetCanonical(
        id=uuid.uuid4(), asset_type="dns_record", value=f"syn-{uuid.uuid4().hex[:8]}.example.com",
        parent_value=None, first_seen_at=now, last_seen_at=now,
        record_type="A", content="203.0.113.9",
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    if cdn:
        projector.merge_state_attributes(db, row.id, {"cdn": True, "cdn_domain": cdn})
        db.commit()
    return row


def _stamp(db, record_id: uuid.UUID, stamp: str) -> None:
    """Seed asset_state.attributes.dangling_probe_at directly to a specific
    (possibly stale) value — planning#144 L3b-3 moved the stamp off
    asset_metadata onto asset_state, written via projector.merge_state_attributes."""
    projector.merge_state_attributes(db, record_id, {"dangling_probe_at": stamp})
    db.commit()


def _probe_stamp(db, record_id: uuid.UUID) -> str | None:
    state = db.query(AssetState).filter(AssetState.asset_canonical_id == record_id).one_or_none()
    return (state.attributes or {}).get("dangling_probe_at") if state else None


def _cleanup(db, *, domains: list[str] = (), values: list[str] = (), target_ids: list = ()):
    all_values = list(domains) + list(values)
    if all_values:
        db.query(FindingCanonical).filter(
            FindingCanonical.asset_canonical_id.in_(
                db.query(AssetCanonical.id).filter(AssetCanonical.value.in_(all_values))
            )
        ).delete(synchronize_session=False)
        # asset_state cascades (ON DELETE CASCADE on asset_canonical_id) — no
        # separate cleanup needed for the dangling_probe_at stamps seeded above.
        db.query(AssetCanonical).filter(AssetCanonical.value.in_(all_values)).delete(synchronize_session=False)
    if target_ids:
        db.query(Target).filter(Target.id.in_(target_ids)).delete(synchronize_session=False)
    db.commit()


# ── Gate computation ────────────────────────────────────────────────────────

def test_touched_record_gate_open_regardless_of_stamp():
    db = SessionLocal()
    try:
        record = _syn_record(db)
        _stamp(db, record.id, datetime.now(timezone.utc).isoformat())
        ids = dda._compute_gate_open_ids(db, [record], touched_asset_ids={record.id})
        assert record.id in ids
    finally:
        _cleanup(db, values=[record.value])
        db.close()


def test_cdn_scope_only_record_never_gate_open():
    """Regression #2: a CDN-annotated scope-only record with no open
    finding must never enter the due-candidate pool, regardless of stamp."""
    db = SessionLocal()
    try:
        record = _syn_record(db, cdn="cloudfront.net")
        ids = dda._compute_gate_open_ids(db, [record], touched_asset_ids=set())
        assert record.id not in ids
    finally:
        _cleanup(db, values=[record.value])
        db.close()


def test_scope_only_fresh_stamp_not_due():
    db = SessionLocal()
    try:
        record = _syn_record(db)
        _stamp(db, record.id, datetime.now(timezone.utc).isoformat())
        ids = dda._compute_gate_open_ids(db, [record], touched_asset_ids=set())
        assert record.id not in ids
    finally:
        _cleanup(db, values=[record.value])
        db.close()


def test_scope_only_stale_or_missing_stamp_is_due():
    db = SessionLocal()
    try:
        stale = (datetime.now(timezone.utc) - timedelta(days=_days_past_ttl())).isoformat()
        stale_record = _syn_record(db)
        _stamp(db, stale_record.id, stale)
        never_stamped = _syn_record(db)
        ids = dda._compute_gate_open_ids(db, [stale_record, never_stamped], touched_asset_ids=set())
        assert stale_record.id in ids
        assert never_stamped.id in ids
    finally:
        _cleanup(db, values=[stale_record.value, never_stamped.value])
        db.close()


def _days_past_ttl() -> int:
    return dda._DANGLING_PROBE_TTL_DAYS + 1


def test_budget_caps_scope_only_probes_oldest_stamped_first():
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        budget = dda._DANGLING_PROBE_BUDGET
        # budget + 3 candidates, all past TTL, each stamped one minute apart —
        # the 3 NEWEST (least stale) must lose out to the budget cap.
        records = [_syn_record(db) for _ in range(budget + 3)]
        for i, record in enumerate(records):
            stamp = (now - timedelta(days=_days_past_ttl(), minutes=i)).isoformat()
            _stamp(db, record.id, stamp)
        # records[0] has the smallest `minutes` subtracted -> newest of the stale set;
        # records[-1] has the largest -> oldest. Oldest-first means records[-1..] win.
        ids = dda._compute_gate_open_ids(db, records, touched_asset_ids=set())
        assert len(ids) == budget
        oldest = records[3:]  # the budget-many oldest-stamped records
        newest = records[:3]  # the 3 that should lose to the cap
        assert all(r.id in ids for r in oldest)
        assert all(r.id not in ids for r in newest)
    finally:
        _cleanup(db, values=[r.value for r in records])
        db.close()


def test_open_finding_bypasses_gate_regardless_of_fresh_stamp():
    suffix = uuid.uuid4().hex[:8]
    value = f"open-finding-{suffix}.example.com"
    db = SessionLocal()
    try:
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(asset_type="dns_record", value=value, parent_value=None,
                             asset_metadata={"record_type": "A", "content": "203.0.113.20"}),
        ])
        asset = db.query(AssetCanonical).filter(AssetCanonical.value == value).one()
        # Very fresh stamp — would normally NOT be due — but an open finding
        # must bypass the gate unconditionally regardless.
        _stamp(db, asset.id, datetime.now(timezone.utc).isoformat())

        write_findings(db, uuid.uuid4(), [
            DiscoveredFinding(
                asset_value=value, asset_id=asset.id, finding_type="dangling_dns", source="constellus",
                severity="medium", title="t", description="d", detail={"fingerprint": "dangling-dns"},
            ),
        ])

        ids = dda._compute_gate_open_ids(db, [asset], touched_asset_ids=set())
        assert asset.id in ids
    finally:
        _cleanup(db, values=[value])
        db.close()


# ── End-to-end analyze_dangling_dns ─────────────────────────────────────────

def test_scope_only_record_gets_probed_and_stamped_with_no_touched_assets():
    """The whole reason planning#114 exists: a domain target's dns_record
    that no connector touched this run must still get evaluated via scope,
    not silently skipped the way touched-only selection would leave it."""
    suffix = uuid.uuid4().hex[:8]
    domain = f"widen-{suffix}.example.com"
    da.resolve_origin = lambda db, record: "203.0.113.30"
    da.check_affinity = lambda hostname, origin_ip, apexes, ports=None: da.AffinityResult(
        hostname=hostname, origin_ip=origin_ip, verdict=da.VERDICT_AFFINE, signals=[], matrix={"443": {}},
    )
    tf.find_takeover_signal = lambda db, asset_id, since: None

    db = SessionLocal()
    target_ids: list = []
    try:
        target = Target(id=uuid.uuid4(), type=TargetType.DOMAIN, value=domain, verified=True)
        db.add(target)
        db.commit()
        target_ids.append(target.id)

        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(asset_type="dns_record", value=domain, parent_value=None,
                             asset_metadata={"record_type": "A", "content": "203.0.113.30"}),
        ])
        asset = db.query(AssetCanonical).filter(AssetCanonical.value == domain).one()
        assert _probe_stamp(db, asset.id) is None

        dda.analyze_dangling_dns(
            db, uuid.uuid4(), {"domains": [domain], "ip_ranges": []}, set(),
            since=datetime.now(timezone.utc) - timedelta(minutes=1),
        )

        db.refresh(asset)
        assert _probe_stamp(db, asset.id) is not None, (
            "planning#114: a scope-only, never-touched record must still get "
            "probed and stamped via target_scope, not silently skipped"
        )
    finally:
        _cleanup(db, domains=[domain], target_ids=target_ids)
        db.close()


def test_worker_down_does_not_resolve_backdated_open_finding():
    """Regression #1, end-to-end: an empty probe matrix (scanner-worker
    unreachable) must not resolve an open finding just because it's past
    the grace window — the record was never actually judged clean."""
    suffix = uuid.uuid4().hex[:8]
    value = f"worker-down-{suffix}.example.com"
    da.resolve_origin = lambda db, record: "203.0.113.40"
    da.check_affinity = lambda hostname, origin_ip, apexes, ports=None: da.AffinityResult(
        hostname=hostname, origin_ip=origin_ip, verdict=da.VERDICT_INDETERMINATE, signals=[], matrix={},
    )
    tf.find_takeover_signal = lambda db, asset_id, since: None

    db = SessionLocal()
    try:
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(asset_type="dns_record", value=value, parent_value=None,
                             asset_metadata={"record_type": "A", "content": "203.0.113.40"}),
        ])
        asset = db.query(AssetCanonical).filter(AssetCanonical.value == value).one()

        write_findings(db, uuid.uuid4(), [
            DiscoveredFinding(
                asset_value=value, asset_id=asset.id, finding_type="dangling_dns", source="constellus",
                severity="medium", title="t", description="d", detail={"fingerprint": "dangling-dns"},
            ),
        ])
        finding = db.query(FindingCanonical).filter(FindingCanonical.asset_canonical_id == asset.id).one()
        finding.last_seen_at = datetime.now(timezone.utc) - timedelta(days=dda._DANGLING_GRACE_DAYS + 1)
        db.commit()

        dda.analyze_dangling_dns(
            db, uuid.uuid4(), {"domains": [], "ip_ranges": []}, {asset.id},
            since=datetime.now(timezone.utc) - timedelta(minutes=1),
        )

        db.refresh(finding)
        db.refresh(asset)
        assert finding.state == "open", "an empty probe matrix must never resolve an open finding"
        assert _probe_stamp(db, asset.id) is None, (
            "an empty matrix produced no evidence — must not be stamped as probed"
        )
    finally:
        _cleanup(db, values=[value])
        db.close()


def test_per_record_exception_is_caught_and_does_not_abort_the_batch():
    """One record's evaluation raising must not prevent the rest of the
    batch from being processed (planning#114 fail-soft requirement)."""
    suffix = uuid.uuid4().hex[:8]
    bad_value = f"raises-{suffix}.example.com"
    good_value = f"good-{suffix}.example.com"

    def _resolve_origin(db, record):
        if record.value == bad_value:
            raise RuntimeError("simulated failure")
        return "203.0.113.50"

    da.resolve_origin = _resolve_origin
    da.check_affinity = lambda hostname, origin_ip, apexes, ports=None: da.AffinityResult(
        hostname=hostname, origin_ip=origin_ip, verdict=da.VERDICT_AFFINE, signals=[], matrix={"443": {}},
    )
    tf.find_takeover_signal = lambda db, asset_id, since: None

    db = SessionLocal()
    try:
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(asset_type="dns_record", value=bad_value, parent_value=None,
                             asset_metadata={"record_type": "A", "content": "203.0.113.51"}),
            DiscoveredAsset(asset_type="dns_record", value=good_value, parent_value=None,
                             asset_metadata={"record_type": "A", "content": "203.0.113.50"}),
        ])
        bad_asset = db.query(AssetCanonical).filter(AssetCanonical.value == bad_value).one()
        good_asset = db.query(AssetCanonical).filter(AssetCanonical.value == good_value).one()

        dda.analyze_dangling_dns(
            db, uuid.uuid4(), {"domains": [], "ip_ranges": []}, {bad_asset.id, good_asset.id},
            since=datetime.now(timezone.utc) - timedelta(minutes=1),
        )

        db.refresh(good_asset)
        assert _probe_stamp(db, good_asset.id) is not None, (
            "the good record must still be evaluated despite the bad record raising"
        )
    finally:
        _cleanup(db, values=[bad_value, good_value])
        db.close()


def _run():
    tests = [
        test_touched_record_gate_open_regardless_of_stamp,
        test_cdn_scope_only_record_never_gate_open,
        test_scope_only_fresh_stamp_not_due,
        test_scope_only_stale_or_missing_stamp_is_due,
        test_budget_caps_scope_only_probes_oldest_stamped_first,
        test_open_finding_bypasses_gate_regardless_of_fresh_stamp,
        test_scope_only_record_gets_probed_and_stamped_with_no_touched_assets,
        test_worker_down_does_not_resolve_backdated_open_finding,
        test_per_record_exception_is_caught_and_does_not_abort_the_batch,
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
