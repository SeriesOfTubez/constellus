"""Executable acceptance criteria for epic planning#129 (asset claims
layer), verified end to end through planning#145's L4 query surface.

L0-L3 (planning#141-#144) built the grounding ontology, the current-claims
store, and the projector; this slice (#145) adds the query surface the
epic's own acceptance criteria read through. The epic promised four
properties the old shallow `asset_metadata` merge could not provide — this
file is the executable form of each one, kept runnable as one unit so a
future regression in any of them fails loudly and by name:

  1. Conflicting values from multiple observers are PRESERVED, not
     merged/clobbered (asset_claims' unique key is (asset, observer,
     claim_type), not (asset, claim_type)).
  2. Absence is queryable: "no claim of type T from observer O" is a real
     predicate, including the NOT-EXISTS case of an asset with zero claims
     of any kind.
  3. Change detection is precise: an unchanged re-observation only bumps
     `last_observed_at`; a changed value appends exactly one
     `claim_history` row.
  4. `asset_state.estate` derives a real tri-state (+ the query-layer
     `"unknown"`) from claims with observers and timestamps behind them —
     `proven_ours` / `claimed_ours` / `not_ours` / `unknown`, verified
     through `claims_query.surface()`.

Driven through the real ingest path — `write_assets()`, which calls
`claim_emitter.emit_claims()` then `projector.project()` synchronously in
the same transaction (`app/services/asset_writer.py` line ~69) — wherever
that path can produce the state under test. The two claim types with no
batch-path producer today (`cloud_inventory`, `affinity_confirmation`; both
are read-modify-write TTL caches written by a dedicated enrichment
service, not decomposed out of a DiscoveredAsset's metadata) are seeded via
`claim_emitter.upsert_single_claim` instead — the same real persistence
function `hosting_classifier` / `shared_infra_verifier` call, exercised
directly here the way `test_serializer_bridge.py` already does for
`hosting_class`.

Run with:  python -m app.tests.test_epic_129_verification
       or: pytest app/tests/test_epic_129_verification.py
"""

import uuid
from datetime import datetime, timezone

import time

from app.connectors.base import DiscoveredAsset
from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.claim import AssetClaim, ClaimHistory
from app.models.observer import Observer
from app.services import claims_query, projector
from app.services.asset_writer import write_assets
from app.services.claim_emitter import upsert_single_claim


# ── helpers ──────────────────────────────────────────────────────────────

def _observer_id(db, name: str) -> uuid.UUID:
    return db.query(Observer).filter(Observer.name == name).one().id


def _claims_for(db, canonical_id: uuid.UUID) -> list[AssetClaim]:
    return db.query(AssetClaim).filter(AssetClaim.asset_canonical_id == canonical_id).all()


def _history_count(db, canonical_id: uuid.UUID, observer_id: uuid.UUID, claim_type: str) -> int:
    return (
        db.query(ClaimHistory)
        .filter(
            ClaimHistory.asset_canonical_id == canonical_id,
            ClaimHistory.observer_id == observer_id,
            ClaimHistory.claim_type == claim_type,
        )
        .count()
    )


def _cleanup(values: list[str], observer_name: str | None = None) -> None:
    """Delete assets_canonical rows for `values` (cascades asset_claims +
    asset_state via FK), their claim_history (no FK, cleaned explicitly —
    same convention as test_claim_emission.py), then a throwaway Observer
    row if one was created — in that order, so the Observer delete never
    races a still-referencing asset_claims row."""
    db = SessionLocal()
    try:
        rows = db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).all()
        ids = [r.id for r in rows]
        if ids:
            db.query(ClaimHistory).filter(ClaimHistory.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).delete(synchronize_session=False)
        db.commit()
        if observer_name:
            db.query(Observer).filter(Observer.name == observer_name).delete(synchronize_session=False)
            db.commit()
    finally:
        db.close()


# ── 1. conflicting values from multiple observers are preserved ────────────

def test_conflicting_values_from_multiple_observers_are_preserved():
    """naabu and shodan each assert a different port list for the SAME IP,
    through the real ingest path. Before the claims layer, asset_writer's
    shallow JSONB merge was first-writer-wins on overlapping keys — one
    observer's view would silently clobber the other's. asset_claims'
    unique (asset, observer, claim_type) key means both survive as
    distinct rows with their own claim_value intact instead."""
    suffix = uuid.uuid4().hex[:10]
    ip = f"203.0.113.{10 + (int(suffix[:2], 16) % 60)}"
    db = SessionLocal()
    try:
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(
                asset_type="ip_address", value=ip,
                asset_metadata={
                    "sources": ["naabu"],
                    "open_ports": [{"port": 22, "protocol": "tcp", "sources": ["naabu"]}],
                },
            ),
        ])
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(
                asset_type="ip_address", value=ip,
                asset_metadata={
                    "sources": ["shodan"],
                    "open_ports": [{"port": 8080, "protocol": "tcp", "sources": ["shodan"]}],
                },
            ),
        ])

        row = db.query(AssetCanonical).filter(AssetCanonical.value == ip).one()
        port_claims = [c for c in _claims_for(db, row.id) if c.claim_type == "port_observation"]
        assert len(port_claims) == 2, f"expected 2 distinct port_observation rows, got {len(port_claims)}"

        by_observer = {c.observer_id: c.claim_value for c in port_claims}
        naabu_id = _observer_id(db, "naabu")
        shodan_id = _observer_id(db, "shodan")
        assert {p["port"] for p in by_observer[naabu_id]["ports"]} == {22}
        assert {p["port"] for p in by_observer[shodan_id]["ports"]} == {8080}
    finally:
        db.close()
        _cleanup([ip])


# ── 2. absence is queryable, including the zero-claims case ─────────────────

def test_absence_query_returns_assets_with_no_claim_from_observer():
    """Two ingested assets, only one carrying a claim from the chosen
    observer (naabu); a third with literally zero claims of any type. The
    absence query must return the unclaimed and zero-claim assets and
    exclude the naabu-claimed one — the NOT-EXISTS correctness case an
    anti-join gated on some other row existing would get wrong."""
    suffix = uuid.uuid4().hex[:10]
    ip_claimed = f"203.0.113.{70 + (int(suffix[:2], 16) % 30)}"
    ip_unclaimed = f"198.51.100.{10 + (int(suffix[2:4], 16) % 60)}"
    ip_zero_claims = f"198.51.100.{80 + (int(suffix[4:6], 16) % 60)}"
    db = SessionLocal()
    try:
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(
                asset_type="ip_address", value=ip_claimed,
                asset_metadata={
                    "sources": ["naabu"],
                    "open_ports": [{"port": 22, "protocol": "tcp", "sources": ["naabu"]}],
                },
            ),
        ])
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(
                asset_type="ip_address", value=ip_unclaimed,
                asset_metadata={"sources": ["shodan"], "shodan_org": "Example Hosting Co"},
            ),
        ])
        # Empty asset_metadata: emit_claims' own `if not meta: continue`
        # guard means this asset gets NO claims at all, of any type — the
        # canonical row is still created by the real ingest path, it just
        # carries zero asset_claims rows, which is exactly the case this
        # primitive must still catch.
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(asset_type="ip_address", value=ip_zero_claims, asset_metadata={}),
        ])

        claimed_row = db.query(AssetCanonical).filter(AssetCanonical.value == ip_claimed).one()
        unclaimed_row = db.query(AssetCanonical).filter(AssetCanonical.value == ip_unclaimed).one()
        zero_row = db.query(AssetCanonical).filter(AssetCanonical.value == ip_zero_claims).one()
        assert _claims_for(db, zero_row.id) == [], "sanity: the zero-claims row must carry no claims at all"

        results = claims_query.assets_missing_claim(
            db, "port_observation", observer_name="naabu", limit=1000,
        )
        result_ids = {a.id for a in results}

        assert claimed_row.id not in result_ids, "the naabu-claimed asset must be excluded"
        assert unclaimed_row.id in result_ids, "the shodan-only asset must be returned"
        assert zero_row.id in result_ids, "the zero-claims asset must be returned"
    finally:
        db.close()
        _cleanup([ip_claimed, ip_unclaimed, ip_zero_claims])


# ── 3. change detection: bump vs. append, by count ───────────────────────────

def test_reobservation_bumps_timestamp_without_history_and_change_writes_one_row():
    """Same value re-observed twice must advance last_observed_at without
    appending a claim_history row; a subsequently changed value must
    append EXACTLY one. Asserted on counts throughout, not truthiness —
    the property that broke before was rows being written 0 or 2+ times,
    not the value being merely present."""
    suffix = uuid.uuid4().hex[:10]
    value = f"epic129-reobs-{suffix}.example.com"
    ip = f"203.0.113.{140 + (int(suffix[:2], 16) % 60)}"
    db = SessionLocal()
    try:
        write_assets(db, uuid.uuid4(), [DiscoveredAsset(
            asset_type="dns_record", value=value, parent_value=None,
            asset_metadata={"sources": ["dns_records"], "record_type": "A", "content": ip, "ttl": 300},
        )])
        row = db.query(AssetCanonical).filter(AssetCanonical.value == value).one()
        dns_records_id = _observer_id(db, "dns_records")

        claim = db.query(AssetClaim).filter(
            AssetClaim.asset_canonical_id == row.id,
            AssetClaim.observer_id == dns_records_id,
            AssetClaim.claim_type == "dns_ttl",
        ).one()
        first_last_observed_at = claim.last_observed_at
        assert _history_count(db, row.id, dns_records_id, "dns_ttl") == 1

        # Re-observe the SAME value.
        time.sleep(0.05)
        write_assets(db, uuid.uuid4(), [DiscoveredAsset(
            asset_type="dns_record", value=value, parent_value=None,
            asset_metadata={"sources": ["dns_records"], "record_type": "A", "content": ip, "ttl": 300},
        )])
        db.expire_all()
        claim = db.query(AssetClaim).filter(
            AssetClaim.asset_canonical_id == row.id,
            AssetClaim.observer_id == dns_records_id,
            AssetClaim.claim_type == "dns_ttl",
        ).one()
        assert claim.last_observed_at > first_last_observed_at, "last_observed_at must advance"
        assert _history_count(db, row.id, dns_records_id, "dns_ttl") == 1, (
            "identical re-observation must not append a claim_history row"
        )

        # Now observe a CHANGED value.
        write_assets(db, uuid.uuid4(), [DiscoveredAsset(
            asset_type="dns_record", value=value, parent_value=None,
            asset_metadata={"sources": ["dns_records"], "record_type": "A", "content": ip, "ttl": 600},
        )])
        db.expire_all()
        claim = db.query(AssetClaim).filter(
            AssetClaim.asset_canonical_id == row.id,
            AssetClaim.observer_id == dns_records_id,
            AssetClaim.claim_type == "dns_ttl",
        ).one()
        assert claim.claim_value == {"ttl": 600}
        assert _history_count(db, row.id, dns_records_id, "dns_ttl") == 2, (
            "a changed value must append exactly one new claim_history row"
        )
    finally:
        db.close()
        _cleanup([value])


# ── 4. surface tri-state (+ unknown) ─────────────────────────────────────────

def test_surface_tri_state_for_proven_claimed_and_not_ours():
    """One asset per estate, asserted through `claims_query.surface()` —
    the crisp mechanical predicate the epic's estate derivation exists to
    support. Plus a fourth asset with no ownership signal at all, pinning
    the planning#145 settled decision that it reads as `"unknown"`, not
    `None` and not silently `"not_ours"`."""
    suffix = uuid.uuid4().hex[:10]
    ip_proven = f"203.0.113.{20 + (int(suffix[:2], 16) % 20)}"
    ip_claimed = f"203.0.113.{40 + (int(suffix[2:4], 16) % 20)}"
    ip_unknown = f"203.0.113.{60 + (int(suffix[4:6], 16) % 20)}"
    third_party_value = f"edge-{suffix}.vendor.invalid"
    all_values = [ip_proven, ip_claimed, ip_unknown, third_party_value]
    observer_name = f"test_cloud_inv_{uuid.uuid4().hex[:10]}"

    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)

        # -- proven_ours: a throwaway cloud_inventory observer (the real
        # observer arrives with planning#118 and must NOT be seeded before
        # then — test_claims_schema.py:81 pins its absence), confirmed True.
        db.add(Observer(
            id=uuid.uuid4(), name=observer_name, kind="connector", trust="observed",
            emits_traffic_to_target=False, addressing="none",
            description="planning#145 test-only throwaway cloud_inventory producer",
        ))
        db.commit()
        write_assets(db, uuid.uuid4(), [DiscoveredAsset(
            asset_type="ip_address", value=ip_proven,
            asset_metadata={
                "sources": ["naabu"],
                "open_ports": [{"port": 443, "protocol": "tcp", "sources": ["naabu"]}],
            },
        )])
        proven_row = db.query(AssetCanonical).filter(AssetCanonical.value == ip_proven).one()
        upsert_single_claim(
            db, proven_row.id, observer_name, "cloud_inventory",
            {"confirmed": True, "authorised_names": [ip_proven], "evidence_ref": "test-evidence-ref"},
            now,
        )
        projector.project(db, {proven_row.id}, now)
        db.commit()

        # -- claimed_ours: shared_infra_verifier's affinity_confirmation,
        # verdict=confirmed_ours (its own TTL-cache single-claim path, same
        # as hosting_class in test_serializer_bridge.py).
        write_assets(db, uuid.uuid4(), [DiscoveredAsset(
            asset_type="ip_address", value=ip_claimed,
            asset_metadata={
                "sources": ["naabu"],
                "open_ports": [{"port": 443, "protocol": "tcp", "sources": ["naabu"]}],
            },
        )])
        claimed_row = db.query(AssetCanonical).filter(AssetCanonical.value == ip_claimed).one()
        upsert_single_claim(
            db, claimed_row.id, "shared_infra_verifier", "affinity_confirmation",
            {"verdict": "confirmed_ours"}, now,
        )
        projector.project(db, {claimed_row.id}, now)
        db.commit()

        # -- not_ours: a captured third_party_dependency boundary target,
        # through the real ingest path (planning#147's accumulator).
        write_assets(db, uuid.uuid4(), [DiscoveredAsset(
            asset_type="dns_record", value=third_party_value, parent_value=None,
            asset_metadata={
                "sources": ["dns_resolve"], "record_type": "CNAME", "content": "origin.vendor.invalid",
                "third_party": True, "relationship": "dependency", "discovered_via": "cname",
            },
        )])
        not_ours_row = db.query(AssetCanonical).filter(AssetCanonical.value == third_party_value).one()

        # -- unknown: a real, claimed asset (naabu found a port) with NO
        # ownership signal at all — the decision this slice settles.
        write_assets(db, uuid.uuid4(), [DiscoveredAsset(
            asset_type="ip_address", value=ip_unknown,
            asset_metadata={
                "sources": ["naabu"],
                "open_ports": [{"port": 22, "protocol": "tcp", "sources": ["naabu"]}],
            },
        )])
        unknown_row = db.query(AssetCanonical).filter(AssetCanonical.value == ip_unknown).one()

        assert claims_query.surface(db, proven_row.id) == "proven_ours"
        assert claims_query.surface(db, claimed_row.id) == "claimed_ours"
        assert claims_query.surface(db, not_ours_row.id) == "not_ours"
        assert claims_query.surface(db, unknown_row.id) == "unknown"
    finally:
        db.close()
        _cleanup(all_values, observer_name=observer_name)


def _run():
    tests = [
        test_conflicting_values_from_multiple_observers_are_preserved,
        test_absence_query_returns_assets_with_no_claim_from_observer,
        test_reobservation_bumps_timestamp_without_history_and_change_writes_one_row,
        test_surface_tri_state_for_proven_claimed_and_not_ours,
    ]
    for fn in tests:
        fn()
        print(f"ok  {fn.__name__}")
    print("all passed")


if __name__ == "__main__":
    _run()
