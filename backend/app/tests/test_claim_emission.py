"""Tests for claim emission from the batch writer (L2 sub-slice A,
planning#143).

Strangler-fig additive: write_assets() keeps authoring asset_metadata
exactly as before (the merge loop, _merge_open_ports, _prune_stale_ports
are untouched); claim_emitter.emit_claims() decomposes the same incoming
DiscoveredAsset batch into asset_claims rows in parallel, in the same
transaction. Nothing reads asset_claims yet — these tests assert on the
table directly.

Requires a live DB connection with migration 0039 applied — same style as
test_partition_maintenance.py / test_writer_concurrency.py.

Run with:  python -m app.tests.test_claim_emission
       or: pytest app/tests/test_claim_emission.py
"""

import time
import uuid
from datetime import datetime, timezone

from app.connectors.base import DiscoveredAsset
from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.claim import AssetClaim, ClaimHistory
from app.models.observer import Observer
from app.services.asset_writer import write_assets


def _observer_id(db, name: str) -> uuid.UUID:
    row = db.query(Observer).filter(Observer.name == name).one()
    return row.id


def _claims_for(db, canonical_id: uuid.UUID) -> list[AssetClaim]:
    return db.query(AssetClaim).filter(AssetClaim.asset_canonical_id == canonical_id).all()


def _history_for(db, canonical_id: uuid.UUID, observer_id: uuid.UUID, claim_type: str) -> list[ClaimHistory]:
    return (
        db.query(ClaimHistory)
        .filter(
            ClaimHistory.asset_canonical_id == canonical_id,
            ClaimHistory.observer_id == observer_id,
            ClaimHistory.claim_type == claim_type,
        )
        .all()
    )


def _cleanup(value_prefix: str) -> None:
    db = SessionLocal()
    try:
        rows = db.query(AssetCanonical).filter(AssetCanonical.value.like(f"{value_prefix}%")).all()
        ids = [r.id for r in rows]
        if ids:
            # claim_history has no FK (append-only log by design) — clean up
            # explicitly so re-runs of these tests start from a clean slate.
            db.query(ClaimHistory).filter(ClaimHistory.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.value.like(f"{value_prefix}%")).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def test_conflicting_values_from_two_observers_produce_two_claims():
    """Two different observers reporting a conflicting dns_ttl value for the
    same dns_record must land as two distinct asset_claims rows (unique key
    is (asset, observer, claim_type), not just (asset, claim_type))."""
    suffix = uuid.uuid4().hex[:10]
    value = f"claim-conflict-{suffix}.example.com"
    db = SessionLocal()
    try:
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(
                asset_type="dns_record", value=value, parent_value=None,
                asset_metadata={
                    "sources": ["cloudflare"], "record_type": "A", "content": "203.0.113.20",
                    "ttl": 300,
                },
            ),
            DiscoveredAsset(
                asset_type="dns_record", value=value, parent_value=None,
                asset_metadata={
                    "sources": ["dns_records"], "record_type": "A", "content": "203.0.113.20",
                    "ttl": 60,
                },
            ),
        ])

        row = db.query(AssetCanonical).filter(AssetCanonical.value == value).one()
        claims = _claims_for(db, row.id)
        ttl_claims = [c for c in claims if c.claim_type == "dns_ttl"]
        assert len(ttl_claims) == 2, f"expected 2 dns_ttl claims (one per observer), got {len(ttl_claims)}"

        by_observer = {c.observer_id: c.claim_value for c in ttl_claims}
        cloudflare_id = _observer_id(db, "cloudflare")
        dns_records_id = _observer_id(db, "dns_records")
        assert by_observer[cloudflare_id] == {"ttl": 300}
        assert by_observer[dns_records_id] == {"ttl": 60}
    finally:
        db.close()
        _cleanup(f"claim-conflict-{suffix}")


def test_reobserve_identical_value_advances_last_observed_no_new_history():
    """Re-observing the same claim_value must advance last_observed_at but
    NOT append a new claim_history row."""
    suffix = uuid.uuid4().hex[:10]
    value = f"claim-stable-{suffix}.example.com"
    db = SessionLocal()
    try:
        asset = DiscoveredAsset(
            asset_type="dns_record", value=value, parent_value=None,
            asset_metadata={"sources": ["cloudflare"], "record_type": "A", "content": "203.0.113.21", "ttl": 300},
        )
        write_assets(db, uuid.uuid4(), [asset])

        row = db.query(AssetCanonical).filter(AssetCanonical.value == value).one()
        cloudflare_id = _observer_id(db, "cloudflare")
        claim = db.query(AssetClaim).filter(
            AssetClaim.asset_canonical_id == row.id,
            AssetClaim.observer_id == cloudflare_id,
            AssetClaim.claim_type == "dns_ttl",
        ).one()
        first_observed_at = claim.first_observed_at
        first_last_observed_at = claim.last_observed_at
        history_count_before = len(_history_for(db, row.id, cloudflare_id, "dns_ttl"))
        assert history_count_before == 1

        time.sleep(0.05)
        write_assets(db, uuid.uuid4(), [DiscoveredAsset(
            asset_type="dns_record", value=value, parent_value=None,
            asset_metadata={"sources": ["cloudflare"], "record_type": "A", "content": "203.0.113.21", "ttl": 300},
        )])

        db.expire_all()
        claim = db.query(AssetClaim).filter(
            AssetClaim.asset_canonical_id == row.id,
            AssetClaim.observer_id == cloudflare_id,
            AssetClaim.claim_type == "dns_ttl",
        ).one()
        assert claim.first_observed_at == first_observed_at, "first_observed_at must not move"
        assert claim.last_observed_at > first_last_observed_at, "last_observed_at must advance"
        history_count_after = len(_history_for(db, row.id, cloudflare_id, "dns_ttl"))
        assert history_count_after == history_count_before == 1, "no new claim_history row on identical re-observation"
    finally:
        db.close()
        _cleanup(f"claim-stable-{suffix}")


def test_changed_value_appends_claim_history_row():
    """A changed claim_value must append a claim_history row (not just
    overwrite the current-value row)."""
    suffix = uuid.uuid4().hex[:10]
    value = f"claim-changed-{suffix}.example.com"
    db = SessionLocal()
    try:
        write_assets(db, uuid.uuid4(), [DiscoveredAsset(
            asset_type="dns_record", value=value, parent_value=None,
            asset_metadata={"sources": ["cloudflare"], "record_type": "A", "content": "203.0.113.22", "ttl": 300},
        )])
        row = db.query(AssetCanonical).filter(AssetCanonical.value == value).one()
        cloudflare_id = _observer_id(db, "cloudflare")
        assert len(_history_for(db, row.id, cloudflare_id, "dns_ttl")) == 1

        write_assets(db, uuid.uuid4(), [DiscoveredAsset(
            asset_type="dns_record", value=value, parent_value=None,
            asset_metadata={"sources": ["cloudflare"], "record_type": "A", "content": "203.0.113.22", "ttl": 600},
        )])

        db.expire_all()
        claim = db.query(AssetClaim).filter(
            AssetClaim.asset_canonical_id == row.id,
            AssetClaim.observer_id == cloudflare_id,
            AssetClaim.claim_type == "dns_ttl",
        ).one()
        assert claim.claim_value == {"ttl": 600}
        history = _history_for(db, row.id, cloudflare_id, "dns_ttl")
        assert len(history) == 2, f"expected 2 claim_history rows (initial + change), got {len(history)}"
        values = sorted(h.claim_value["ttl"] for h in history)
        assert values == [300, 600]
    finally:
        db.close()
        _cleanup(f"claim-changed-{suffix}")


def test_naabu_and_tlsx_produce_two_port_observation_claims():
    """naabu and tlsx patches for the same IP, in the same batch, must
    produce two distinct port_observation claims — one per observer,
    each carrying only that observer's ports."""
    suffix = uuid.uuid4().hex[:10]
    ip = f"203.0.113.{100 + (int(suffix[:2], 16) % 100)}"
    db = SessionLocal()
    try:
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(
                asset_type="ip_address", value=ip, parent_value=None,
                asset_metadata={
                    "sources": ["naabu"],
                    "open_ports": [{"port": 80, "protocol": "tcp", "sources": ["naabu"], "last_seen_at": "2026-08-19T00:00:00+00:00"}],
                    "naabu_last_scan_at": "2026-08-19T00:00:00+00:00",
                    "naabu_tier": "standard",
                },
            ),
            DiscoveredAsset(
                asset_type="ip_address", value=ip, parent_value=None,
                asset_metadata={
                    "sources": ["tlsx"],
                    "open_ports": [{"port": 443, "protocol": "tcp", "sources": ["tlsx"], "l7_confirmed": True}],
                },
            ),
        ])

        row = db.query(AssetCanonical).filter(AssetCanonical.value == ip).one()
        claims = [c for c in _claims_for(db, row.id) if c.claim_type == "port_observation"]
        assert len(claims) == 2, f"expected 2 port_observation claims, got {len(claims)}"

        naabu_id = _observer_id(db, "naabu")
        tlsx_id = _observer_id(db, "tlsx")
        by_observer = {c.observer_id: c for c in claims}

        naabu_claim = by_observer[naabu_id]
        assert [p["port"] for p in naabu_claim.claim_value["ports"]] == [80]
        assert "sources" not in naabu_claim.claim_value["ports"][0]
        assert naabu_claim.evidence.get("naabu_tier") == "standard"

        tlsx_claim = by_observer[tlsx_id]
        assert [p["port"] for p in tlsx_claim.claim_value["ports"]] == [443]
        assert tlsx_claim.claim_value["ports"][0].get("l7_confirmed") is True
    finally:
        db.close()
        _cleanup_ip(ip)


def _cleanup_ip(value: str) -> None:
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


def test_non_emitted_keys_produce_only_observation_claim():
    """Identity keys (record_type/content), derived keys (provider_mx) and
    path-2 keys (hosting_class) must NOT produce any Table-1 asset_claims
    rows — but the asset-level observer still resolves
    (sources=["dns_records"]), so the base-provenance `observation` claim
    (L3c-2a, planning#144) IS emitted, carrying an empty claim_value.

    `cdn_domain` is here for a sharper reason since L3c-3 made cdn a claim:
    a bare `cdn_domain` with no `cdn` flag is NOT a boundary judgment and
    must still emit nothing. `_accumulate_cdn_claim` keys off `cdn` alone
    for exactly this case."""
    suffix = uuid.uuid4().hex[:10]
    value = f"claim-nonemit-{suffix}.example.com"
    db = SessionLocal()
    try:
        write_assets(db, uuid.uuid4(), [DiscoveredAsset(
            asset_type="dns_record", value=value, parent_value=None,
            asset_metadata={
                "sources": ["dns_records"],
                "record_type": "MX",
                "content": "mail.example.com",
                "provider_mx": True,
                "cdn_domain": "cdn.example.net",
                "hosting_class": {"is_datacenter": True, "provider": "example-cloud"},
                "resolved_ips": ["203.0.113.23"],
            },
        )])

        row = db.query(AssetCanonical).filter(AssetCanonical.value == value).one()
        claims = _claims_for(db, row.id)
        claim_types = {c.claim_type for c in claims}
        assert claim_types == {"observation"}, (
            f"expected only the observation claim for non-emitted keys, got {[(c.claim_type, c.claim_value) for c in claims]}"
        )
        assert claims[0].claim_value == {}
        # And the (skipped-in-this-slice) mx_preference field wasn't set, so
        # no mx_preference claim either.
        assert not any(c.claim_type == "mx_preference" for c in claims)
    finally:
        db.close()
        _cleanup(f"claim-nonemit-{suffix}")


def test_cdn_boundary_claim_emitted_for_cdn_annotated_cname():
    """planning#144 L3c-3: dns_resolve's CDN-boundary judgment on a CNAME hop
    it declined to follow becomes a `cdn_boundary` claim, so it survives the
    L3c-4 asset_metadata drop. Before this it reached readers only via the
    persisted column, which the projector mirrored back out as a stopgap —
    a passthrough with no source once that column is gone."""
    suffix = uuid.uuid4().hex[:10]
    value = f"claim-cdn-{suffix}.example.com"
    db = SessionLocal()
    try:
        write_assets(db, uuid.uuid4(), [DiscoveredAsset(
            asset_type="dns_record", value=value, parent_value=None,
            asset_metadata={
                "sources": ["dns_resolve"],
                "record_type": "CNAME",
                "content": "d111.cloudfront.net",
                "cdn": True,
                "cdn_domain": "cloudfront.net",
            },
        )])

        row = db.query(AssetCanonical).filter(AssetCanonical.value == value).one()
        claims = {c.claim_type: c for c in _claims_for(db, row.id)}
        assert "cdn_boundary" in claims, sorted(claims)
        assert claims["cdn_boundary"].claim_value == {
            "cdn": True, "cdn_domain": "cloudfront.net",
        }, claims["cdn_boundary"].claim_value

        # And it projects onto asset_state.attributes, which is what
        # dangling_dns_analyzer's CDN exclusion reads.
        from app.models.asset_state import AssetState
        from app.services import projector
        projector.project(db, {row.id}, datetime.now(timezone.utc))
        db.commit()
        state = db.query(AssetState).filter(AssetState.asset_canonical_id == row.id).one()
        assert state.attributes.get("cdn") is True, state.attributes
        assert state.attributes.get("cdn_domain") == "cloudfront.net", state.attributes
    finally:
        db.close()
        _cleanup(f"claim-cdn-{suffix}")


def test_identity_only_dns_record_emits_observation_claim():
    """The common dns_resolve/dns_records shape for a plain A/AAAA/CNAME
    hop — asset_metadata carrying ONLY {sources, record_type, content},
    nothing else — used to emit NO claim at all, so that observer vanished
    from the L3c-2 serializer bridge's reconstructed `sources` (see
    test_serializer_bridge.py). It must now emit exactly one `observation`
    claim attributed to dns_resolve, with an empty claim_value."""
    suffix = uuid.uuid4().hex[:10]
    value = f"claim-identity-only-{suffix}.example.com"
    db = SessionLocal()
    try:
        write_assets(db, uuid.uuid4(), [DiscoveredAsset(
            asset_type="dns_record", value=value, parent_value=None,
            asset_metadata={
                "sources": ["dns_resolve"],
                "record_type": "A",
                "content": "203.0.113.30",
            },
        )])

        row = db.query(AssetCanonical).filter(AssetCanonical.value == value).one()
        claims = _claims_for(db, row.id)
        assert len(claims) == 1, f"expected exactly 1 claim (observation), got {[(c.claim_type, c.claim_value) for c in claims]}"
        assert claims[0].claim_type == "observation"
        assert claims[0].claim_value == {}
        dns_resolve_id = _observer_id(db, "dns_resolve")
        assert claims[0].observer_id == dns_resolve_id
    finally:
        db.close()
        _cleanup(f"claim-identity-only-{suffix}")


def test_explicit_observer_field_overrides_sources_fallback():
    """DiscoveredAsset.observer, when set, takes priority over the
    single-entry `sources` fallback for observer resolution."""
    suffix = uuid.uuid4().hex[:10]
    value = f"claim-explicit-observer-{suffix}.example.com"
    db = SessionLocal()
    try:
        write_assets(db, uuid.uuid4(), [DiscoveredAsset(
            asset_type="dns_record", value=value, parent_value=None,
            asset_metadata={"sources": ["cloudflare"], "record_type": "A", "content": "203.0.113.24", "ttl": 120},
            observer="dns_records",
        )])

        row = db.query(AssetCanonical).filter(AssetCanonical.value == value).one()
        dns_records_id = _observer_id(db, "dns_records")
        claim = db.query(AssetClaim).filter(
            AssetClaim.asset_canonical_id == row.id,
            AssetClaim.claim_type == "dns_ttl",
        ).one()
        assert claim.observer_id == dns_records_id, "explicit .observer must win over sources fallback"
    finally:
        db.close()
        _cleanup(f"claim-explicit-observer-{suffix}")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
