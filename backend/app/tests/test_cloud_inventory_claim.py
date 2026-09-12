"""End-to-end tests for the cloud_inventory claim (planning#118a).

`cloud_inventory` has been a seeded claim type since migration 0039, and the
projector has promoted it to `estate = "proven_ours"` since planning#145 L4.
Until this slice it had NO producer — these tests walk the whole path the
Wiz connector now opens: DiscoveredAsset -> claim_emitter -> asset_claims ->
projector -> asset_state.estate.

Requires a live DB with migration 0048 applied (the `wiz` observer seed) —
same style as test_claim_emission.py.

Run with:  python -m app.tests.test_cloud_inventory_claim
       or: pytest app/tests/test_cloud_inventory_claim.py
"""

import uuid
from datetime import datetime, timezone

from app.connectors.base import DiscoveredAsset
from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.claim import AssetClaim, ClaimHistory
from app.models.observer import Observer
from app.services import projector
from app.services.asset_writer import write_assets

# Documentation range only (RFC-5737) — no real address in a tracked file.
_IP_PREFIX = "192.0.2."


def _claims_for(db, canonical_id):
    return db.query(AssetClaim).filter(AssetClaim.asset_canonical_id == canonical_id).all()


def _cleanup(value: str) -> None:
    db = SessionLocal()
    try:
        rows = db.query(AssetCanonical).filter(AssetCanonical.value == value).all()
        ids = [r.id for r in rows]
        if ids:
            db.query(ClaimHistory).filter(ClaimHistory.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
            db.query(AssetState).filter(AssetState.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
            db.query(AssetClaim).filter(AssetClaim.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.value == value).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _claim_payload(**overrides):
    payload = {
        "confirmed": True,
        "authorised_names": [],
        "resource_count": 1,
        "resources": [{"id": "res-a", "name": "example-lb", "type": "WEB_SERVICE"}],
        "exposure_count": 2,
        "evidence_ref": ["exp-1", "exp-2"],
    }
    payload.update(overrides)
    return payload


def _write(db, ip: str, payload):
    meta = {"sources": ["wiz"]}
    if payload is not None:
        meta["cloud_inventory"] = payload
    write_assets(db, uuid.uuid4(), [DiscoveredAsset(
        asset_type="ip_address", value=ip, parent_value=None,
        observer="wiz", asset_metadata=meta,
    )])
    return db.query(AssetCanonical).filter(AssetCanonical.value == ip).one()


def test_wiz_observer_is_seeded_with_the_intended_taxonomy():
    """Migration 0048. The values are load-bearing, not cosmetic: `observed`
    (not `inferred`) is what makes this a credentialed source rather than a
    third-party guess, and `addressing = "none"` is what stops the
    probe-authorisation gate treating Wiz as a prober."""
    db = SessionLocal()
    try:
        row = db.query(Observer).filter(Observer.name == "wiz").one()
        assert row.kind == "connector"
        assert row.trust == "observed"
        assert row.emits_traffic_to_target is False
        assert row.addressing == "none"
    finally:
        db.close()


def test_confirmed_payload_becomes_a_claim_and_projects_to_proven_ours():
    """The whole point of the slice: a credentialed ownership claim reaches
    `estate = "proven_ours"`, which had no producer before."""
    ip = f"{_IP_PREFIX}{uuid.uuid4().int % 200 + 10}"
    db = SessionLocal()
    try:
        row = _write(db, ip, _claim_payload())
        claims = {c.claim_type: c for c in _claims_for(db, row.id)}
        assert "cloud_inventory" in claims, sorted(claims)

        claim = claims["cloud_inventory"]
        assert claim.claim_value["confirmed"] is True
        assert claim.claim_value["authorised_names"] == []
        assert claim.claim_value["resources"][0]["id"] == "res-a"

        observer = db.query(Observer).filter(Observer.id == claim.observer_id).one()
        assert observer.name == "wiz"

        projector.project(db, {row.id}, datetime.now(timezone.utc))
        db.commit()
        state = db.query(AssetState).filter(AssetState.asset_canonical_id == row.id).one()
        assert state.estate == "proven_ours", state.estate
    finally:
        db.close()
        _cleanup(ip)


def test_evidence_is_split_out_so_churn_is_not_an_ownership_change():
    """Exposure ids and their count live in the evidence column, not in
    claim_value. A firewall rule added or removed changes both while the
    answer to "is this address ours" does not — left inline, the emitter's
    JSON-equality check would read that as a value change and append a
    claim_history row saying ownership changed."""
    ip = f"{_IP_PREFIX}{uuid.uuid4().int % 200 + 10}"
    db = SessionLocal()
    try:
        row = _write(db, ip, _claim_payload())
        claim = {c.claim_type: c for c in _claims_for(db, row.id)}["cloud_inventory"]
        assert "evidence_ref" not in claim.claim_value, claim.claim_value
        assert "exposure_count" not in claim.claim_value, claim.claim_value
        assert claim.evidence["evidence_ref"] == ["exp-1", "exp-2"]
        assert claim.evidence["exposure_count"] == 2

        history_before = db.query(ClaimHistory).filter(
            ClaimHistory.asset_canonical_id == row.id,
            ClaimHistory.claim_type == "cloud_inventory",
        ).count()

        # Same ownership, different exposure evidence.
        _write(db, ip, _claim_payload(exposure_count=5, evidence_ref=["exp-9"]))
        history_after = db.query(ClaimHistory).filter(
            ClaimHistory.asset_canonical_id == row.id,
            ClaimHistory.claim_type == "cloud_inventory",
        ).count()
        assert history_after == history_before, "evidence churn must not append history"
    finally:
        db.close()
        _cleanup(ip)


def test_a_genuine_ownership_change_does_append_history():
    """The counterpart to the test above — evidence churn is filtered out,
    but a real change in what Wiz says owns the address is not."""
    ip = f"{_IP_PREFIX}{uuid.uuid4().int % 200 + 10}"
    db = SessionLocal()
    try:
        row = _write(db, ip, _claim_payload())
        before = db.query(ClaimHistory).filter(
            ClaimHistory.asset_canonical_id == row.id,
            ClaimHistory.claim_type == "cloud_inventory",
        ).count()

        _write(db, ip, _claim_payload(
            resources=[{"id": "res-b", "name": "other-lb", "type": "VIRTUAL_MACHINE"}],
        ))
        after = db.query(ClaimHistory).filter(
            ClaimHistory.asset_canonical_id == row.id,
            ClaimHistory.claim_type == "cloud_inventory",
        ).count()
        assert after == before + 1
    finally:
        db.close()
        _cleanup(ip)


def test_unconfirmed_payload_writes_no_claim_at_all():
    """`confirmed: False` must not become a row. cloud_inventory promotes to
    proven_ours, outranking every other estate rule, so only an affirmative
    yes may be recorded — and "Wiz has not heard of this address" is not
    evidence the address is not ours. The absence layer (planning#145)
    represents that, by the claim's absence."""
    ip = f"{_IP_PREFIX}{uuid.uuid4().int % 200 + 10}"
    db = SessionLocal()
    try:
        row = _write(db, ip, _claim_payload(confirmed=False))
        claim_types = {c.claim_type for c in _claims_for(db, row.id)}
        assert "cloud_inventory" not in claim_types, claim_types
        # The base-provenance claim still lands — we did observe the asset.
        assert "observation" in claim_types, claim_types
    finally:
        db.close()
        _cleanup(ip)


def test_truthy_but_non_true_confirmed_is_rejected():
    """`is not True`, not `not truthy`. A producer sending the string "yes"
    or a non-empty dict must not clear a bar this high by accident."""
    for bogus in ["yes", 1, {"ok": True}, [1]]:
        ip = f"{_IP_PREFIX}{uuid.uuid4().int % 200 + 10}"
        db = SessionLocal()
        try:
            row = _write(db, ip, _claim_payload(confirmed=bogus))
            claim_types = {c.claim_type for c in _claims_for(db, row.id)}
            assert "cloud_inventory" not in claim_types, (bogus, claim_types)
        finally:
            db.close()
            _cleanup(ip)


def test_non_dict_payload_is_ignored_without_raising():
    ip = f"{_IP_PREFIX}{uuid.uuid4().int % 200 + 10}"
    db = SessionLocal()
    try:
        row = _write(db, ip, "confirmed")
        claim_types = {c.claim_type for c in _claims_for(db, row.id)}
        assert "cloud_inventory" not in claim_types, claim_types
    finally:
        db.close()
        _cleanup(ip)


if __name__ == "__main__":
    for name, fn in sorted(list(globals().items())):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
    print("all cloud_inventory claim tests passed")
