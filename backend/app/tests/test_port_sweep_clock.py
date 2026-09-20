"""Regression tests for planning#190 — the staleness cutoff must be the
naabu SWEEP's clock, not the claim's write clock.

`asset_state.open_ports` was `[]` for every naabu-discovered port,
permanently. `_prune_stale_ports` keeps a port only if
`port.last_seen_at >= cutoff`, and the cutoff was the `port_observation`
claim's `last_observed_at` — which `asset_writer.write_assets()` stamps
*after* the connector has returned. Two clocks, and the order between them
is guaranteed, not racy: the cutoff is ALWAYS strictly later than every port
it is compared against, so every freshly observed port was deleted on the
very projection that first recorded it. Measured at 370µs and 619µs on the
dev DB; only the magnitude ever varies, never the sign.

## Why no existing test caught it — every one of them used a single clock

* `test_prune_stale_ports.py` seeded a port half an hour AFTER the cutoff.
* `test_projector.py` used the same `now` object for the claim's
  `last_observed_at` and the port's `last_seen_at`, so `>=` passed by
  equality.

Both orderings are ones the pipeline cannot produce. So the tests below are
built around one rule: **`sweep` strictly precedes `written`**, and every
patch is emitted at `written` while its ports and `naabu_last_scan_at` carry
`sweep`. That is the only ordering production has ever produced, and it is
the one no test covered.

## Mutation proof

Revert `projector.py`'s `naabu_swept_at = _normalized_swept_at(...)` to
`naabu_swept_at = last_observed_at.isoformat()` and
`test_fresh_ports_survive_the_projection_that_records_them` fails, because
the cutoff becomes `written` and the ports are stamped `sweep`. A test that
passes against both spellings is testing the wrong thing, which is how this
shipped in the first place.

## What these tests do NOT cover — planning#175

A naabu sweep that finds ZERO ports emits no `port_observation` claim at all
(`claim_emitter._accumulate_port_observation` skips empty groups), so the
prune never runs and a phantom is never retired. That is #175, it lives one
layer up in the emitter, and it is still open. Nothing here asserts it.

Run with:  python -m app.tests.test_port_sweep_clock
       or: pytest app/tests/test_port_sweep_clock.py
"""

import uuid
from datetime import datetime, timedelta, timezone

from app.api.assets import _serialize_asset
from app.connectors.base import DiscoveredAsset
from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.claim import AssetClaim, ClaimHistory
from app.models.observer import Observer
from app.services import claim_emitter, projector
from app.services.metadata_bridge import load_bridge_sources
from app.tests import _docaddr


# ── helpers ──────────────────────────────────────────────────────────────

def _observer_id(db, name: str) -> uuid.UUID:
    return db.query(Observer).filter(Observer.name == name).one().id


def _make_asset(db, ip: str) -> uuid.UUID:
    now = datetime.now(timezone.utc)
    asset = AssetCanonical(
        id=uuid.uuid4(), asset_type="ip_address", value=ip, parent_value=None,
        first_seen_at=now, last_seen_at=now,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset.id


def _cleanup(asset_id: uuid.UUID | None) -> None:
    """Scoped to this asset's own id only — the suite runs against the DEV
    database, so a table-wide delete here would take real rows with it."""
    if asset_id is None:
        return
    db = SessionLocal()
    try:
        db.query(ClaimHistory).filter(ClaimHistory.asset_canonical_id == asset_id).delete(synchronize_session=False)
        db.query(AssetClaim).filter(AssetClaim.asset_canonical_id == asset_id).delete(synchronize_session=False)
        db.query(AssetState).filter(AssetState.asset_canonical_id == asset_id).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.id == asset_id).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _naabu_patch(ip: str, ports: list[int], sweep: datetime, *, complete: bool = True) -> DiscoveredAsset:
    """A naabu patch shaped exactly as `connectors/naabu._build_phase_result`
    builds one: a single `now` stamps BOTH every port's `last_seen_at` and
    `naabu_last_scan_at`, and the latter is omitted entirely when the pass
    did not complete (planning#160 D3)."""
    stamped = sweep.isoformat()
    metadata: dict = {
        "sources": ["naabu"],
        "naabu_tier": "standard",
        "naabu_sweep_complete": complete,
        "open_ports": [
            {"port": p, "protocol": "tcp", "sources": ["naabu"], "last_seen_at": stamped}
            for p in ports
        ],
    }
    if complete:
        metadata["naabu_last_scan_at"] = stamped
    return DiscoveredAsset(
        asset_type="ip_address", value=ip, parent_value=None, asset_metadata=metadata,
    )


def _emit_and_project(db, ip: str, asset_id: uuid.UUID, patch: DiscoveredAsset, written: datetime) -> None:
    """Drive one patch through the real emit -> project path at `written`.

    `written` is the writer's clock — what `write_assets()` stamps and what
    lands in `claim.last_observed_at`. Callers pass one STRICTLY LATER than
    the patch's sweep timestamp, because that is the only ordering the real
    pipeline produces: the writer cannot run until the connector has returned.
    """
    claim_emitter.emit_claims(db, [patch], {("ip_address", ip): asset_id}, written)
    db.commit()
    projector.project(db, {asset_id}, written)
    db.commit()


def _state_for(db, asset_id: uuid.UUID) -> AssetState:
    return db.query(AssetState).filter(AssetState.asset_canonical_id == asset_id).one()


def _projected_ports(db, asset_id: uuid.UUID) -> list[int]:
    return sorted(p["port"] for p in _state_for(db, asset_id).open_ports)


def _served_ports(db, asset_id: uuid.UUID) -> list[int]:
    """What `GET /api/assets/{id}` would return for this asset — the same
    `load_bridge_sources` -> `_serialize_asset` pair the route body calls,
    which is where the read-time `_filter_stale_ports` hide lives. Called
    without the route so this file does not need an auth fixture; the
    serializer is the whole of the behaviour under test."""
    asset = db.get(AssetCanonical, asset_id)
    bridge = load_bridge_sources(db, [asset.id])
    served = _serialize_asset(asset, None, bridge.get(asset.id))
    return sorted(p["port"] for p in served["asset_metadata"].get("open_ports", []))


# ── tests ────────────────────────────────────────────────────────────────

def test_fresh_ports_survive_the_projection_that_records_them():
    """THE planning#190 regression, in the production ordering: the sweep
    stamps its ports, the writer stamps the claim a moment LATER, and the
    ports must still be there afterwards.

    Fails if the cutoff goes back to the claim's `last_observed_at`, because
    `written` is after every port's `last_seen_at` by construction — which is
    precisely what made `open_ports` permanently empty."""
    ip = _docaddr.alloc()
    db = SessionLocal()
    asset_id = None
    try:
        sweep = datetime.now(timezone.utc) - timedelta(seconds=5)
        written = sweep + timedelta(seconds=5)
        asset_id = _make_asset(db, ip)

        _emit_and_project(db, ip, asset_id, _naabu_patch(ip, [22, 53, 80, 9929], sweep), written)

        assert _projected_ports(db, asset_id) == [22, 53, 80, 9929], (
            "fresh naabu ports deleted on the projection that recorded them — "
            "the cutoff is not the sweep's own clock"
        )
        # The read-time hide must not undo the write-time keep: both sides now
        # read the same `swept_at`, surfaced as attributes["naabu_last_scan_at"].
        assert _served_ports(db, asset_id) == [22, 53, 80, 9929]
        assert _state_for(db, asset_id).attributes["naabu_last_scan_at"] == sweep.isoformat()
    finally:
        db.close()
        _cleanup(asset_id)


def test_a_later_complete_sweep_still_retires_a_port_it_did_not_reconfirm():
    """The counterweight. Keeping fresh ports must not make ports immortal:
    a plain (never l7_confirmed, never shodan) port from yesterday's sweep
    that today's COMPLETE sweep did not re-confirm is still dropped — with
    both sweeps driven in the real ordering, not a single shared clock."""
    ip = _docaddr.alloc()
    db = SessionLocal()
    asset_id = None
    try:
        first_sweep = datetime.now(timezone.utc) - timedelta(days=1)
        second_sweep = datetime.now(timezone.utc) - timedelta(seconds=5)
        asset_id = _make_asset(db, ip)

        _emit_and_project(
            db, ip, asset_id,
            _naabu_patch(ip, [22, 8080], first_sweep), first_sweep + timedelta(seconds=5),
        )
        assert _projected_ports(db, asset_id) == [22, 8080]

        _emit_and_project(
            db, ip, asset_id,
            _naabu_patch(ip, [22], second_sweep), second_sweep + timedelta(seconds=5),
        )

        assert _projected_ports(db, asset_id) == [22], "8080 was not re-confirmed — it must retire"
        assert _served_ports(db, asset_id) == [22]
    finally:
        db.close()
        _cleanup(asset_id)


def test_an_incomplete_sweep_does_not_advance_the_cutoff():
    """planning#169 survives the clock change. An incomplete pass carries no
    `naabu_last_scan_at` (planning#160 D3) and `evidence["complete"] is
    False` gates the assignment anyway, so it must prune nothing — 8080 from
    the previous complete sweep stays, even though this pass missed it.

    Swapping a bug that HIDES real ports for one that DELETES them on every
    partial sweep would be strictly worse than what #190 fixed."""
    ip = _docaddr.alloc()
    db = SessionLocal()
    asset_id = None
    try:
        first_sweep = datetime.now(timezone.utc) - timedelta(days=1)
        partial_sweep = datetime.now(timezone.utc) - timedelta(seconds=5)
        asset_id = _make_asset(db, ip)

        _emit_and_project(
            db, ip, asset_id,
            _naabu_patch(ip, [22, 8080], first_sweep), first_sweep + timedelta(seconds=5),
        )
        assert _projected_ports(db, asset_id) == [22, 8080]

        _emit_and_project(
            db, ip, asset_id,
            _naabu_patch(ip, [22], partial_sweep, complete=False),
            partial_sweep + timedelta(seconds=5),
        )

        assert _projected_ports(db, asset_id) == [22, 8080], "an unfinished pass deleted a real port"
        # The cutoff must not have ADVANCED. It does not disappear either:
        # `asset_state.attributes` is written with a JSONB `||` merge
        # (projector.py's on_conflict_do_update), so the previous complete
        # sweep's key survives a projection that sets no new one — which is
        # the behaviour #169 wants, one scan's delay before a phantom retires.
        attrs = _state_for(db, asset_id).attributes
        assert attrs["naabu_last_scan_at"] == first_sweep.isoformat()
        assert attrs["naabu_last_scan_at"] != partial_sweep.isoformat()
    finally:
        db.close()
        _cleanup(asset_id)


def test_a_claim_with_no_swept_at_prunes_nothing():
    """Back-compat, and the trap this fix could most easily have become.

    Every `port_observation` claim written before #190 carries evidence
    `{"complete": true, "naabu_tier": ...}` and no `swept_at`. Falling back
    to `last_observed_at` for those would silently reinstate the bug on
    exactly the rows a fix is tested against, so the fallback is instead
    "prune nothing" — the same posture as `_prune_stale_ports`' own
    unparseable-marker branch.

    Seeded as a raw claim because that IS the pre-#190 shape; the emitter can
    no longer produce it."""
    ip = _docaddr.alloc()
    db = SessionLocal()
    asset_id = None
    try:
        stale = datetime.now(timezone.utc) - timedelta(days=30)
        written = datetime.now(timezone.utc)
        asset_id = _make_asset(db, ip)

        db.add(AssetClaim(
            asset_canonical_id=asset_id,
            observer_id=_observer_id(db, "naabu"),
            claim_type="port_observation",
            claim_value={"ports": [
                {"port": 8080, "protocol": "tcp", "last_seen_at": stale.isoformat()},
            ]},
            evidence={"complete": True, "naabu_tier": "standard"},
            first_observed_at=stale,
            last_observed_at=written,
        ))
        db.commit()

        projector.project(db, {asset_id}, written)
        db.commit()

        assert _projected_ports(db, asset_id) == [8080], (
            "a legacy claim with no swept_at must not be pruned against any "
            "substitute cutoff — least of all last_observed_at, which is the bug"
        )
        assert "naabu_last_scan_at" not in _state_for(db, asset_id).attributes
    finally:
        db.close()
        _cleanup(asset_id)


if __name__ == "__main__":
    for _name, _fn in sorted(globals().items()):
        if _name.startswith("test_") and callable(_fn):
            _fn()
            print(f"ok  {_name}")
    print("all passed")
