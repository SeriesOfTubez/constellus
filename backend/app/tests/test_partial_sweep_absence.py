"""Regression tests for planning#169 — a naabu pass that confirms only a
subset of an IP's real open ports must not delete the rest from canonical.

Two independent mechanisms caused the loss, and both are exercised here:

1. Claim replacement. `_upsert_claims` used to set `existing.claim_value =
   claim_value` wholesale on every change, so a partial naabu pass (one
   port confirmed) replaced the previous claim's five-port list with a
   one-port list — the other four vanished from the projector's
   cross-observer fold before `_prune_stale_ports` was ever consulted.
   This was the DOMINANT loss: with pruning neutralised entirely, 4 of 5
   ports still disappeared through this path alone.

2. Prune cutoff. `projector` set the `_prune_stale_ports` cutoff (and
   `attributes["naabu_last_scan_at"]`) from naabu's claim's
   `last_observed_at`, which the emitter refreshes on every upsert whether
   or not the pass finished. An unearned cutoff pruned OTHER observers'
   ports (httpx/tlsx/shodan/zgrab2) out of the fold too, and drove the
   read-time hide via `naabu_last_scan_at`.

The fix carries #160's `PhaseResult.complete` through to the claim itself
(naabu's `naabu_sweep_complete` asset_metadata key -> `evidence["complete"]`
on the `port_observation` claim), and gates both replacement and the
staleness cutoff on it.

Every seeded port below is PLAIN: no `l7_confirmed`, no `"shodan"` in
`sources`. Those carry 3-day/14-day grace windows in `_prune_stale_ports`
(see test_worker_outage_absence.py's docstring for the same caveat) — a
test built around a graced port would pass even with the bug present and
prove nothing about this fix.

Claims are seeded directly as AssetClaim rows (mirrors test_projector.py's
style) but the PATCH under test is driven through the real
claim_emitter.emit_claims() -> projector.project() path, since the bug
lives in the emitter's merge/replace decision, not in direct claim seeding.

Run with:  python -m app.tests.test_partial_sweep_absence
       or: pytest app/tests/test_partial_sweep_absence.py
"""

import uuid
from datetime import datetime, timedelta, timezone

from app.connectors.base import DiscoveredAsset
from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.claim import AssetClaim, ClaimHistory
from app.models.observer import Observer
from app.services import claim_emitter, projector
from app.tests import _docaddr


# ── helpers ──────────────────────────────────────────────────────────────

def _observer_id(db, name: str) -> uuid.UUID:
    return db.query(Observer).filter(Observer.name == name).one().id


def _seed(db, ip: str, seeded_at: datetime) -> uuid.UUID:
    """One ip_address asset with naabu's five-port baseline claim (22, 80,
    443, 3306, 5432) and httpx's one-port claim (8080), both at
    `seeded_at` — the "yesterday's complete sweep" state every test below
    starts from."""
    now = datetime.now(timezone.utc)
    asset = AssetCanonical(
        id=uuid.uuid4(), asset_type="ip_address", value=ip, parent_value=None,
        first_seen_at=now, last_seen_at=now,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)

    naabu_ports = [
        {"port": p, "protocol": "tcp", "last_seen_at": seeded_at.isoformat()}
        for p in (22, 80, 443, 3306, 5432)
    ]
    db.add(AssetClaim(
        asset_canonical_id=asset.id,
        observer_id=_observer_id(db, "naabu"),
        claim_type="port_observation",
        claim_value={"ports": naabu_ports},
        evidence={},
        first_observed_at=seeded_at,
        last_observed_at=seeded_at,
    ))
    db.add(AssetClaim(
        asset_canonical_id=asset.id,
        observer_id=_observer_id(db, "httpx"),
        claim_type="port_observation",
        claim_value={"ports": [
            {"port": 8080, "protocol": "tcp", "last_seen_at": seeded_at.isoformat()},
        ]},
        evidence={},
        first_observed_at=seeded_at,
        last_observed_at=seeded_at,
    ))
    db.commit()
    return asset.id


def _cleanup(asset_id: uuid.UUID) -> None:
    db = SessionLocal()
    try:
        db.query(ClaimHistory).filter(ClaimHistory.asset_canonical_id == asset_id).delete(synchronize_session=False)
        db.query(AssetClaim).filter(AssetClaim.asset_canonical_id == asset_id).delete(synchronize_session=False)
        db.query(AssetState).filter(AssetState.asset_canonical_id == asset_id).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.id == asset_id).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _naabu_claim(db, asset_id: uuid.UUID) -> AssetClaim:
    return (
        db.query(AssetClaim)
        .filter(
            AssetClaim.asset_canonical_id == asset_id,
            AssetClaim.observer_id == _observer_id(db, "naabu"),
            AssetClaim.claim_type == "port_observation",
        )
        .one()
    )


def _state_for(db, asset_id: uuid.UUID) -> AssetState:
    return db.query(AssetState).filter(AssetState.asset_canonical_id == asset_id).one()


def _emit_and_project(db, ip: str, asset_id: uuid.UUID, now: datetime, metadata: dict) -> None:
    """Drive one naabu patch through the real emit_claims -> project path —
    the bug is in the emitter's merge/replace decision, so seeding claims
    directly (as test_projector.py does) would not exercise it."""
    patch = DiscoveredAsset(
        asset_type="ip_address", value=ip, parent_value=None, asset_metadata=metadata,
    )
    claim_emitter.emit_claims(db, [patch], {("ip_address", ip): asset_id}, now)
    db.commit()
    projector.project(db, {asset_id}, now)
    db.commit()


# ── tests ──────────────────────────────────────────────────────────────

def test_incomplete_sweep_does_not_delete_unconfirmed_ports():
    """A naabu pass confirming only 443 (naabu_sweep_complete=False) must
    not prune 22/80/3306/5432 from naabu's own fold, nor httpx's 8080 — the
    projected open_ports must still carry all six, and 443's last_seen_at
    must have advanced to the new pass."""
    ip = _docaddr.alloc()
    db = SessionLocal()
    asset_id = None
    try:
        seeded_at = datetime.now(timezone.utc) - timedelta(days=1)
        asset_id = _seed(db, ip, seeded_at)
        now = datetime.now(timezone.utc)

        _emit_and_project(db, ip, asset_id, now, {
            "sources": ["naabu"],
            "naabu_tier": "standard",
            "naabu_sweep_complete": False,
            "open_ports": [
                {"port": 443, "protocol": "tcp", "sources": ["naabu"], "last_seen_at": now.isoformat()},
            ],
        })

        state = _state_for(db, asset_id)
        by_port = {p["port"]: p for p in state.open_ports}
        assert set(by_port) == {22, 80, 443, 3306, 5432, 8080}, by_port
        assert by_port[443]["last_seen_at"] == now.isoformat()
        assert state.attributes.get("naabu_last_scan_at") != now.isoformat()
    finally:
        db.close()
        if asset_id is not None:
            _cleanup(asset_id)


def test_incomplete_sweep_merges_rather_than_replaces_the_claim():
    """Mechanism test for the DOMINANT loss: at the CLAIM level, before the
    projector's prune even runs, an incomplete naabu pass's claim_value
    must still list all five previously-confirmed port numbers, not just
    the one this pass re-confirmed."""
    ip = _docaddr.alloc()
    db = SessionLocal()
    asset_id = None
    try:
        seeded_at = datetime.now(timezone.utc) - timedelta(days=1)
        asset_id = _seed(db, ip, seeded_at)
        now = datetime.now(timezone.utc)

        _emit_and_project(db, ip, asset_id, now, {
            "sources": ["naabu"],
            "naabu_tier": "standard",
            "naabu_sweep_complete": False,
            "open_ports": [
                {"port": 443, "protocol": "tcp", "sources": ["naabu"], "last_seen_at": now.isoformat()},
            ],
        })

        claim = _naabu_claim(db, asset_id)
        ports = {e["port"] for e in claim.claim_value["ports"]}
        assert ports == {22, 80, 443, 3306, 5432}, ports
    finally:
        db.close()
        if asset_id is not None:
            _cleanup(asset_id)


def test_complete_sweep_still_retires_ports():
    """Over-fix guard: a COMPLETE naabu pass confirming only 443 must still
    replace the claim wholesale and earn the prune cutoff — httpx's 8080
    gone from the projected open_ports, naabu's claim_value exactly [443].
    The whole point of replace-and-prune must survive this fix."""
    ip = _docaddr.alloc()
    db = SessionLocal()
    asset_id = None
    try:
        seeded_at = datetime.now(timezone.utc) - timedelta(days=1)
        asset_id = _seed(db, ip, seeded_at)
        now = datetime.now(timezone.utc)

        _emit_and_project(db, ip, asset_id, now, {
            "sources": ["naabu"],
            "naabu_tier": "standard",
            "naabu_sweep_complete": True,
            # planning#190 — a completed pass carries its own clock, and that
            # is what earns the cutoff now. Without it nothing is pruned and
            # httpx's 8080 survives, so the over-fix guard below tests nothing.
            "naabu_last_scan_at": now.isoformat(),
            "open_ports": [
                {"port": 443, "protocol": "tcp", "sources": ["naabu"], "last_seen_at": now.isoformat()},
            ],
        })

        claim = _naabu_claim(db, asset_id)
        assert [e["port"] for e in claim.claim_value["ports"]] == [443]

        state = _state_for(db, asset_id)
        assert [p["port"] for p in state.open_ports] == [443], state.open_ports
    finally:
        db.close()
        if asset_id is not None:
            _cleanup(asset_id)


def test_evidence_completeness_is_refreshed_when_the_port_list_is_unchanged():
    """Emit the SAME single-port list twice: first naabu_sweep_complete=True,
    then False. The second emit hits `_json_equal`'s EQUAL branch (the port
    list didn't change). Without Change 4's evidence write on that branch,
    the stale `complete: True` from the first emit would survive and
    license an unearned prune later. Assert the second emit's
    `complete: False` wins in the stored claim."""
    ip = _docaddr.alloc()
    db = SessionLocal()
    asset_id = None
    try:
        seeded_at = datetime.now(timezone.utc) - timedelta(days=1)
        asset_id = _seed(db, ip, seeded_at)

        now1 = datetime.now(timezone.utc)
        port_entry = {"port": 443, "protocol": "tcp", "sources": ["naabu"], "last_seen_at": now1.isoformat()}

        _emit_and_project(db, ip, asset_id, now1, {
            "sources": ["naabu"],
            "naabu_tier": "standard",
            "naabu_sweep_complete": True,
            "open_ports": [dict(port_entry)],
        })

        now2 = datetime.now(timezone.utc)
        _emit_and_project(db, ip, asset_id, now2, {
            "sources": ["naabu"],
            "naabu_tier": "standard",
            "naabu_sweep_complete": False,
            "open_ports": [dict(port_entry)],
        })

        claim = _naabu_claim(db, asset_id)
        assert claim.evidence.get("complete") is False, claim.evidence
    finally:
        db.close()
        if asset_id is not None:
            _cleanup(asset_id)


def test_absent_completeness_key_behaves_as_complete():
    """A patch with NO `naabu_sweep_complete` key at all — backward
    compatibility for producers that don't know about planning#169, and for
    claims stored before it — must behave exactly like a complete sweep:
    same assertions as test_complete_sweep_still_retires_ports, just
    without the key."""
    ip = _docaddr.alloc()
    db = SessionLocal()
    asset_id = None
    try:
        seeded_at = datetime.now(timezone.utc) - timedelta(days=1)
        asset_id = _seed(db, ip, seeded_at)
        now = datetime.now(timezone.utc)

        _emit_and_project(db, ip, asset_id, now, {
            "sources": ["naabu"],
            "naabu_tier": "standard",
            # `naabu_last_scan_at` predates #169 (planning#160), so a producer
            # that has never heard of `naabu_sweep_complete` still writes it —
            # the absence under test here is the COMPLETENESS key, not the
            # sweep clock (planning#190).
            "naabu_last_scan_at": now.isoformat(),
            "open_ports": [
                {"port": 443, "protocol": "tcp", "sources": ["naabu"], "last_seen_at": now.isoformat()},
            ],
        })

        claim = _naabu_claim(db, asset_id)
        assert [e["port"] for e in claim.claim_value["ports"]] == [443]

        state = _state_for(db, asset_id)
        assert [p["port"] for p in state.open_ports] == [443], state.open_ports
    finally:
        db.close()
        if asset_id is not None:
            _cleanup(asset_id)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
