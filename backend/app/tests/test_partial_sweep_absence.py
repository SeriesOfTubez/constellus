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

The last three tests are planning#175 rather than #169, and they are here
because this is where the real emit -> project harness lives. They cover the
patch shape none of the above did: an EMPTY one. Every test above narrows a
port list, which replaces a claim normally; emptying one did nothing at all,
because the emitter built its observer groups out of port entries and a patch
with no entries produced no group. That made the zero-port fill patch naabu
has emitted since planning#160 inert — an asset's LAST port never retired —
and it was never specific to the CIDR-swept hosts planning#175 found it
through. The two bounds on the fix (an incomplete pass, and another
observer's silence) are pinned alongside it, since emptying a claim is the
most destructive thing the emitter can do.

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


def test_an_empty_complete_sweep_retires_the_last_port():
    """planning#175 — the zero-port fill patch, end to end.

    Every other test here narrows a port list; this one empties it. That
    distinction matters because the empty patch is the *only* thing the
    planning#175 fix newly emits: a CIDR-swept host whose last port closed
    gets `open_ports: []` with a fresh `naabu_last_scan_at`, and nothing
    else. If the emitter treated an empty list as "nothing to claim" and
    skipped the upsert — a perfectly plausible reading — the fix would
    produce a patch that changes nothing, and every connector-level test in
    test_swept_host_port_retirement.py would still pass.

    It lives in this module rather than with the rest of planning#175
    because the harness that drives the real emit -> project path is here.

    httpx's 8080 retiring alongside naabu's ports is the correct and
    already-tested consequence of a complete pass earning the cutoff (see
    `test_complete_sweep_still_retires_ports`) — an absence claim is
    cross-observer, not naabu-only."""
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
            "naabu_last_scan_at": now.isoformat(),
            "open_ports": [],
        })

        claim = _naabu_claim(db, asset_id)
        assert claim.claim_value["ports"] == [], (
            "an empty complete sweep must replace the claim, not be skipped "
            "as an empty update: " + repr(claim.claim_value)
        )

        state = _state_for(db, asset_id)
        assert [p["port"] for p in state.open_ports] == [], state.open_ports
    finally:
        db.close()
        if asset_id is not None:
            _cleanup(asset_id)


def test_an_incomplete_empty_sweep_retires_nothing():
    """planning#175's first safety bound. `absence_claimants` triggers on
    `naabu_last_scan_at`, which `_build_phase_result` writes only when the
    baseline completed (planning#160 D3) — so a pass that died mid-sweep,
    which looks identical apart from that key, must still empty nothing.

    Emptying a claim is the most destructive thing the emitter can do, and
    an unfinished pass is precisely when it must not.

    Measured, not assumed: deleting the `naabu_last_scan_at` condition from
    `absence_claimants` leaves this test PASSING, because planning#169's
    `merge_with_existing=not sweep_complete` independently folds the empty
    list into the stored one. Two mechanisms cover this case, and this test
    pins the behaviour rather than either mechanism — if it ever fails, both
    have gone, which is the thing actually worth knowing."""
    ip = _docaddr.alloc()
    db = SessionLocal()
    asset_id = None
    try:
        seeded_at = datetime.now(timezone.utc) - timedelta(days=1)
        asset_id = _seed(db, ip, seeded_at)

        _emit_and_project(db, ip, asset_id, datetime.now(timezone.utc), {
            "sources": ["naabu"],
            "naabu_tier": "standard",
            "naabu_sweep_complete": False,
            # no naabu_last_scan_at — an incomplete pass omits it entirely
            "open_ports": [],
        })

        claim = _naabu_claim(db, asset_id)
        assert [e["port"] for e in claim.claim_value["ports"]] == [22, 80, 443, 3306, 5432], (
            "an incomplete pass emptied a claim: " + repr(claim.claim_value)
        )
    finally:
        db.close()
        if asset_id is not None:
            _cleanup(asset_id)


def test_another_observers_silence_is_not_an_absence_claim():
    """planning#175's second safety bound, and the reason `absence_claimants`
    names naabu rather than reading the patch's own `sources`.

    Only naabu sweeps an address exhaustively enough for "no ports" to be an
    observation. A patch from any other observer that mentions no ports means
    that observer did not speak — not that it looked and saw nothing — so
    neither its own claim nor naabu's may be emptied by it."""
    ip = _docaddr.alloc()
    db = SessionLocal()
    asset_id = None
    try:
        seeded_at = datetime.now(timezone.utc) - timedelta(days=1)
        asset_id = _seed(db, ip, seeded_at)

        _emit_and_project(db, ip, asset_id, datetime.now(timezone.utc), {
            "sources": ["httpx"],
            "open_ports": [],
        })

        assert [e["port"] for e in _naabu_claim(db, asset_id).claim_value["ports"]] == [
            22, 80, 443, 3306, 5432,
        ], "another observer's empty patch emptied naabu's claim"

        httpx_claim = (
            db.query(AssetClaim)
            .filter(
                AssetClaim.asset_canonical_id == asset_id,
                AssetClaim.observer_id == _observer_id(db, "httpx"),
                AssetClaim.claim_type == "port_observation",
            )
            .one()
        )
        assert [e["port"] for e in httpx_claim.claim_value["ports"]] == [8080], (
            "an observer emptied its OWN claim by not mentioning ports: "
            + repr(httpx_claim.claim_value)
        )
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
