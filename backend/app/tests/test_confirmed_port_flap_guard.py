"""Regression tests for planning#172 — the l7_confirmed flap-guard must
actually protect naabu-discovered ports.

`_prune_stale_ports` keeps a previously app-confirmed port for
`_CONFIRMED_PORT_GRACE_DAYS` (3) past its last confirmation, so a real
service that flaps is not retired on one miss (planning#69: port 80 flapped
open<->filtered within seconds from two WANs). After planning#144 L3c-4 moved
the prune into the projection, that guard was dead for every port naabu
discovered: `project()` folded `merged_ports` purely from current claim
values, so a port naabu dropped from its claim never reached the prune and
its grace branch never ran. Disabling the prune entirely changed nothing —
proof the prune was not what removed them.

The fix seeds the fold from the previous projection, restoring the
accumulated input the prune had before the migration. Claim semantics are
unchanged: naabu's claim still means "what I saw last pass".

Every seeded port here is `l7_confirmed: True` — the exact inverse of
test_partial_sweep_absence.py's plain-port guard. A plain port would be
retired by the prune either way and would prove nothing about this fix.
`test_plain_ports_still_retire_on_a_complete_pass` is the counterweight: it
proves the new seed did not make ports immortal.

Run with:  python -m app.tests.test_confirmed_port_flap_guard
       or: pytest app/tests/test_confirmed_port_flap_guard.py
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


def _seed(db, ip: str, seeded_at: datetime, *, confirmed: bool) -> uuid.UUID:
    """One ip_address asset with naabu's five-port baseline (22, 80, 443,
    3306, 5432) and httpx's 8080, all at `seeded_at`, then PROJECTED at
    `seeded_at` so `asset_state.open_ports` holds them — that projection is
    the input planning#172's fix reads."""
    now = datetime.now(timezone.utc)
    asset = AssetCanonical(
        id=uuid.uuid4(), asset_type="ip_address", value=ip, parent_value=None,
        first_seen_at=now, last_seen_at=now,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)

    def _entry(port: int) -> dict:
        e = {"port": port, "protocol": "tcp", "last_seen_at": seeded_at.isoformat()}
        if confirmed:
            e["l7_confirmed"] = True
        return e

    db.add(AssetClaim(
        asset_canonical_id=asset.id,
        observer_id=_observer_id(db, "naabu"),
        claim_type="port_observation",
        claim_value={"ports": [_entry(p) for p in (22, 80, 443, 3306, 5432)]},
        evidence={"complete": True},
        first_observed_at=seeded_at,
        last_observed_at=seeded_at,
    ))
    db.add(AssetClaim(
        asset_canonical_id=asset.id,
        observer_id=_observer_id(db, "httpx"),
        claim_type="port_observation",
        claim_value={"ports": [_entry(8080)]},
        evidence={"complete": True},
        first_observed_at=seeded_at,
        last_observed_at=seeded_at,
    ))
    db.commit()

    # The baseline projection. Without this there is nothing for the fold to
    # be seeded FROM and every test below would pass or fail for the wrong
    # reason.
    projector.project(db, {asset.id}, seeded_at)
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


def _projected_ports(db, asset_id: uuid.UUID) -> list[int]:
    state = db.query(AssetState).filter(AssetState.asset_canonical_id == asset_id).one()
    return sorted(e["port"] for e in (state.open_ports or []) if isinstance(e.get("port"), int))


def _run_naabu_pass(db, ip: str, asset_id: uuid.UUID, now: datetime,
                    ports: list[int], *, complete: bool) -> None:
    """One naabu patch through the real emit_claims -> project path."""
    patch = DiscoveredAsset(
        asset_type="ip_address", value=ip, parent_value=None,
        asset_metadata={
            "open_ports": [
                {"port": p, "protocol": "tcp", "sources": ["naabu"],
                 "l7_confirmed": True, "last_seen_at": now.isoformat()}
                for p in ports
            ],
            "naabu_sweep_complete": complete,
        },
    )
    claim_emitter.emit_claims(db, [patch], {("ip_address", ip): asset_id}, now)
    db.commit()
    projector.project(db, {asset_id}, now)
    db.commit()


# ── tests ──────────────────────────────────────────────────────────────

def test_confirmed_ports_survive_a_complete_pass_inside_the_grace():
    """THE planning#172 regression. A COMPLETE naabu pass confirming only 443
    must not retire the four confirmed ports it missed — they are one day old,
    well inside the 3-day confirmed grace. Before the fix this projected
    [443, 8080]: naabu's four were gone from the fold entirely, and disabling
    the prune changed nothing."""
    ip = _docaddr.alloc()
    db = SessionLocal()
    asset_id = None
    try:
        now = datetime.now(timezone.utc)
        asset_id = _seed(db, ip, now - timedelta(days=1), confirmed=True)
        assert _projected_ports(db, asset_id) == [22, 80, 443, 3306, 5432, 8080]

        _run_naabu_pass(db, ip, asset_id, now, [443], complete=True)

        assert _projected_ports(db, asset_id) == [22, 80, 443, 3306, 5432, 8080]
    finally:
        db.close()
        if asset_id:
            _cleanup(asset_id)


def test_confirmed_ports_retire_once_the_grace_expires():
    """The grace is a window, not immortality. Same pass, ports seeded 4 days
    old — past _CONFIRMED_PORT_GRACE_DAYS — must retire down to the one the
    pass actually confirmed."""
    ip = _docaddr.alloc()
    db = SessionLocal()
    asset_id = None
    try:
        now = datetime.now(timezone.utc)
        asset_id = _seed(db, ip, now - timedelta(days=4), confirmed=True)
        assert _projected_ports(db, asset_id) == [22, 80, 443, 3306, 5432, 8080]

        _run_naabu_pass(db, ip, asset_id, now, [443], complete=True)

        assert _projected_ports(db, asset_id) == [443]
    finally:
        db.close()
        if asset_id:
            _cleanup(asset_id)


def test_plain_ports_still_retire_on_a_complete_pass():
    """The counterweight to the seed: an UNCONFIRMED port carries no grace, so
    a complete pass that misses it must still retire it immediately. This is
    what proves seeding the fold from the previous projection did not make
    ports immortal."""
    ip = _docaddr.alloc()
    db = SessionLocal()
    asset_id = None
    try:
        now = datetime.now(timezone.utc)
        asset_id = _seed(db, ip, now - timedelta(days=1), confirmed=False)
        assert _projected_ports(db, asset_id) == [22, 80, 443, 3306, 5432, 8080]

        _run_naabu_pass(db, ip, asset_id, now, [443], complete=True)

        assert _projected_ports(db, asset_id) == [443]
    finally:
        db.close()
        if asset_id:
            _cleanup(asset_id)


def test_incomplete_pass_still_keeps_everything():
    """planning#169's control, re-run with confirmed ports and the new seed in
    place: an INCOMPLETE pass withholds the cutoff, so nothing is pruned and
    every port survives regardless of grace."""
    ip = _docaddr.alloc()
    db = SessionLocal()
    asset_id = None
    try:
        now = datetime.now(timezone.utc)
        asset_id = _seed(db, ip, now - timedelta(days=4), confirmed=True)

        _run_naabu_pass(db, ip, asset_id, now, [443], complete=False)

        assert _projected_ports(db, asset_id) == [22, 80, 443, 3306, 5432, 8080]
    finally:
        db.close()
        if asset_id:
            _cleanup(asset_id)


def test_projection_is_idempotent_with_the_seed():
    """The seed makes project() read its own previous output, so re-running it
    must converge, not grow or shrink."""
    ip = _docaddr.alloc()
    db = SessionLocal()
    asset_id = None
    try:
        now = datetime.now(timezone.utc)
        asset_id = _seed(db, ip, now - timedelta(days=1), confirmed=True)
        _run_naabu_pass(db, ip, asset_id, now, [443], complete=True)
        first = _projected_ports(db, asset_id)

        projector.project(db, {asset_id}, now)
        db.commit()

        assert _projected_ports(db, asset_id) == first
    finally:
        db.close()
        if asset_id:
            _cleanup(asset_id)


if __name__ == "__main__":
    for fn in (
        test_confirmed_ports_survive_a_complete_pass_inside_the_grace,
        test_confirmed_ports_retire_once_the_grace_expires,
        test_plain_ports_still_retire_on_a_complete_pass,
        test_incomplete_pass_still_keeps_everything,
        test_projection_is_idempotent_with_the_seed,
    ):
        fn()
        print(f"ok  {fn.__name__}")
    print("all passed")
