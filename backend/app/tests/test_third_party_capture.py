"""Tests for third-party CNAME boundary capture (planning#147).

`dns_resolve` used to discard the customer→third-party boundary target along
with everything past it, leaving the dependency as a `cdn_domain` STRING on
the owned record. A CNAME pointing at a lapsed or vendor-owned domain had no
node for a WHOIS check, takeover fingerprint or vendor-incident query to
attach to. #147 captures that one node — "stop destroying nodes".

The load-bearing distinction throughout is **capture != scan eligibility**.
The node is recorded; it is never probed. That is enforced in three
independent places, and each is asserted here:

  1. `_extract_scan_targets` filters it out of the in-batch scan list.
  2. The projector sets `probe_class = no_probe` / `estate = not_ours`.
  3. Target scope excludes it structurally — a boundary target is by
     definition outside every declared domain, which is what made it the
     boundary. (Covered in test_target_scope.py's own suite; asserted here
     only as the estate projection it depends on.)

Run with:  python -m app.tests.test_third_party_capture
       or: pytest app/tests/test_third_party_capture.py
"""

import uuid
from datetime import datetime, timezone

from app.connectors.base import DiscoveredAsset
from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.asset_edge import AssetEdge
from app.models.asset_state import AssetState
from app.models.claim import AssetClaim, ClaimHistory
from app.services.asset_writer import write_assets
from app.services.discovery.dns_resolve import _emit_assets
from app.services.scan_executor import _extract_scan_targets


def _cleanup(values: list[str]) -> None:
    db = SessionLocal()
    try:
        rows = db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).all()
        ids = [r.id for r in rows]
        if ids:
            db.query(ClaimHistory).filter(ClaimHistory.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
            db.query(AssetEdge).filter(AssetEdge.source_id.in_(ids)).delete(synchronize_session=False)
            db.query(AssetEdge).filter(AssetEdge.target_id.in_(ids)).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


# ── capture != scan eligibility ─────────────────────────────────────────────

def test_captured_node_is_not_a_scan_target():
    """The in-batch half of the rule. Probing a vendor's infrastructure
    because a customer record points at it is exactly the unauthorised scan
    the boundary rule exists to prevent."""
    assets = _emit_assets(
        {"app.example.com": [
            {"type": "CNAME", "content": "edge.vendor-example.net"},
            {"type": "A", "content": "203.0.113.7"},
        ]},
        "dns_resolve", "example.com", frozenset({"example.com"}),
    )
    targets = _extract_scan_targets(assets)
    assert "app.example.com" in targets, targets
    assert "edge.vendor-example.net" not in targets, (
        f"captured third-party node leaked into the scan target list: {targets}"
    )


def test_owned_assets_still_reach_the_scan_list():
    """Guard the filter's blast radius — it must key off `third_party`, not
    quietly drop ordinary records."""
    assets = _emit_assets(
        {"mail.example.com": [{"type": "A", "content": "203.0.113.9"}]},
        "dns_resolve", "example.com", frozenset({"example.com"}),
    )
    targets = _extract_scan_targets(assets)
    assert "mail.example.com" in targets and "203.0.113.9" in targets, targets


# ── one node per boundary, however many records point at it ────────────────

def test_many_owned_records_share_one_captured_node():
    """Every go.*.contoso.com pointing at the same vendor host must capture
    that host once, not once per record."""
    assets = _emit_assets(
        {
            "a.contoso.com": [{"type": "CNAME", "content": "go.vendor-example.net"},
                              {"type": "A", "content": "203.0.113.20"}],
            "b.contoso.com": [{"type": "CNAME", "content": "go.vendor-example.net"},
                              {"type": "A", "content": "203.0.113.20"}],
        },
        "dns_resolve", "contoso.com", frozenset({"contoso.com"}),
    )
    captured = [a for a in assets if a.value == "go.vendor-example.net"]
    assert len(captured) == 1, f"expected one captured node, got {len(captured)}"


# ── the write path: claim, projection, edge ────────────────────────────────

def test_capture_writes_claim_projects_not_ours_and_draws_a_cname_edge():
    """End to end through the real writer: the captured node gets a
    `third_party_dependency` claim, projects to estate=not_ours /
    probe_class=no_probe, and the owned record points at it with a `cname`
    edge — the attribution axis, not a plain `resolves_to`."""
    suffix = uuid.uuid4().hex[:8]
    owned = f"app-{suffix}.example.com"
    vendor = f"edge-{suffix}.vendor-example.net"
    db = SessionLocal()
    try:
        assets = _emit_assets(
            {owned: [{"type": "CNAME", "content": vendor},
                     {"type": "A", "content": "203.0.113.11"}]},
            "dns_resolve", "example.com", frozenset({"example.com"}),
        )
        write_assets(db, uuid.uuid4(), assets)

        owned_row = db.query(AssetCanonical).filter(AssetCanonical.value == owned).one()
        vendor_row = db.query(AssetCanonical).filter(AssetCanonical.value == vendor).one()

        # The captured node carries no invented DNS identity.
        assert vendor_row.record_type is None, vendor_row.record_type
        assert vendor_row.content is None, vendor_row.content

        claim = (
            db.query(AssetClaim)
            .filter(
                AssetClaim.asset_canonical_id == vendor_row.id,
                AssetClaim.claim_type == "third_party_dependency",
            )
            .one()
        )
        assert claim.claim_value.get("relationship") == "dependency", claim.claim_value
        assert claim.claim_value.get("discovered_via") == "cname", claim.claim_value

        # write_assets projects internally — estate and probe class follow.
        state = db.query(AssetState).filter(
            AssetState.asset_canonical_id == vendor_row.id
        ).one()
        assert state.estate == "not_ours", state.estate
        assert state.attributes.get("probe_class") == "no_probe", state.attributes

        # The dependency edge, and NOT a duplicate resolves_to for the same pair.
        edge_types = {
            e.edge_type for e in db.query(AssetEdge).filter(
                AssetEdge.source_id == owned_row.id,
                AssetEdge.target_id == vendor_row.id,
            ).all()
        }
        assert edge_types == {"cname"}, (
            f"boundary hop should emit exactly one `cname` edge, got {edge_types}"
        )
    finally:
        db.close()
        _cleanup([owned, vendor, "203.0.113.11"])


def test_owned_cname_hop_still_emits_resolves_to():
    """#125 non-regression at the edge layer: a CNAME between two declared
    targets is a plain resolution step, not a third-party dependency. If this
    flips to `cname`, the attribution axis has started claiming the org's own
    infrastructure is a vendor."""
    suffix = uuid.uuid4().hex[:8]
    owned = f"app-{suffix}.fabrikam-example.com"
    other = f"svc-{suffix}.northwind-example.com"
    db = SessionLocal()
    try:
        assets = _emit_assets(
            {owned: [{"type": "CNAME", "content": other},
                     {"type": "A", "content": "203.0.113.12"}]},
            "dns_resolve", "fabrikam-example.com",
            frozenset({"fabrikam-example.com", "northwind-example.com"}),
        )
        write_assets(db, uuid.uuid4(), assets)

        owned_row = db.query(AssetCanonical).filter(AssetCanonical.value == owned).one()
        other_rows = db.query(AssetCanonical).filter(AssetCanonical.value == other).all()
        other_ids = {r.id for r in other_rows}

        edge_types = {
            e.edge_type for e in db.query(AssetEdge).filter(
                AssetEdge.source_id == owned_row.id,
                AssetEdge.target_id.in_(other_ids),
            ).all()
        }
        assert edge_types == {"resolves_to"}, (
            f"owned->owned CNAME must stay resolves_to, got {edge_types}"
        )
        # And neither side was marked third-party.
        for row in [owned_row, *other_rows]:
            assert db.query(AssetClaim).filter(
                AssetClaim.asset_canonical_id == row.id,
                AssetClaim.claim_type == "third_party_dependency",
            ).count() == 0, f"{row.value} was mis-captured as third-party"
    finally:
        db.close()
        _cleanup([owned, other, "203.0.113.12"])


def test_estate_not_ours_survives_reprojection():
    """The claim is durable, so a later projection pass (every scan runs
    several) must not wash the estate back to NULL."""
    from app.services import projector

    suffix = uuid.uuid4().hex[:8]
    owned = f"app-{suffix}.example.com"
    vendor = f"edge-{suffix}.vendor-example.net"
    db = SessionLocal()
    try:
        assets = _emit_assets(
            {owned: [{"type": "CNAME", "content": vendor},
                     {"type": "A", "content": "203.0.113.13"}]},
            "dns_resolve", "example.com", frozenset({"example.com"}),
        )
        write_assets(db, uuid.uuid4(), assets)
        vendor_row = db.query(AssetCanonical).filter(AssetCanonical.value == vendor).one()

        projector.project(db, {vendor_row.id}, datetime.now(timezone.utc))
        db.commit()

        state = db.query(AssetState).filter(
            AssetState.asset_canonical_id == vendor_row.id
        ).one()
        db.refresh(state)
        assert state.estate == "not_ours", state.estate
        assert state.attributes.get("probe_class") == "no_probe", state.attributes
    finally:
        db.close()
        _cleanup([owned, vendor, "203.0.113.13"])


# ── the read path: captured nodes are hidden by default ────────────────────

def test_captured_node_is_hidden_from_the_default_asset_list():
    """Capture must not inflate the inventory an operator reads as "our
    assets". The node exists for dependency/WHOIS/takeover queries to attach
    to; it is not something the org owns, so it is filtered from the default
    list the same way `ignored` rows are — and reachable via an explicit
    flag, not lost."""
    from app.api.assets import list_assets

    suffix = uuid.uuid4().hex[:8]
    owned = f"app-{suffix}.example.com"
    vendor = f"edge-{suffix}.vendor-example.net"
    db = SessionLocal()
    try:
        assets = _emit_assets(
            {owned: [{"type": "CNAME", "content": vendor},
                     {"type": "A", "content": "203.0.113.14"}]},
            "dns_resolve", "example.com", frozenset({"example.com"}),
        )
        write_assets(db, uuid.uuid4(), assets)

        default_values = {a["value"] for a in list_assets(db=db, _=None)}
        assert owned in default_values, "the owned record must still be listed"
        assert vendor not in default_values, (
            "captured third-party node leaked into the default asset list"
        )

        shown_values = {a["value"] for a in list_assets(show_third_party=True, db=db, _=None)}
        assert vendor in shown_values, (
            "show_third_party=True must surface the captured node, not hide it forever"
        )
    finally:
        db.close()
        _cleanup([owned, vendor, "203.0.113.14"])


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
