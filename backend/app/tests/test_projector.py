"""Tests for the synchronous claims -> asset_state projector (L2 sub-slice
C, planning#143).

Claims are seeded directly as AssetClaim rows (not through write_assets /
claim_emitter) so each test controls claim_value and last_observed_at
precisely — mirrors the direct-function style of test_prune_stale_ports.py,
just exercised through the DB-backed projector.project() instead of the
bare function.

Requires a live DB connection with migration 0039 applied (asset_claims,
asset_state, observers seeded) — same style as test_claim_emission.py.

Run with:  python -m app.tests.test_projector
       or: pytest app/tests/test_projector.py
"""

import uuid
from datetime import datetime, timedelta, timezone

from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.claim import AssetClaim, ClaimHistory
from app.models.observer import Observer
from app.models.target import Target, TargetType
from app.services import projector


# ── helpers ──────────────────────────────────────────────────────────────

def _observer_id(db, name: str) -> uuid.UUID:
    return db.query(Observer).filter(Observer.name == name).one().id


def _make_asset(
    db, asset_type: str, value: str, metadata: dict | None = None,
    record_type: str | None = None, content: str | None = None,
) -> AssetCanonical:
    """planning#144 L3b-1 promoted dns_record identity (record_type/content)
    to real assets_canonical columns; L3b-2's provider_mx recompute reads
    those columns, not asset_metadata — pass record_type/content explicitly
    for dns_record test rows that need them."""
    now = datetime.now(timezone.utc)
    row = AssetCanonical(
        id=uuid.uuid4(), asset_type=asset_type, value=value, parent_value=None,
        first_seen_at=now, last_seen_at=now, asset_metadata=metadata or {},
        record_type=record_type, content=content,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _add_port_claim(db, asset_id, observer_name: str, ports: list[dict], last_observed_at: datetime) -> None:
    db.add(AssetClaim(
        asset_canonical_id=asset_id,
        observer_id=_observer_id(db, observer_name),
        claim_type="port_observation",
        claim_value={"ports": ports},
        evidence={},
        first_observed_at=last_observed_at,
        last_observed_at=last_observed_at,
    ))


def _add_claim(db, asset_id, observer_name: str, claim_type: str, claim_value: dict, last_observed_at: datetime) -> None:
    """planning#144 L3a: hosting_class / affinity_confirmation are seeded as
    claims (not asset_metadata) for the estate/probe_class projector cases
    below — same seeding style as _add_port_claim, just single-value."""
    db.add(AssetClaim(
        asset_canonical_id=asset_id,
        observer_id=_observer_id(db, observer_name),
        claim_type=claim_type,
        claim_value=claim_value,
        evidence={},
        first_observed_at=last_observed_at,
        last_observed_at=last_observed_at,
    ))


def _state_for(db, asset_id) -> AssetState:
    return db.query(AssetState).filter(AssetState.asset_canonical_id == asset_id).one()


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


def _cleanup_prefix(value_prefix: str) -> None:
    db = SessionLocal()
    try:
        rows = db.query(AssetCanonical).filter(AssetCanonical.value.like(f"{value_prefix}%")).all()
        ids = [r.id for r in rows]
        if ids:
            db.query(ClaimHistory).filter(ClaimHistory.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.value.like(f"{value_prefix}%")).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _cleanup_target(target_id) -> None:
    db = SessionLocal()
    try:
        db.query(Target).filter(Target.id == target_id).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


# ── open_ports: merge across observers, sources restored ───────────────────

def test_open_ports_merge_across_observers_with_restored_sources():
    """naabu (80, 443) + tlsx (443, l7_confirmed) claims for one IP must
    project into one asset_state.open_ports list with both ports; 443 must
    carry tlsx's l7_confirmed field and sources unioned across both
    observers — proving the emitter's stripped `sources` gets restored from
    observer identity before the merge, not lost."""
    suffix = uuid.uuid4().hex[:10]
    ip = f"203.0.113.{10 + (int(suffix[:2], 16) % 60)}"
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        asset = _make_asset(db, "ip_address", ip, metadata={"sources": ["naabu"]})

        _add_port_claim(db, asset.id, "naabu", [
            {"port": 80, "protocol": "tcp", "last_seen_at": now.isoformat()},
            {"port": 443, "protocol": "tcp", "last_seen_at": now.isoformat()},
        ], now)
        _add_port_claim(db, asset.id, "tlsx", [
            {"port": 443, "protocol": "tcp", "l7_confirmed": True, "last_seen_at": now.isoformat()},
        ], now)
        db.commit()

        projector.project(db, {asset.id}, now)
        db.commit()

        state = _state_for(db, asset.id)
        by_port = {p["port"]: p for p in state.open_ports}
        assert set(by_port) == {80, 443}, by_port

        entry_443 = by_port[443]
        assert entry_443.get("l7_confirmed") is True
        assert set(entry_443["sources"]) == {"naabu", "tlsx"}

        entry_80 = by_port[80]
        assert entry_80["sources"] == ["naabu"]
    finally:
        db.close()
        _cleanup_ip(ip)


# ── prune + flap-guard ──────────────────────────────────────────────────────

def test_prune_stale_port_and_flap_guard_kept():
    """A port only re-observed in an old naabu claim entry (stale vs. the
    naabu claim's own last_observed_at cutoff, never app-confirmed) is
    dropped; a port previously l7_confirmed but not re-seen for only a
    couple of days (inside the 3-day confirmed grace) is kept — mirrors
    _prune_stale_ports' flap-guard case, now exercised end-to-end through
    claims."""
    suffix = uuid.uuid4().hex[:10]
    ip = f"203.0.113.{80 + (int(suffix[:2], 16) % 60)}"
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        old = now - timedelta(days=30)
        within_confirmed_grace = now - timedelta(days=2)

        asset = _make_asset(db, "ip_address", ip, metadata={"sources": ["naabu"]})

        # naabu's claim envelope (last_observed_at) is fresh — "now" — i.e.
        # naabu did just run; but the 8080 entry inside its ports list wasn't
        # re-confirmed this run (its own last_seen_at is 30 days stale), so
        # it must be dropped. 22 was re-confirmed now, kept.
        _add_port_claim(db, asset.id, "naabu", [
            {"port": 22, "protocol": "tcp", "last_seen_at": now.isoformat()},
            {"port": 8080, "protocol": "tcp", "last_seen_at": old.isoformat()},
        ], now)
        # A previously-confirmed real service on 443, 2 days stale — inside
        # the 3-day confirmed grace, so kept despite predating the naabu cutoff.
        _add_port_claim(db, asset.id, "tlsx", [
            {"port": 443, "protocol": "tcp", "l7_confirmed": True, "last_seen_at": within_confirmed_grace.isoformat()},
        ], now)
        db.commit()

        projector.project(db, {asset.id}, now)
        db.commit()

        state = _state_for(db, asset.id)
        ports = {p["port"] for p in state.open_ports}
        assert ports == {22, 443}, f"expected fresh(22) + flap-guarded(443), got {ports}"
    finally:
        db.close()
        _cleanup_ip(ip)


def test_no_naabu_claim_skips_prune_keeps_all():
    """No naabu port_observation claim at all -> prune is skipped entirely
    (matches the old writer's 'no naabu_last_scan_at -> keep all')."""
    suffix = uuid.uuid4().hex[:10]
    ip = f"203.0.113.{140 + (int(suffix[:2], 16) % 60)}"
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        old = now - timedelta(days=365)
        asset = _make_asset(db, "ip_address", ip, metadata={"sources": ["shodan"]})

        _add_port_claim(db, asset.id, "shodan", [
            {"port": 21, "protocol": "tcp", "last_seen_at": old.isoformat()},
        ], now)
        db.commit()

        projector.project(db, {asset.id}, now)
        db.commit()

        state = _state_for(db, asset.id)
        ports = {p["port"] for p in state.open_ports}
        assert ports == {21}, "no naabu claim -> nothing pruned, stale shodan port kept"
    finally:
        db.close()
        _cleanup_ip(ip)


# ── estate mapping ───────────────────────────────────────────────────────

def test_estate_mapping():
    suffix = uuid.uuid4().hex[:10]
    ip_confirmed = f"203.0.113.{170 + (int(suffix[:2], 16) % 25)}"
    ip_rejected = f"203.0.113.{200 + (int(suffix[2:4], 16) % 25)}"
    ip_absent = f"203.0.113.{230 + (int(suffix[4:6], 16) % 25)}"
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        # planning#144 L3a: the ownership verdict is now an
        # affinity_confirmation claim, not asset_metadata.
        a_confirmed = _make_asset(db, "ip_address", ip_confirmed)
        _add_claim(db, a_confirmed.id, "shared_infra_verifier", "affinity_confirmation",
                   {"verdict": "confirmed_ours", "evidence": {}}, now)
        a_rejected = _make_asset(db, "ip_address", ip_rejected)
        _add_claim(db, a_rejected.id, "shared_infra_verifier", "affinity_confirmation",
                   {"verdict": "rejected_shared_infra", "evidence": {}}, now)
        # No ownership signal at all -> estate must stay NULL, not default to
        # any of the three known values (planning#129 is an open decision;
        # this projector must not invent one).
        a_absent = _make_asset(db, "ip_address", ip_absent, metadata={"sources": ["dns_records"]})
        db.commit()

        projector.project(db, {a_confirmed.id, a_rejected.id, a_absent.id}, now)
        db.commit()

        assert _state_for(db, a_confirmed.id).estate == "claimed_ours"
        assert _state_for(db, a_rejected.id).estate == "not_ours"
        assert _state_for(db, a_absent.id).estate is None
    finally:
        db.close()
        for ip in (ip_confirmed, ip_rejected, ip_absent):
            _cleanup_ip(ip)


# ── probe_class ──────────────────────────────────────────────────────────

def test_probe_class_rules():
    """planning#144 L3b-2: the MX leg of probe_class now comes from the
    recomputed attributes["provider_mx"] (record_type/content COLUMNS), not
    asset_metadata — a_mx is a dns_record MX row, not an ip_address with a
    metadata flag."""
    suffix = uuid.uuid4().hex[:10]
    ip_cidr = f"192.0.2.{100 + (int(suffix[2:4], 16) % 40)}"
    host_name_mx = f"probe-class-mx-{suffix}.example.com"
    host_name = f"probe-class-{suffix}.example.com"
    db = SessionLocal()
    target_id = None
    try:
        now = datetime.now(timezone.utc)

        a_mx = _make_asset(
            db, "dns_record", host_name_mx,
            metadata={"sources": ["dns_records"], "record_type": "MX", "content": "aspmx.l.google.com"},
            record_type="MX", content="aspmx.l.google.com",
        )

        cidr_value = f"{ip_cidr.rsplit('.', 1)[0]}.0/24"
        target_id = uuid.uuid4()
        db.add(Target(id=target_id, type=TargetType.CIDR.value, value=cidr_value))
        db.commit()
        a_cidr = _make_asset(db, "ip_address", ip_cidr, metadata={"sources": ["naabu"]})

        a_name = _make_asset(
            db, "dns_record", host_name,
            metadata={"sources": ["dns_records"], "record_type": "A", "content": "192.0.2.250"},
            record_type="A", content="192.0.2.250",
        )

        projector.project(db, {a_mx.id, a_cidr.id, a_name.id}, now)
        db.commit()

        assert _state_for(db, a_mx.id).attributes.get("probe_class") == "no_probe"
        assert _state_for(db, a_mx.id).attributes.get("provider_mx") is True
        assert _state_for(db, a_cidr.id).attributes.get("probe_class") == "direct_addressable"
        assert _state_for(db, a_name.id).attributes.get("probe_class") == "name_only"
        assert _state_for(db, a_name.id).attributes.get("provider_mx") is False
    finally:
        db.close()
        if target_id is not None:
            _cleanup_target(target_id)
        _cleanup_ip(ip_cidr)
        _cleanup_prefix(f"probe-class-{suffix}")
        _cleanup_prefix(f"probe-class-mx-{suffix}")


def test_probe_class_direct_addressable_via_hosting_and_confirmed_ours():
    """The other direct_addressable trigger, not CIDR-scoped: a datacenter
    IP (hosting_class claim) with a confirmed_ours affinity_confirmation
    claim. planning#144 L3a — both now claims, not asset_metadata."""
    suffix = uuid.uuid4().hex[:10]
    ip = f"192.0.2.{190 + (int(suffix[:2], 16) % 40)}"
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        asset = _make_asset(db, "ip_address", ip)
        _add_claim(db, asset.id, "hosting_classifier", "hosting_class", {"is_datacenter": True}, now)
        _add_claim(db, asset.id, "shared_infra_verifier", "affinity_confirmation",
                   {"verdict": "confirmed_ours"}, now)
        db.commit()

        projector.project(db, {asset.id}, now)
        db.commit()

        assert _state_for(db, asset.id).attributes.get("probe_class") == "direct_addressable"
    finally:
        db.close()
        _cleanup_ip(ip)


def test_hosting_claim_only_asset_is_not_skipped():
    """planning#144 L3a: an asset with ONLY a hosting_class claim — no port
    claims, no asset_metadata, no affinity_confirmation claim — must still
    get projected, not silently dropped by the projector's 'nothing to
    project' skip condition."""
    suffix = uuid.uuid4().hex[:10]
    ip = f"192.0.2.{230 + (int(suffix[:2], 16) % 20)}"
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        asset = _make_asset(db, "ip_address", ip)  # empty asset_metadata, no port claims
        _add_claim(db, asset.id, "hosting_classifier", "hosting_class",
                   {"is_datacenter": True, "company_name": "Acme Hosting"}, now)
        db.commit()

        projector.project(db, {asset.id}, now)
        db.commit()

        state = _state_for(db, asset.id)
        assert state.hosting == {"is_datacenter": True, "company_name": "Acme Hosting"}
        assert state.estate is None
    finally:
        db.close()
        _cleanup_ip(ip)


# ── derived attributes (planning#144 L3b-2) ─────────────────────────────────

def test_provider_mx_recompute_from_columns():
    """provider_mx is recomputed from the L3b-1 record_type/content COLUMNS
    (is_provider_managed_mx), not read off asset_metadata: a managed MX ->
    True, a non-managed MX -> False, a non-MX dns_record -> False."""
    suffix = uuid.uuid4().hex[:10]
    host_managed = f"provider-mx-managed-{suffix}.example.com"
    host_unmanaged = f"provider-mx-unmanaged-{suffix}.example.com"
    host_non_mx = f"provider-mx-nonmx-{suffix}.example.com"
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        a_managed = _make_asset(
            db, "dns_record", host_managed,
            metadata={"record_type": "MX", "content": "aspmx.l.google.com"},
            record_type="MX", content="aspmx.l.google.com",
        )
        a_unmanaged = _make_asset(
            db, "dns_record", host_unmanaged,
            metadata={"record_type": "MX", "content": "mail.custom-corp-example.com"},
            record_type="MX", content="mail.custom-corp-example.com",
        )
        a_non_mx = _make_asset(
            db, "dns_record", host_non_mx,
            metadata={"record_type": "A", "content": "192.0.2.77"},
            record_type="A", content="192.0.2.77",
        )

        projector.project(db, {a_managed.id, a_unmanaged.id, a_non_mx.id}, now)
        db.commit()

        assert _state_for(db, a_managed.id).attributes.get("provider_mx") is True
        assert _state_for(db, a_unmanaged.id).attributes.get("provider_mx") is False
        assert _state_for(db, a_non_mx.id).attributes.get("provider_mx") is False
    finally:
        db.close()
        _cleanup_prefix(f"provider-mx-managed-{suffix}")
        _cleanup_prefix(f"provider-mx-unmanaged-{suffix}")
        _cleanup_prefix(f"provider-mx-nonmx-{suffix}")


def test_naabu_last_scan_at_derived_from_claim():
    """attributes["naabu_last_scan_at"] is the naabu port_observation claim's
    last_observed_at, isoformatted — the same value already used as the
    prune cutoff, now also exposed for the L3c port-lifecycle readers."""
    suffix = uuid.uuid4().hex[:10]
    ip = f"198.51.100.{80 + (int(suffix[:2], 16) % 60)}"
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        asset = _make_asset(db, "ip_address", ip, metadata={"sources": ["naabu"]})
        _add_port_claim(db, asset.id, "naabu", [
            {"port": 443, "protocol": "tcp", "last_seen_at": now.isoformat()},
        ], now)
        db.commit()

        projector.project(db, {asset.id}, now)
        db.commit()

        state = _state_for(db, asset.id)
        assert state.attributes.get("naabu_last_scan_at") == now.isoformat()
    finally:
        db.close()
        _cleanup_ip(ip)


def test_no_naabu_claim_no_naabu_last_scan_at():
    """No naabu port_observation claim -> the key is absent entirely, not
    set to null (mirrors the prune-cutoff's own 'no naabu claim' handling)."""
    suffix = uuid.uuid4().hex[:10]
    ip = f"198.51.100.{200 + (int(suffix[:2], 16) % 50)}"
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        asset = _make_asset(db, "ip_address", ip, metadata={"sources": ["shodan"]})
        _add_port_claim(db, asset.id, "shodan", [
            {"port": 21, "protocol": "tcp", "last_seen_at": now.isoformat()},
        ], now)
        db.commit()

        projector.project(db, {asset.id}, now)
        db.commit()

        state = _state_for(db, asset.id)
        assert "naabu_last_scan_at" not in state.attributes
    finally:
        db.close()
        _cleanup_ip(ip)


def test_cdn_and_cdn_domain_mirrored_from_metadata():
    """cdn / cdn_domain are a stopgap passthrough copy from asset_metadata
    into attributes (planning#144 L3b-2 user decision) — pure mirror, no
    boundary judgment recomputed here."""
    suffix = uuid.uuid4().hex[:10]
    host_name = f"cdn-mirror-{suffix}.example.com"
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        asset = _make_asset(
            db, "dns_record", host_name,
            metadata={
                "record_type": "CNAME", "content": "d123.cloudfront.net",
                "cdn": True, "cdn_domain": "cloudfront.net",
            },
            record_type="CNAME", content="d123.cloudfront.net",
        )
        db.commit()

        projector.project(db, {asset.id}, now)
        db.commit()

        state = _state_for(db, asset.id)
        assert state.attributes.get("cdn") is True
        assert state.attributes.get("cdn_domain") == "cloudfront.net"
    finally:
        db.close()
        _cleanup_prefix(f"cdn-mirror-{suffix}")


def test_no_cdn_metadata_no_cdn_attributes():
    """No cdn/cdn_domain in asset_metadata -> neither key appears in
    attributes (no invented default)."""
    suffix = uuid.uuid4().hex[:10]
    ip = f"198.51.100.{10 + (int(suffix[:2], 16) % 60)}"
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        asset = _make_asset(db, "ip_address", ip, metadata={"sources": ["naabu"]})
        _add_port_claim(db, asset.id, "naabu", [
            {"port": 80, "protocol": "tcp", "last_seen_at": now.isoformat()},
        ], now)
        db.commit()

        projector.project(db, {asset.id}, now)
        db.commit()

        state = _state_for(db, asset.id)
        assert "cdn" not in state.attributes
        assert "cdn_domain" not in state.attributes
    finally:
        db.close()
        _cleanup_ip(ip)


# ── merge_state_attributes (planning#144 L3b-3) ─────────────────────────

def test_merge_state_attributes_inserts_fresh_row_with_column_defaults():
    """No projector run has ever touched this asset — merge_state_attributes
    must still succeed (upsert, not update-only), landing the patch in
    `attributes` with the other NOT-NULL columns at their table defaults."""
    suffix = uuid.uuid4().hex[:10]
    ip = f"198.51.100.{10 + (int(suffix[:2], 16) % 60)}"
    db = SessionLocal()
    try:
        asset = _make_asset(db, "ip_address", ip)

        projector.merge_state_attributes(db, asset.id, {"dangling_probe_at": "2026-08-19T00:00:00+00:00"})
        db.commit()

        state = _state_for(db, asset.id)
        assert state.attributes == {"dangling_probe_at": "2026-08-19T00:00:00+00:00"}
        assert state.open_ports == []
        assert state.hosting == {}
        assert state.eol_summary == {}
        assert state.estate is None
        assert state.projected_at is None
    finally:
        db.close()
        _cleanup_ip(ip)


def test_merge_state_attributes_merges_without_clobbering_existing_keys():
    """A patch written by merge_state_attributes must compose with the
    projector's own attributes || merge — disjoint keys survive both
    directions, whichever runs first."""
    suffix = uuid.uuid4().hex[:10]
    ip = f"198.51.100.{10 + (int(suffix[:2], 16) % 60)}"
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        asset = _make_asset(db, "ip_address", ip)
        _add_port_claim(db, asset.id, "naabu", [
            {"port": 80, "protocol": "tcp", "last_seen_at": now.isoformat()},
        ], now)
        db.commit()

        # project() runs first and writes probe_class/provider_mx.
        projector.project(db, {asset.id}, now)
        db.commit()
        state = _state_for(db, asset.id)
        assert "probe_class" in state.attributes

        # merge_state_attributes then adds a disjoint key — must not clobber
        # what project() already wrote.
        projector.merge_state_attributes(db, asset.id, {"dangling_probe_at": "2026-08-19T00:00:00+00:00"})
        db.commit()

        state = _state_for(db, asset.id)
        assert state.attributes.get("dangling_probe_at") == "2026-08-19T00:00:00+00:00"
        assert "probe_class" in state.attributes

        # And the reverse order: a second project() run must not clobber the
        # dangling_probe_at key merge_state_attributes already wrote.
        projector.project(db, {asset.id}, now)
        db.commit()
        state = _state_for(db, asset.id)
        assert state.attributes.get("dangling_probe_at") == "2026-08-19T00:00:00+00:00"
        assert "probe_class" in state.attributes
    finally:
        db.close()
        _cleanup_ip(ip)


# ── idempotency ──────────────────────────────────────────────────────────

def test_idempotent_double_projection():
    suffix = uuid.uuid4().hex[:10]
    ip = f"198.51.100.{10 + (int(suffix[:2], 16) % 60)}"
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        # planning#144 L3a: hosting_class / ownership_verdict are now claims,
        # not asset_metadata — this asset has NO asset_metadata contribution
        # at all, only claims, exercising the projector's "claims-only, no
        # metadata" skip-condition fix alongside idempotency.
        asset = _make_asset(db, "ip_address", ip)
        _add_claim(db, asset.id, "shared_infra_verifier", "affinity_confirmation",
                   {"verdict": "confirmed_ours"}, now)
        _add_claim(db, asset.id, "hosting_classifier", "hosting_class",
                   {"is_datacenter": True}, now)
        _add_port_claim(db, asset.id, "naabu", [
            {"port": 80, "protocol": "tcp", "last_seen_at": now.isoformat()},
        ], now)
        db.commit()

        projector.project(db, {asset.id}, now)
        db.commit()
        db.expire_all()
        first = _state_for(db, asset.id)
        first_snapshot = (
            first.open_ports, first.estate, first.hosting,
            first.eol_summary, first.attributes, first.projected_at,
        )

        projector.project(db, {asset.id}, now)
        db.commit()
        db.expire_all()
        second = _state_for(db, asset.id)
        second_snapshot = (
            second.open_ports, second.estate, second.hosting,
            second.eol_summary, second.attributes, second.projected_at,
        )

        assert first_snapshot == second_snapshot, "double projection must yield an identical row"
    finally:
        db.close()
        _cleanup_ip(ip)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
