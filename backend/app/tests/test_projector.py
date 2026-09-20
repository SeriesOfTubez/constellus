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
from app.services.claim_emitter import upsert_single_claim
from app.tests import _docaddr


# ── helpers ──────────────────────────────────────────────────────────────

def _observer_id(db, name: str) -> uuid.UUID:
    return db.query(Observer).filter(Observer.name == name).one().id


def _make_asset(
    db, asset_type: str, value: str,
    record_type: str | None = None, content: str | None = None,
) -> AssetCanonical:
    """planning#144 L3b-1 promoted dns_record identity (record_type/content)
    to real assets_canonical columns and L3b-2's provider_mx recompute reads
    those columns — pass record_type/content explicitly for dns_record test
    rows that need them.

    The `metadata` parameter this used to take is gone with L3c-4: the
    column no longer exists, and every attribute a projector test needs is
    seeded as a claim via `_add_claim` / `_add_port_claim` instead."""
    now = datetime.now(timezone.utc)
    row = AssetCanonical(
        id=uuid.uuid4(), asset_type=asset_type, value=value, parent_value=None,
        first_seen_at=now, last_seen_at=now,
        record_type=record_type, content=content,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _add_port_claim(db, asset_id, observer_name: str, ports: list[dict],
                    last_observed_at: datetime, evidence: dict | None = None) -> None:
    """planning#190 — `evidence` matters for naabu claims: the prune cutoff is
    `evidence["swept_at"]` (the sweep's own clock), not `last_observed_at`.
    A naabu claim seeded without it prunes NOTHING, by design — that is the
    back-compat posture for claims written before #190. So any test that wants
    the prune to RUN has to seed the evidence a real naabu pass would carry."""
    db.add(AssetClaim(
        asset_canonical_id=asset_id,
        observer_id=_observer_id(db, observer_name),
        claim_type="port_observation",
        claim_value={"ports": ports},
        evidence=evidence if evidence is not None else {},
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
    ip = _docaddr.alloc()
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        asset = _make_asset(db, "ip_address", ip)

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
    ip = _docaddr.alloc()
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        old = now - timedelta(days=30)
        within_confirmed_grace = now - timedelta(days=2)

        asset = _make_asset(db, "ip_address", ip)

        # naabu's claim envelope (last_observed_at) is fresh — "now" — i.e.
        # naabu did just run; but the 8080 entry inside its ports list wasn't
        # re-confirmed this run (its own last_seen_at is 30 days stale), so
        # it must be dropped. 22 was re-confirmed now, kept.
        _add_port_claim(db, asset.id, "naabu", [
            {"port": 22, "protocol": "tcp", "last_seen_at": now.isoformat()},
            {"port": 8080, "protocol": "tcp", "last_seen_at": old.isoformat()},
        ], now, evidence={"complete": True, "swept_at": now.isoformat()})
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
    ip = _docaddr.alloc()
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        old = now - timedelta(days=365)
        asset = _make_asset(db, "ip_address", ip)

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
    ip_confirmed = _docaddr.alloc()
    ip_rejected = _docaddr.alloc()
    ip_absent = _docaddr.alloc()
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
        a_absent = _make_asset(db, "ip_address", ip_absent)
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
    cidr_value, ip_cidr = _docaddr.alloc_cidr()
    host_name_mx = f"probe-class-mx-{suffix}.example.com"
    host_name = f"probe-class-{suffix}.example.com"
    db = SessionLocal()
    target_id = None
    try:
        now = datetime.now(timezone.utc)

        a_mx = _make_asset(
            db, "dns_record", host_name_mx,
            record_type="MX", content="aspmx.l.google.com",
        )

        target_id = uuid.uuid4()
        # `cidr_value` is a /29 from `_docaddr.alloc_cidr()` (planning#199),
        # so it cannot equal another test's range — not the literal
        # "192.0.2.0/24" test_scope_cap.py seeds, and not the one the other
        # CIDR test here draws. `Target.value` is still globally UNIQUE
        # (uq_targets_value) and `_cleanup_target` deletes by *id*, so a row
        # stranded by a run that died between the INSERT and its teardown
        # (a kill, a Ctrl-C, an unrelated crash) would make this INSERT fail on
        # every later run until something cleared it. Delete-then-insert
        # (planning#156) makes the seed idempotent, the way scope_cap's is.
        db.query(Target).filter(Target.value == cidr_value).delete(synchronize_session=False)
        db.commit()
        db.add(Target(id=target_id, type=TargetType.CIDR.value, value=cidr_value))
        db.commit()
        a_cidr = _make_asset(db, "ip_address", ip_cidr)

        a_name = _make_asset(
            db, "dns_record", host_name,
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


def test_hosting_claim_only_asset_is_not_skipped():
    """planning#144 L3a: an asset with ONLY a hosting_class claim — no port
    claims, no asset_metadata, no affinity_confirmation claim — must still
    get projected, not silently dropped by the projector's 'nothing to
    project' skip condition."""
    ip = _docaddr.alloc()
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
            record_type="MX", content="aspmx.l.google.com",
        )
        a_unmanaged = _make_asset(
            db, "dns_record", host_unmanaged,
            record_type="MX", content="mail.custom-corp-example.com",
        )
        a_non_mx = _make_asset(
            db, "dns_record", host_non_mx,
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
    `evidence["swept_at"]` — the same value already used as the prune cutoff,
    now also exposed for the L3c port-lifecycle readers. planning#190 moved
    both off the claim's `last_observed_at`, which is stamped after the
    connector returns and so was always later than the ports it judged."""
    ip = _docaddr.alloc()
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        asset = _make_asset(db, "ip_address", ip)
        _add_port_claim(db, asset.id, "naabu", [
            {"port": 443, "protocol": "tcp", "last_seen_at": now.isoformat()},
        ], now, evidence={"complete": True, "swept_at": now.isoformat()})
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
    ip = _docaddr.alloc()
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        asset = _make_asset(db, "ip_address", ip)
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


def test_cdn_and_cdn_domain_projected_from_cdn_boundary_claim():
    """cdn / cdn_domain come from the discovery observer's `cdn_boundary`
    claim (planning#144 L3c-3, replacing L3b-2's asset_metadata passthrough
    stopgap) — still a projection of dns_resolve's judgment, never
    recomputed here."""
    suffix = uuid.uuid4().hex[:10]
    host_name = f"cdn-mirror-{suffix}.example.com"
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        asset = _make_asset(
            db, "dns_record", host_name,
            record_type="CNAME", content="d123.cloudfront.net",
        )
        db.commit()
        _add_claim(db, asset.id, "dns_resolve", "cdn_boundary",
                   {"cdn": True, "cdn_domain": "cloudfront.net"}, now)
        db.commit()

        projector.project(db, {asset.id}, now)
        db.commit()

        state = _state_for(db, asset.id)
        assert state.attributes.get("cdn") is True
        assert state.attributes.get("cdn_domain") == "cloudfront.net"
    finally:
        db.close()
        _cleanup_prefix(f"cdn-mirror-{suffix}")


def test_cdn_boundary_claim_from_any_discovery_observer_is_projected():
    """The cdn_boundary claim is deliberately NOT pinned to one observer —
    the CNAME resolver that makes the judgment is dns_resolve today but the
    key's meaning belongs to whoever resolved it (planning#144 L3c-3)."""
    suffix = uuid.uuid4().hex[:10]
    host_name = f"cdn-mirror-{suffix}.example.com"
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        asset = _make_asset(
            db, "dns_record", host_name,
            record_type="CNAME", content="x.fastly.net",
        )
        db.commit()
        _add_claim(db, asset.id, "dns_records", "cdn_boundary",
                   {"cdn": True, "cdn_domain": "fastly.net"}, now)
        db.commit()

        projector.project(db, {asset.id}, now)
        db.commit()

        assert _state_for(db, asset.id).attributes.get("cdn_domain") == "fastly.net"
    finally:
        db.close()
        _cleanup_prefix(f"cdn-mirror-{suffix}")


def test_eol_summary_projected_from_eol_status_claim():
    """eol_summary comes from eol_enrichment's `eol_status` claim
    (planning#144 L3c-3) — it was the projector's last read of the
    still-authoritative asset_metadata column. The claim wraps a LIST under
    `services` despite the column being named eol_summary."""
    ip = _docaddr.alloc()
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        asset = _make_asset(db, "ip_address", ip)
        db.commit()
        services = [{"port": 443, "product": "nginx", "version": "1.18", "is_eol": True}]
        _add_claim(db, asset.id, "eol_enrichment", "eol_status", {"services": services}, now)
        db.commit()

        projector.project(db, {asset.id}, now)
        db.commit()

        assert _state_for(db, asset.id).eol_summary == services
    finally:
        db.close()
        _cleanup_ip(ip)


def test_eol_status_claim_emptied_clears_eol_summary():
    """A cleared `eol_status` claim (`services: []` — what enrich_eol now
    writes when a host has ports but nothing EOL on them) must empty
    eol_summary, not leave the previous run's records stuck.

    This is a deliberate behaviour CHANGE from the asset_metadata write it
    replaced, which only ever SET eol_services and so let a stale record
    outlive the service it described (planning#144 L3c-3)."""
    ip = _docaddr.alloc()
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        asset = _make_asset(db, "ip_address", ip)
        db.commit()
        _add_claim(db, asset.id, "eol_enrichment", "eol_status",
                   {"services": [{"port": 443, "product": "nginx", "version": "1.18", "is_eol": True}]}, now)
        db.commit()
        projector.project(db, {asset.id}, now)
        db.commit()
        assert _state_for(db, asset.id).eol_summary, "precondition: eol_summary populated"

        # Re-observation, not a second claim — upsert_single_claim is the
        # whole-value replace enrich_eol itself uses.
        later = now + timedelta(hours=1)
        upsert_single_claim(db, asset.id, "eol_enrichment", "eol_status", {"services": []}, later)
        db.commit()
        projector.project(db, {asset.id}, later)
        db.commit()

        assert _state_for(db, asset.id).eol_summary == []
    finally:
        db.close()
        _cleanup_ip(ip)


def test_eol_status_claim_from_another_observer_is_ignored():
    """eol_status is pinned to the eol_enrichment observer — it is that
    service's output, not an open vocabulary like cdn_boundary. A claim of
    the same type from anyone else must not become eol_summary."""
    ip = _docaddr.alloc()
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        asset = _make_asset(db, "ip_address", ip)
        db.commit()
        _add_claim(db, asset.id, "shodan", "eol_status",
                   {"services": [{"port": 1, "product": "bogus", "version": "0", "is_eol": True}]}, now)
        db.commit()

        projector.project(db, {asset.id}, now)
        db.commit()

        assert _state_for(db, asset.id).eol_summary == []
    finally:
        db.close()
        _cleanup_ip(ip)


def test_no_cdn_metadata_no_cdn_attributes():
    """No `cdn_boundary` claim -> neither key appears in attributes (no
    invented default)."""
    ip = _docaddr.alloc()
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        asset = _make_asset(db, "ip_address", ip)
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
    ip = _docaddr.alloc()
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
    ip = _docaddr.alloc()
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
    ip = _docaddr.alloc()
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



# ── tenancy composition, rule only (planning#182 rung 3) ──────────────────
#
# `_compose_tenancy` is pure, so these pin the composition RULE itself with
# no DB and no race against the live enricher. The projector tests below pin
# the wiring; these pin the decision.


def _op(tenancy, *, tier=0, observer="tenancy_enricher", reason="r", promoting=None):
    return {
        "observer": observer, "claim_type": "tenancy", "tier": tier,
        "tenancy": tenancy, "reason": reason,
        "promoting": (tier in projector._PROMOTING_TIERS) if promoting is None else promoting,
    }


def test_compose_tenancy_no_rungs_is_distinguishable_from_no_answer():
    """planning#177 acceptance criterion 3, and the whole reason this is
    composed rather than read off one claim: "we never looked" and "we looked
    and nothing could answer" are different facts, both deny, and the
    decision log has to tell them apart. `is_datacenter` could not — a
    missing claim and a False one were the same falsy value."""
    never_looked = projector._compose_tenancy([])
    assert never_looked["tenancy"] == "undetermined"
    assert never_looked["rule"] == "no_rungs_reported"
    assert never_looked["rungs"] == []

    looked_no_answer = projector._compose_tenancy([
        _op("undetermined", tier=None, reason="service_class_unknown"),
    ])
    assert looked_no_answer["tenancy"] == "undetermined"
    assert looked_no_answer["rule"] == "all_rungs_undetermined"
    assert looked_no_answer["rungs"][0]["reason"] == "service_class_unknown"

    assert never_looked["rule"] != looked_no_answer["rule"]


def test_compose_tenancy_promoting_rung_alone_promotes():
    """Tier 0 `compute` (AWS EC2 / a pure-VPS range) is single-tenant by
    construction — one address, one ENI — so it carries a promotion on its
    own. Tier 1 later joined `_PROMOTING_TIERS` too, but on a separate,
    explicitly weaker argument (see that frozenset's comment in
    `projector.py`) — it is not admitted for the same reason Tier 0 is."""
    composed = projector._compose_tenancy([
        _op("single_tenant", tier=0, reason="provider_service_class_compute"),
    ])
    assert composed["tenancy"] == "single_tenant"
    assert composed["rule"] == "unanimous_with_promoting_rung"


def test_compose_tenancy_tier1_promotes_alone():
    """planning#181 §3. Azure, GCP and OCI publish zero Tier-0-promotable
    prefixes, so on those estates Tier 1 is the only rung that votes. A
    non-promoting Tier 1 would fall to `single_tenant_not_corroborated` and
    deny — delivering nothing for the population it was built for. The
    promotion is admitted on the argument written into `_PROMOTING_TIERS`:
    it is ANDed with `confirmed_ours` at the probe_class rung, and Tier 2's
    dissent still wins outright over it."""
    assert 1 in projector._PROMOTING_TIERS
    composed = projector._compose_tenancy([
        _op("single_tenant", tier=1, observer="tenancy_tls", reason="r"),
    ])
    assert composed["tenancy"] == "single_tenant"
    assert composed["rule"] == "unanimous_with_promoting_rung"


def test_compose_tenancy_tier2_dissent_still_beats_a_tier1_promotion():
    """The second guard named in `_PROMOTING_TIERS`' argument: a default
    certificate is exactly what a shared host would present, and Tier 2 is
    the rung specialised in detecting that. Rule 1 must still win."""
    composed = projector._compose_tenancy([
        _op("single_tenant", tier=1, observer="tenancy_tls", reason="r"),
        projector._tier2_tenancy_opinion({"sharing": "shared"}),
    ])
    assert composed["tenancy"] == "not_single_tenant"
    assert composed["rule"] == "dissent_wins_outright"


def test_compose_tenancy_dissent_wins_outright_over_a_promoting_rung():
    """The asymmetry, copied from `shared_infra_verifier`: one rung saying
    `not_single_tenant` denies even against an authoritative promotion. A
    CDN fronted out of an EC2 range is exactly this shape, and denial is the
    cheap error — the expensive one points a port scanner at a shared host."""
    composed = projector._compose_tenancy([
        _op("single_tenant", tier=0, reason="provider_service_class_compute"),
        projector._tier2_tenancy_opinion({"sharing": "shared"}),
    ])
    assert composed["tenancy"] == "not_single_tenant"
    assert composed["rule"] == "dissent_wins_outright"


def test_compose_tenancy_non_promoting_rung_cannot_promote_alone():
    """Tier 2 `dedicated` is an argument from ABSENCE over a source with
    incomplete coverage. It corroborates; it never carries a promotion by
    itself — and the denial it produces is recorded as its own rule, not as
    the "nothing could answer" one, because something did answer."""
    alone = projector._compose_tenancy([projector._tier2_tenancy_opinion({"sharing": "dedicated"})])
    assert alone["tenancy"] == "undetermined"
    assert alone["rule"] == "single_tenant_not_corroborated"

    with_tier0 = projector._compose_tenancy([
        _op("single_tenant", tier=0, reason="provider_service_class_compute"),
        projector._tier2_tenancy_opinion({"sharing": "dedicated"}),
    ])
    assert with_tier0["tenancy"] == "single_tenant"
    assert with_tier0["rule"] == "unanimous_with_promoting_rung"


def test_compose_tenancy_abstention_does_not_block_a_promotion():
    """The one place this deliberately diverges from
    `shared_infra_verifier`, whose unanimity treats `indeterminate` as
    blocking. There each abstention is an unprobed vhost — real unexamined
    risk on the address. Here every rung describes the SAME address and
    `undetermined` means "my source has nothing to say", which is not
    partial evidence of multi-tenancy. `reverse_ip` reports `unknown`
    whenever passive DNS returns nothing at all, so treating abstention as a
    veto would let a silent rung block every promotion."""
    for silent in ({"sharing": "unknown"}, {"sharing": "historically_shared"}):
        composed = projector._compose_tenancy([
            _op("single_tenant", tier=0, reason="provider_service_class_compute"),
            projector._tier2_tenancy_opinion(silent),
        ])
        assert composed["tenancy"] == "single_tenant", silent
        assert composed["rule"] == "unanimous_with_promoting_rung", silent


def test_tier2_never_extrapolates_historically_shared():
    """planning#180's rule, carried forward by #182: `historically_shared`
    says the sharing we can SEE is old. It is not a tenancy verdict in
    either direction, and `_sharing_verdict` already refuses to emit it on a
    truncated page, so its absence is not evidence either."""
    assert projector._tier2_tenancy_opinion({"sharing": "historically_shared"})["tenancy"] == "undetermined"
    assert projector._tier2_tenancy_opinion({"sharing": "shared"})["tenancy"] == "not_single_tenant"
    assert projector._tier2_tenancy_opinion({"sharing": "dedicated"})["tenancy"] == "single_tenant"
    assert projector._tier2_tenancy_opinion({"sharing": "dedicated"})["promoting"] is False
    # Unrecognised / missing shapes abstain by returning no opinion at all —
    # never a `no`. "Absent is not false" (planning#182).
    assert projector._tier2_tenancy_opinion(None) is None
    assert projector._tier2_tenancy_opinion({}) is None
    assert projector._tier2_tenancy_opinion({"sharing": "something_new"}) is None


def test_tenancy_opinion_from_claim_ignores_unrecognised_claim_shapes():
    assert projector._tenancy_opinion_from_claim("tenancy_enricher", None) is None
    assert projector._tenancy_opinion_from_claim("tenancy_enricher", {}) is None
    assert projector._tenancy_opinion_from_claim("tenancy_enricher", {"tenancy": "maybe"}) is None
    opinion = projector._tenancy_opinion_from_claim("tenancy_enricher", {
        "tenancy": "single_tenant", "decided_by_tier": 0,
        "reason": "provider_service_class_compute", "dataset_sha256": "9f125cb4",
    })
    assert opinion["promoting"] is True
    assert opinion["dataset_sha256"] == "9f125cb4"


def test_compose_tenancy_carries_dataset_sha256_for_provenance():
    """SCHEMA.md asks a consumer to record the dataset digest alongside the
    decision it informed. planning#181 already stamps it on the claim, so
    carrying it through costs nothing and keeps a past authorisation
    reconstructable against the exact dataset that produced it."""
    composed = projector._compose_tenancy([
        _op("single_tenant", tier=0) | {"dataset_sha256": "9f125cb4"},
        projector._tier2_tenancy_opinion({"sharing": "dedicated"}),
    ])
    assert composed["dataset_sha256"] == "9f125cb4"
    # A composition with no range-feed rung carries no digest rather than a
    # null one — the key's presence means "a dataset informed this".
    assert "dataset_sha256" not in projector._compose_tenancy(
        [projector._tier2_tenancy_opinion({"sharing": "shared"})]
    )


# ── tenancy rung 3, through the projector (planning#182) ──────────────────
#
# These run against the real dev DB with the live tenancy_enricher ticking
# every 60s. They used to mask the real `cloud_ranges` rows covering their IP,
# because Vultr's feed published all three RFC 5737 documentation ranges as
# `compute` and the gitleaks non-reserved-public-ipv4 rule makes RFC 5737 the
# only IPv4 this suite may use — a tick landing mid-test stamped
# `single_tenant` from the LIVE dataset and inverted every denial below.
# planning#183 fixed that at the source: normalize.py now drops every
# non-global prefix from every feed, so a tick on these addresses yields
# `undetermined`/`no_matching_prefix` and cannot invert an assertion.
#
# A tick can still ADD an undetermined rung, which is a different problem and
# only matters to test_is_datacenter_alone_no_longer_promotes — see there.


def test_tenancy_and_ownership_are_separate_caps():
    """THE test for planning#178's load-bearing constraint. A single-tenant
    address with NO confirmed-ours verdict must not promote: single tenancy
    says one tenant lives here, not that the tenant is us. Collapsed into one
    signal, a recycled address in a pure-VPS range authorises scanning a
    stranger's host."""
    ip = _docaddr.alloc()
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        asset = _make_asset(db, "ip_address", ip)
        _add_claim(db, asset.id, "tenancy_enricher", "tenancy", {
            "tenancy": "single_tenant", "decided_by_tier": 0,
            "reason": "provider_service_class_compute", "dataset_sha256": "deadbeef",
        }, now)
        db.commit()

        projector.project(db, {asset.id}, now)
        db.commit()
        db.expire_all()

        state = _state_for(db, asset.id)
        assert state.attributes["tenancy"]["tenancy"] == "single_tenant"
        assert state.attributes["probe_class"] == "name_only", (
            "single tenancy alone must never license a bare-IP probe"
        )
    finally:
        db.close()
        _cleanup_ip(ip)


def test_probe_class_direct_addressable_via_tenancy_and_confirmed_ours():
    """The rung planning#182 rewrote: composed `single_tenant` AND
    `confirmed_ours`, ANDed as two independent caps."""
    ip = _docaddr.alloc()
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        asset = _make_asset(db, "ip_address", ip)
        _add_claim(db, asset.id, "tenancy_enricher", "tenancy", {
            "tenancy": "single_tenant", "decided_by_tier": 0,
            "reason": "provider_service_class_compute", "dataset_sha256": "deadbeef",
        }, now)
        _add_claim(db, asset.id, "shared_infra_verifier", "affinity_confirmation",
                   {"verdict": "confirmed_ours"}, now)
        db.commit()

        projector.project(db, {asset.id}, now)
        db.commit()
        db.expire_all()

        state = _state_for(db, asset.id)
        assert state.attributes["probe_class"] == "direct_addressable"
        assert state.attributes["tenancy"]["rule"] == "unanimous_with_promoting_rung"
        assert state.attributes["tenancy"]["dataset_sha256"] == "deadbeef"
    finally:
        db.close()
        _cleanup_ip(ip)


def test_is_datacenter_alone_no_longer_promotes():
    """The regression planning#182 exists to fix. `is_datacenter` is true of
    a CDN edge node and a managed load balancer as readily as a customer VM,
    and it fails SOFT to False on a broken lookup (planning#177). It is out
    of the rung entirely now — a hosting_class claim with no tenancy claim
    behind it licenses nothing, however confident the ownership verdict.

    `hosting` itself must still project, unchanged: the finding-attribution
    path (epic#81 Phase D / planning#107) reads it, and that path is asking a
    genuinely different question."""
    ip = _docaddr.alloc()
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        asset = _make_asset(db, "ip_address", ip)
        _add_claim(db, asset.id, "hosting_classifier", "hosting_class",
                   {"is_datacenter": True, "company_name": "Acme Hosting"}, now)
        _add_claim(db, asset.id, "shared_infra_verifier", "affinity_confirmation",
                   {"verdict": "confirmed_ours"}, now)
        db.commit()

        # planning#183 §4: the live enricher ticks every 60s and, now that the
        # dataset no longer claims RFC 5737, a tick on this address writes an
        # `undetermined`/`no_matching_prefix` tenancy claim. That is a rung
        # REPORTING, which composes to `all_rungs_undetermined` — not to the
        # `no_rungs_reported` this test is actually about. Dropping the bad
        # Vultr rows did NOT remove that race; only clearing the claim does.
        # Deleted by id, uncommitted, in the same transaction project() reads.
        #
        # KNOWN RESIDUAL, measured and accepted (2026-09-19, Jason). This
        # clears only what has already COMMITTED. Postgres is READ COMMITTED,
        # so a tick committing between this DELETE and project()'s
        # `asset_claims` SELECT is still visible to that read. Measured window
        # 3.3–6.7ms against a 60s tick: ~1 in 9,000 runs. If you are here
        # because of
        #     assert 'all_rungs_undetermined' == 'no_rungs_reported'
        # that is what happened — rerun, nothing is broken. It cannot cause a
        # false PASS: a stray tick only ever ADDS a rung, and the safety
        # assertion below (`name_only`) holds either way. CI never hits it —
        # the scheduler does not run under pytest and CI's `cloud_ranges` is
        # empty, so `tick()` returns without writing. Closing it fully would
        # take REPEATABLE READ on this transaction; deliberately not done,
        # rather than have one test carry a custom isolation level.
        db.query(AssetClaim).filter(
            AssetClaim.asset_canonical_id == asset.id,
            AssetClaim.claim_type == "tenancy",
            AssetClaim.observer_id == _observer_id(db, "tenancy_enricher"),
        ).delete(synchronize_session=False)

        projector.project(db, {asset.id}, now)
        db.commit()
        db.expire_all()

        state = _state_for(db, asset.id)
        assert state.attributes["probe_class"] == "name_only"
        assert state.hosting == {"is_datacenter": True, "company_name": "Acme Hosting"}
        # No tenancy claim behind the hosting_class claim: nothing reports.
        assert state.attributes["tenancy"]["rule"] == "no_rungs_reported"
    finally:
        db.close()
        _cleanup_ip(ip)


def test_not_single_tenant_denies_and_is_logged_distinctly_from_unknown():
    """A CDN/managed range: the provider's own feed says no customer VM
    lives here. Denies regardless of affinity, and lands on a rule that a
    reader of `authorisation_decisions` can separate from "we could not
    check" — which is planning#177's whole complaint and this issue's third
    acceptance criterion."""
    ip = _docaddr.alloc()
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        asset = _make_asset(db, "ip_address", ip)
        _add_claim(db, asset.id, "tenancy_enricher", "tenancy", {
            "tenancy": "not_single_tenant", "decided_by_tier": 0,
            "reason": "provider_service_class_edge", "dataset_sha256": "deadbeef",
        }, now)
        _add_claim(db, asset.id, "shared_infra_verifier", "affinity_confirmation",
                   {"verdict": "confirmed_ours"}, now)
        db.commit()

        projector.project(db, {asset.id}, now)
        db.commit()
        db.expire_all()

        state = _state_for(db, asset.id)
        assert state.attributes["probe_class"] == "name_only"
        assert state.attributes["tenancy"]["tenancy"] == "not_single_tenant"
        assert state.attributes["tenancy"]["rule"] == "dissent_wins_outright"
        assert state.attributes["tenancy"]["rungs"][0]["reason"] == "provider_service_class_edge"
    finally:
        db.close()
        _cleanup_ip(ip)


def test_tier2_reverse_ip_sharing_denies_a_tier0_promotion():
    """Tier 2 rides on the `reverse_ip` claim hosting_classifier already
    writes — no new claim type, no new observer, no mnemonic quota. A live
    CDN address inside an EC2 range is the case: Tier 0 promotes, Tier 2 sees
    300 currently-resolving domains, and dissent wins outright."""
    ip = _docaddr.alloc()
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        asset = _make_asset(db, "ip_address", ip)
        _add_claim(db, asset.id, "tenancy_enricher", "tenancy", {
            "tenancy": "single_tenant", "decided_by_tier": 0,
            "reason": "provider_service_class_compute", "dataset_sha256": "deadbeef",
        }, now)
        _add_claim(db, asset.id, "hosting_classifier", "reverse_ip",
                   {"source": "mnemonic", "count": 332, "domains": [],
                    "records": [], "active_count": 120, "truncated": True,
                    "sharing": "shared"}, now)
        _add_claim(db, asset.id, "shared_infra_verifier", "affinity_confirmation",
                   {"verdict": "confirmed_ours"}, now)
        db.commit()

        projector.project(db, {asset.id}, now)
        db.commit()
        db.expire_all()

        state = _state_for(db, asset.id)
        assert state.attributes["probe_class"] == "name_only"
        assert state.attributes["tenancy"]["rule"] == "dissent_wins_outright"
        claim_types = {r["claim_type"] for r in state.attributes["tenancy"]["rungs"]}
        assert claim_types == {"tenancy", "reverse_ip"}
    finally:
        db.close()
        _cleanup_ip(ip)


def test_tenancy_claim_from_an_unlisted_observer_is_ignored():
    """`tenancy` is read from a SET of observers, not from anyone. An
    observer not in `_TENANCY_OBSERVERS` gets no vote — the set is the
    entitlement check, the same way emission-time seeding is for
    `cloud_inventory`."""
    ip = _docaddr.alloc()
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        asset = _make_asset(db, "ip_address", ip)
        _add_claim(db, asset.id, "naabu", "tenancy", {
            "tenancy": "single_tenant", "decided_by_tier": 0,
            "reason": "provider_service_class_compute",
        }, now)
        _add_claim(db, asset.id, "shared_infra_verifier", "affinity_confirmation",
                   {"verdict": "confirmed_ours"}, now)
        db.commit()

        projector.project(db, {asset.id}, now)
        db.commit()
        db.expire_all()

        state = _state_for(db, asset.id)
        assert state.attributes["probe_class"] == "name_only"
        assert all(
            r["observer"] != "naabu" for r in state.attributes["tenancy"]["rungs"]
        )
    finally:
        db.close()
        _cleanup_ip(ip)


def test_cidr_route_is_untouched_by_tenancy():
    """The declared-CIDR disjunct is the strongest non-credentialed evidence
    we have and planning#182 deliberately does not touch it: an address the
    customer declared in scope stays `direct_addressable` even when a rung
    calls the range multi-tenant. An operator declaring a CIDR is a stronger
    authorisation than any inference about who else lives there."""
    cidr_value, ip = _docaddr.alloc_cidr()
    db = SessionLocal()
    target_id = None
    try:
        now = datetime.now(timezone.utc)
        target_id = uuid.uuid4()
        # Delete-then-insert: `Target.value` is globally UNIQUE and
        # `_cleanup_target` deletes by id, so a row stranded by a killed
        # run would otherwise fail this INSERT forever (planning#156,
        # same reasoning as test_probe_class_rules').
        db.query(Target).filter(Target.value == cidr_value).delete(synchronize_session=False)
        db.commit()
        db.add(Target(id=target_id, type=TargetType.CIDR.value, value=cidr_value))
        db.commit()

        asset = _make_asset(db, "ip_address", ip)
        _add_claim(db, asset.id, "tenancy_enricher", "tenancy", {
            "tenancy": "not_single_tenant", "decided_by_tier": 0,
            "reason": "provider_service_class_managed", "dataset_sha256": "deadbeef",
        }, now)
        db.commit()

        projector.project(db, {asset.id}, now)
        db.commit()
        db.expire_all()

        state = _state_for(db, asset.id)
        assert state.attributes["probe_class"] == "direct_addressable"
        assert state.attributes["tenancy"]["tenancy"] == "not_single_tenant"
    finally:
        db.close()
        if target_id is not None:
            _cleanup_target(target_id)
        _cleanup_ip(ip)


def test_non_ip_assets_carry_no_tenancy_attribute():
    """A hostname has no address for a rung to have an opinion about.
    Writing `no_rungs_reported` onto every dns_record row would put a
    meaningless key on most rows in the table — and, because `attributes` is
    merged rather than replaced, one that never goes away."""
    suffix = uuid.uuid4().hex[:10]
    host = f"tenancy-nonip-{suffix}.example.com"
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        asset = _make_asset(db, "dns_record", host, record_type="A", content="203.0.113.9")
        _add_port_claim(db, asset.id, "naabu", [
            {"port": 443, "protocol": "tcp", "last_seen_at": now.isoformat()},
        ], now)
        db.commit()

        projector.project(db, {asset.id}, now)
        db.commit()
        db.expire_all()

        assert "tenancy" not in _state_for(db, asset.id).attributes
    finally:
        db.close()
        _cleanup_prefix(f"tenancy-nonip-{suffix}")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
