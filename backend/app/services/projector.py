"""Synchronous, incremental claims -> asset_state projector (planning#143, L2
sub-slice C).

Reads `asset_claims` (path 1, the new grounding layer) + the still-
authoritative `asset_metadata` on `assets_canonical` (path 2, not converted
this slice) and folds them into one projected row per asset in `asset_state`.
Hybrid dual-source by design:

  - `open_ports` is projected from `port_observation` claims — proving the
    claim path actually carries the data readers need.
  - `hosting` (from a `hosting_class` claim) and `estate` (from an
    `affinity_confirmation` claim's `verdict`) are also read from
    `asset_claims` now (planning#144 L3a — hosting_classifier and
    shared_infra_verifier's asset_metadata TTL-caches moved to claims).
  - `eol_summary` is still read straight through from `asset_metadata`,
    because eol_enrichment hasn't been converted to emit claims yet — that
    is a later slice, not this one. `provider_mx` (and the `no_probe` half
    of `probe_class` that depends on it) is now RECOMPUTED here from the
    `assets_canonical.record_type`/`.content` columns (planning#144 L3b-1
    promoted those to columns; L3b-2 stops reading the transitional
    `asset_metadata["provider_mx"]` mirror and derives it fresh instead).

`attributes` on `asset_state` also carries three more derived/envelope
keys as of L3b-2: `provider_mx` (recomputed, see above), `naabu_last_scan_at`
(the naabu `port_observation` claim's `last_observed_at`, isoformatted —
the same value used as the prune cutoff), and `cdn`/`cdn_domain` (a
stopgap passthrough mirror of the still asset_metadata-authoritative CDN
boundary judgment, so they survive the eventual `asset_metadata` column
drop; #147 replaces this with the real CNAME->third-party edge).

This module does NOT do the risky cutover: `asset_writer`'s merge loop stays
in place and keeps authoring `asset_metadata` (the transitional compat
mirror every existing reader still uses). This module only ADDS a
projection into `asset_state`, a table nothing reads yet.

`_merge_open_ports` / `_prune_stale_ports` (plus their grace-period
constants) used to live in `asset_writer.py`; they moved here verbatim as
part of this slice so the projector and the writer's own asset_metadata
merge share one definition. `asset_writer.py` imports them back and keeps
calling them exactly as before — that's a pure move, not a rewrite.
"""

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.connectors.base import is_provider_managed_mx
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.claim import AssetClaim
from app.models.observer import Observer
from app.models.target import Target, TargetType
from app.services import target_scope

# ── moved verbatim from asset_writer.py ────────────────────────────────────

# A Shodan-sourced port (never seen by our active scan) is kept as time-boxed
# intel for this many days past its last_seen_at before the prune drops it.
# Mirrors the read-time grace in app.api.assets._filter_stale_ports.
_SHODAN_PORT_GRACE_DAYS = 14

# A port confirmed by an active prober (l7_confirmed=True) is kept this many days
# past its last confirmation even if later scans miss it. Real services flap —
# intermittent / firewall throttling — so a single missed scan must not retire a
# known-real port (validated 2026-06-23, planning#69: port 80 flapped
# open<->filtered within seconds from two WANs). Shorter than the Shodan grace: a
# confirmed port we can't re-confirm for days is probably genuinely closed.
_CONFIRMED_PORT_GRACE_DAYS = 3


def _prune_stale_ports(open_ports: list, naabu_last_scan_at: str, now: datetime) -> list:
    """Drop ports not re-confirmed in the latest naabu scan, so stored
    `open_ports` == the current truth (instead of accumulating forever).

    A port is kept if it was re-observed at/after the latest naabu scan, OR it
    was previously app-confirmed (l7_confirmed) within the confirmed grace window
    (flap-guard for intermittent real ports), OR it's Shodan-sourced intel inside
    the Shodan grace window, OR it has no timestamp to judge by. Everything else
    (e.g. a firewall phantom that a later nmap-authoritative scan no longer
    confirms) is removed at the source. This is the write-time counterpart of the
    read-time `_filter_stale_ports` hide — here we delete, which also stops any
    consumer from re-probing stale phantoms.
    """
    try:
        cutoff = datetime.fromisoformat(naabu_last_scan_at)
        if cutoff.tzinfo is None:
            cutoff = cutoff.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError, AttributeError):
        return open_ports  # can't parse the marker — don't risk dropping anything
    grace_cutoff = now - timedelta(days=_SHODAN_PORT_GRACE_DAYS)
    confirmed_grace_cutoff = now - timedelta(days=_CONFIRMED_PORT_GRACE_DAYS)
    kept: list = []
    for entry in open_ports:
        if not isinstance(entry, dict):
            continue
        raw = entry.get("last_seen_at")
        if not raw:
            kept.append(entry)  # no timestamp — keep, can't judge staleness
            continue
        try:
            ts = datetime.fromisoformat(raw)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except (ValueError, AttributeError):
            kept.append(entry)
            continue
        if ts >= cutoff:
            kept.append(entry)
        elif entry.get("l7_confirmed") is True and ts >= confirmed_grace_cutoff:
            # Flap-guard: a previously-confirmed real port is kept through brief
            # misses (it flaps) until the confirmed grace expires.
            kept.append(entry)
        elif "shodan" in (entry.get("sources") or []) and ts >= grace_cutoff:
            kept.append(entry)
        # else: stale / grace-expired — drop
    return kept


def _merge_open_ports(existing: list, new: list) -> list:
    """Merge two `open_ports` lists keyed by port number.

    Each entry is `{port, protocol, sources, last_seen_at, …}` plus any
    fields contributed by service enrichers (`service`, `service_version`,
    `tech_stack[]`, `tls_cert_sans[]`, etc.). Merge rules per port:

    * `sources` — union, preserving first-seen order.
    * Other primitive fields — last-write-wins for non-empty values.
    * `last_seen_at` — the newer one wins (lexicographic ISO 8601 ordering).

    A previously-known port that wasn't re-observed in this batch is kept
    untouched; cleanup of stale ports is a separate lifecycle concern.
    """
    by_port: dict[int, dict] = {}
    for entry in existing:
        if isinstance(entry, dict) and isinstance(entry.get("port"), int):
            by_port[entry["port"]] = dict(entry)

    for entry in new:
        if not isinstance(entry, dict):
            continue
        port = entry.get("port")
        if not isinstance(port, int):
            continue
        current = by_port.get(port)
        if current is None:
            by_port[port] = dict(entry)
            continue
        for k, v in entry.items():
            if k == "port":
                continue
            if v in (None, "", [], {}):
                continue
            if k == "sources":
                existing_sources = current.get("sources", [])
                src_list = v if isinstance(v, list) else [v]
                current["sources"] = list(dict.fromkeys(existing_sources + src_list))
            elif k == "last_seen_at":
                if not current.get("last_seen_at") or v > current["last_seen_at"]:
                    current["last_seen_at"] = v
            else:
                current[k] = v

    return sorted(by_port.values(), key=lambda p: p["port"])


# ── projector ────────────────────────────────────────────────────────────

def project(db: Session, asset_ids: set[uuid.UUID], now: datetime) -> None:
    """Fold claims + path-2 asset_metadata into `asset_state`, one row per id.

    Read-only on `asset_claims` + `assets_canonical`; write-only on
    `asset_state`. Never writes `asset_metadata`. Idempotent — running twice
    over the same ids yields the same asset_state rows.

    Skips any id with neither claims (port_observation, hosting_class,
    affinity_confirmation) nor asset_metadata (nothing to project).
    """
    if not asset_ids:
        return

    canonical_by_id: dict[uuid.UUID, AssetCanonical] = {
        r.id: r
        for r in db.query(AssetCanonical).filter(AssetCanonical.id.in_(asset_ids)).all()
    }

    claim_rows = (
        db.query(
            AssetClaim.asset_canonical_id,
            AssetClaim.claim_value,
            AssetClaim.last_observed_at,
            Observer.name,
        )
        .join(Observer, AssetClaim.observer_id == Observer.id)
        .filter(
            AssetClaim.asset_canonical_id.in_(asset_ids),
            AssetClaim.claim_type == "port_observation",
        )
        .all()
    )
    claims_by_asset: dict[uuid.UUID, list[tuple[str, dict, datetime]]] = {}
    for asset_id, claim_value, last_observed_at, observer_name in claim_rows:
        claims_by_asset.setdefault(asset_id, []).append((observer_name, claim_value, last_observed_at))

    # Single-value claims (planning#144 L3a): hosting_class (hosting_classifier
    # observer) and affinity_confirmation (shared_infra_verifier observer),
    # batch-loaded up front like port_observation above rather than a
    # get_current_claim() call per asset in the loop below.
    single_claim_observer_ids = {
        name: observer_id
        for observer_id, name in db.query(Observer.id, Observer.name)
        .filter(Observer.name.in_(["hosting_classifier", "shared_infra_verifier"]))
        .all()
    }
    hosting_class_by_asset: dict[uuid.UUID, dict] = {}
    affinity_confirmation_by_asset: dict[uuid.UUID, dict] = {}
    if single_claim_observer_ids:
        single_claim_rows = (
            db.query(AssetClaim.asset_canonical_id, AssetClaim.claim_type, AssetClaim.claim_value)
            .filter(
                AssetClaim.asset_canonical_id.in_(asset_ids),
                AssetClaim.claim_type.in_(["hosting_class", "affinity_confirmation"]),
                AssetClaim.observer_id.in_(single_claim_observer_ids.values()),
            )
            .all()
        )
        for asset_id, claim_type, claim_value in single_claim_rows:
            if claim_type == "hosting_class":
                hosting_class_by_asset[asset_id] = claim_value
            elif claim_type == "affinity_confirmation":
                affinity_confirmation_by_asset[asset_id] = claim_value

    # CIDR/IP-scoped ip_address ids, computed once for the whole batch —
    # target_scope._ip_scoped_asset_ids takes the full ip/cidr target list,
    # not a per-asset lookup.
    ip_target_values = [
        v for (v,) in db.query(Target.value)
        .filter(Target.type.in_([TargetType.IP, TargetType.CIDR]))
        .all()
    ]
    cidr_scoped_ids = target_scope._ip_scoped_asset_ids(db, ip_target_values)

    rows_to_upsert: list[dict] = []

    for asset_id in asset_ids:
        canonical = canonical_by_id.get(asset_id)
        asset_claims = claims_by_asset.get(asset_id, [])
        metadata = (canonical.asset_metadata or {}) if canonical is not None else {}
        hosting_claim_value = hosting_class_by_asset.get(asset_id)
        affinity_claim_value = affinity_confirmation_by_asset.get(asset_id)

        if not asset_claims and not metadata and hosting_claim_value is None and affinity_claim_value is None:
            continue  # nothing to project for this id

        # ── open_ports: fold every observer's claim through _merge_open_ports,
        # restoring the observer identity the emitter stripped, then prune on
        # the naabu observer's last_observed_at (no naabu claim -> keep all).
        merged_ports: list = []
        naabu_last_observed_at: datetime | None = None
        for observer_name, claim_value, last_observed_at in asset_claims:
            ports = claim_value.get("ports") if isinstance(claim_value, dict) else None
            if not isinstance(ports, list):
                continue
            restored: list[dict] = []
            for entry in ports:
                if not isinstance(entry, dict):
                    continue
                entry = dict(entry)
                entry["sources"] = [observer_name]
                restored.append(entry)
            merged_ports = _merge_open_ports(merged_ports, restored)
            if observer_name == "naabu":
                naabu_last_observed_at = last_observed_at

        if naabu_last_observed_at is not None:
            cutoff_iso = naabu_last_observed_at.isoformat()
            merged_ports = _prune_stale_ports(merged_ports, cutoff_iso, now)

        # ── hosting_class / affinity_confirmation claims (planning#144 L3a) ──
        hosting = hosting_claim_value if isinstance(hosting_claim_value, dict) else {}

        # ── path-2 reads (still-authoritative asset_metadata) ─────────────
        eol_summary = metadata.get("eol_services")
        if not isinstance(eol_summary, dict):
            eol_summary = {}

        verdict = affinity_claim_value.get("verdict") if isinstance(affinity_claim_value, dict) else None
        if verdict == "confirmed_ours":
            estate = "claimed_ours"
        elif verdict == "rejected_shared_infra":
            estate = "not_ours"
        else:
            # No ownership signal (absent, unverified, ownership_unverifiable,
            # …) -> NULL. Do not invent an estate-unknown default here; it's
            # an open decision (planning#129).
            estate = None

        # ── provider_mx (recomputed from the L3b-1 record_type/content
        # columns, not asset_metadata) ─────────────────────────────────────
        asset_type = canonical.asset_type if canonical is not None else None
        if (
            asset_type == "dns_record"
            and canonical is not None
            and canonical.record_type == "MX"
            and canonical.content
        ):
            provider_mx = is_provider_managed_mx(canonical.content)
        else:
            provider_mx = False

        if provider_mx:
            probe_class = "no_probe"
        elif asset_type == "ip_address" and (
            asset_id in cidr_scoped_ids
            or (hosting.get("is_datacenter") is True and verdict == "confirmed_ours")
        ):
            probe_class = "direct_addressable"
        else:
            probe_class = "name_only"

        attributes: dict = {"probe_class": probe_class, "provider_mx": provider_mx}

        if naabu_last_observed_at is not None:
            attributes["naabu_last_scan_at"] = naabu_last_observed_at.isoformat()

        # ── cdn / cdn_domain: stopgap passthrough mirror of the still
        # asset_metadata-authoritative CDN boundary judgment (planning#144
        # L3b-2 user decision) — do NOT recompute the judgment here.
        if "cdn" in metadata:
            attributes["cdn"] = metadata["cdn"]
        if "cdn_domain" in metadata:
            attributes["cdn_domain"] = metadata["cdn_domain"]

        rows_to_upsert.append({
            "asset_canonical_id": asset_id,
            "open_ports": merged_ports,
            "estate": estate,
            "hosting": hosting,
            "eol_summary": eol_summary,
            "attributes": attributes,
            "projected_at": now,
        })

    if not rows_to_upsert:
        return

    stmt = pg_insert(AssetState.__table__).values(rows_to_upsert)
    stmt = stmt.on_conflict_do_update(
        index_elements=["asset_canonical_id"],
        set_={
            "open_ports": stmt.excluded.open_ports,
            "estate": stmt.excluded.estate,
            "hosting": stmt.excluded.hosting,
            "eol_summary": stmt.excluded.eol_summary,
            # Merge rather than overwrite so future keys (this slice only
            # ever writes probe_class) don't clobber each other; same key
            # from this run wins, matching every other merge in this module.
            "attributes": AssetState.__table__.c.attributes.op("||")(stmt.excluded.attributes),
            "projected_at": stmt.excluded.projected_at,
        },
    )
    db.execute(stmt)
