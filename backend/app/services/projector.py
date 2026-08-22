"""Synchronous, incremental claims -> asset_state projector (planning#143, L2
sub-slice C).

Reads `asset_claims` + `assets_canonical`'s own columns and folds them into
one projected row per asset in `asset_state`. As of planning#144 L3c-3 this
module no longer reads `assets_canonical.metadata` at all — every source is
either a claim or a real column:

  - `open_ports` <- `port_observation` claims, folded across observers.
  - `hosting` <- a `hosting_class` claim; `estate` <- an
    `affinity_confirmation` claim's `verdict` (L3a — hosting_classifier and
    shared_infra_verifier's asset_metadata TTL-caches moved to claims).
  - `eol_summary` <- the eol_enrichment observer's `eol_status` claim
    (L3c-3 — converted this slice; it was the last path-2 read here).
  - `attributes["cdn"]`/`["cdn_domain"]` <- a `cdn_boundary` claim (L3c-3 —
    replaces L3b-2's stopgap passthrough of the same keys out of the
    metadata column, which had no source surviving the L3c-4 drop).
  - `attributes["provider_mx"]` (and the `no_probe` half of `probe_class`
    that depends on it) is RECOMPUTED here from the
    `assets_canonical.record_type`/`.content` columns (L3b-1 promoted those
    to columns; L3b-2 stopped reading the transitional metadata mirror).
  - `attributes["naabu_last_scan_at"]` <- the naabu `port_observation`
    claim's `last_observed_at`, isoformatted — the same value used as the
    prune cutoff.

`asset_writer`'s merge loop still authors `asset_metadata` for the readers
L3c-3 has not reached, and L3c-4 removes that write along with the column.
Nothing in THIS module depends on it either way.

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


# ── asset_state read helpers (planning#144 L3c-3) ──────────────────────────
#
# Every backend reader repointed off `assets_canonical.metadata` in L3c-3
# comes through one of these, so the batching lives in one place instead of
# being re-derived (or forgotten) per caller.

def load_states(db: Session, asset_ids) -> dict[uuid.UUID, AssetState]:
    """Batch-load the `asset_state` row for each id in `asset_ids`, in one
    query (planning#144 L3c-3).

    The shared entry point for every backend reader that used to reach for
    `assets_canonical.metadata`: `open_ports`, `eol_summary`, `hosting`,
    `estate` and `attributes` all live here now. Ids with no projected row
    yet are simply absent from the result, so callers treat a miss the same
    way they used to treat an absent metadata key — `.get(id)` then fall
    back to empty.

    Read-only. Note this returns what the LAST `project()` call folded, so
    a caller that needs to see claims written earlier in the same scan
    pipeline must run after the projection pass that covers them — see the
    ordering comments in scan_executor's post-scan block.
    """
    ids = list(asset_ids)
    if not ids:
        return {}
    return {
        row.asset_canonical_id: row
        for row in db.query(AssetState).filter(AssetState.asset_canonical_id.in_(ids)).all()
    }


def open_ports_by_asset(db: Session, asset_ids) -> dict[uuid.UUID, list]:
    """`load_states` narrowed to just `open_ports` — the shape most of the
    repointed readers actually want. Ids with no state row (or an empty
    port list) map to `[]`."""
    return {
        asset_id: (state.open_ports or [])
        for asset_id, state in load_states(db, asset_ids).items()
    }


# ── standalone attributes upsert (planning#144 L3b-3) ──────────────────────

def merge_state_attributes(db: Session, asset_id: uuid.UUID, patch: dict) -> None:
    """Upsert `patch` into one asset's `asset_state.attributes`, JSONB `||`
    merged in — the same merge operator `project()`'s own upsert uses for
    `attributes` (see the on_conflict_do_update below). That's what lets the
    two compose safely: this function and the projector write disjoint keys
    (e.g. `dangling_dns_analyzer` writes `dangling_probe_at`, `project()`
    writes `probe_class`/`provider_mx`/...), so neither ever clobbers the
    other's key, regardless of which runs first or last.

    For callers outside the projector proper that need to persist a single
    attributes key straight to `asset_state` without doing a full claims
    projection (first user: `dangling_dns_analyzer`'s `dangling_probe_at`
    freshness stamp, moved off `asset_metadata` in this slice). On a fresh
    row — no projector run has touched this asset yet — the other NOT-NULL
    columns get their table defaults (`open_ports=[]`, `hosting={}`,
    `eol_summary={}`); `estate`/`projected_at` stay NULL until a real
    projection runs. Does not commit — same convention as `project()`.
    """
    stmt = pg_insert(AssetState.__table__).values(
        asset_canonical_id=asset_id,
        open_ports=[],
        hosting={},
        eol_summary={},
        attributes=patch,
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["asset_canonical_id"],
        set_={
            "attributes": AssetState.__table__.c.attributes.op("||")(stmt.excluded.attributes),
        },
    )
    db.execute(stmt)


# ── projector ────────────────────────────────────────────────────────────

def project(db: Session, asset_ids: set[uuid.UUID], now: datetime) -> None:
    """Fold claims + canonical columns into `asset_state`, one row per id.

    Read-only on `asset_claims` + `assets_canonical`; write-only on
    `asset_state`. Never writes `asset_metadata`. Idempotent — running twice
    over the same ids yields the same asset_state rows.

    Projects every id that still resolves to an `assets_canonical` row —
    skipping only ids that don't (deleted mid-scan). Before planning#144
    L3c-3 this also skipped ids with no claims AND no asset_metadata; with
    the metadata read gone that guard would have started dropping
    identity-only DNS records, which carry no port claim but whose
    `probe_class`/`provider_mx` are derived from their columns alone and so
    always have something to project.
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

    # Single-value claims, batch-loaded up front like port_observation above
    # rather than a get_current_claim() call per asset in the loop below.
    #
    # Three of the four are single-owner TTL caches or service outputs, so
    # they are pinned to the observer that owns them (planning#144 L3a for
    # hosting_class/affinity_confirmation, L3c-3 for eol_status) — a claim of
    # that type from anyone else is not the value this projection means.
    # cdn_boundary is deliberately NOT pinned: the CDN judgment is made by
    # whichever discovery observer resolved the CNAME (dns_resolve today,
    # dns_records or a future resolver tomorrow), so it is taken from any
    # observer, most-recently-observed winning.
    _OWNED_CLAIMS = {
        "hosting_class": "hosting_classifier",
        "affinity_confirmation": "shared_infra_verifier",
        "eol_status": "eol_enrichment",
    }
    observer_name_by_id = {
        observer_id: name for observer_id, name in db.query(Observer.id, Observer.name).all()
    }
    hosting_class_by_asset: dict[uuid.UUID, dict] = {}
    affinity_confirmation_by_asset: dict[uuid.UUID, dict] = {}
    eol_status_by_asset: dict[uuid.UUID, dict] = {}
    cdn_boundary_by_asset: dict[uuid.UUID, dict] = {}
    _cdn_seen_at: dict[uuid.UUID, datetime] = {}
    single_claim_rows = (
        db.query(
            AssetClaim.asset_canonical_id,
            AssetClaim.claim_type,
            AssetClaim.claim_value,
            AssetClaim.observer_id,
            AssetClaim.last_observed_at,
        )
        .filter(
            AssetClaim.asset_canonical_id.in_(asset_ids),
            AssetClaim.claim_type.in_(list(_OWNED_CLAIMS) + ["cdn_boundary"]),
        )
        .all()
    )
    for asset_id, claim_type, claim_value, observer_id, last_observed_at in single_claim_rows:
        if claim_type == "cdn_boundary":
            previous = _cdn_seen_at.get(asset_id)
            if previous is None or last_observed_at > previous:
                _cdn_seen_at[asset_id] = last_observed_at
                cdn_boundary_by_asset[asset_id] = claim_value
            continue
        if observer_name_by_id.get(observer_id) != _OWNED_CLAIMS[claim_type]:
            continue
        if claim_type == "hosting_class":
            hosting_class_by_asset[asset_id] = claim_value
        elif claim_type == "affinity_confirmation":
            affinity_confirmation_by_asset[asset_id] = claim_value
        elif claim_type == "eol_status":
            eol_status_by_asset[asset_id] = claim_value

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
        hosting_claim_value = hosting_class_by_asset.get(asset_id)
        affinity_claim_value = affinity_confirmation_by_asset.get(asset_id)
        eol_claim_value = eol_status_by_asset.get(asset_id)
        cdn_claim_value = cdn_boundary_by_asset.get(asset_id)

        if canonical is None:
            continue  # id doesn't resolve to a row (deleted mid-scan)

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

        # ── eol_summary: the eol_enrichment observer's `eol_status` claim
        # (planning#144 L3c-3 — the last path-2 asset_metadata read in this
        # module, now gone). The claim carries a LIST of per-port EOL
        # records under `services`, despite the column being named
        # eol_summary; L3c-2 found the old passthrough guard here checking
        # isinstance(dict) and silently discarding every real list into {}.
        eol_summary = eol_claim_value.get("services") if isinstance(eol_claim_value, dict) else None
        if not isinstance(eol_summary, list):
            eol_summary = []

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

        # ── cdn / cdn_domain: the discovery observer's `cdn_boundary` claim
        # (planning#144 L3c-3). This replaces the L3b-2 stopgap, which
        # mirrored the keys straight out of the asset_metadata column — a
        # passthrough that would have had no source left once L3c-4 drops
        # that column. Still NOT recomputed here: the boundary judgment
        # belongs to dns_resolve, this only projects it. #147 replaces the
        # whole annotation with a real CNAME -> third-party edge.
        if isinstance(cdn_claim_value, dict):
            for attr_key in ("cdn", "cdn_domain"):
                if attr_key in cdn_claim_value:
                    attributes[attr_key] = cdn_claim_value[attr_key]

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
