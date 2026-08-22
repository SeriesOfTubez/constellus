"""Claims -> `asset_metadata`-shaped dict reconstruction (planning#144 L3c-2).

Lifted out of `app/api/assets.py` in L3c-3, unchanged in behaviour. It lives
in `app/services` now because the API serializer is no longer its only
caller: `api/edges.py`'s node-summary panel and `services/tag_service.py`'s
`metadata.<key>` rule fields both need the same reconstruction, and neither
should be importing out of an API router to get it.

`api/assets.py` still owns `_serialize_asset` and `_filter_stale_ports` and
re-exports `load_bridge_sources` / `_bridge_metadata` under their original
names, so existing callers and tests are unaffected.
"""

import uuid
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.claim import AssetClaim
from app.models.observer import Observer
from app.services import claim_emitter


# ── claims-bridge (planning#144 L3c-2) ──────────────────────────────────────
#
# `_serialize_asset` used to return `row.asset_metadata` verbatim. Now that
# claim_emitter/projector (L2/L3) have decomposed asset_metadata's producers
# into asset_claims + asset_state, this reconstructs the same dict shape from
# those sources instead — the exact inverse of claim_emitter.emit_claims'
# Table 1 mapping — so a later slice can drop the asset_metadata column
# without changing the API response. The column still exists and the merge
# loop (asset_writer._upsert_canonical_batch) still writes it; this bridge
# just stops the serializer from READING it.
#
# A metadata key is included only when its source exists (claim/state key
# present), matching asset_metadata's own sparse-key shape — the emitters
# never write a key for data that wasn't observed.

EMPTY_BRIDGE_SOURCES: dict = {
    "state": None,
    "by_type": {},
    "ports_by_observer": {},
    "observers": [],
    "shodan_last_observed_at": None,
}

# `asset_metadata["sources"]` has only ever meant "which scan/discovery/
# connector observer produced this asset" — every real writer of that key
# (naabu, tlsx, httpx, banner_grab, dns_records, dnsrecon, subfinder,
# bruteforce, cert_transparency, shodan, cloudflare) is one of these three
# Observer.kind values (verified against every literal `"sources": [...]`
# write in app/connectors + app/services). `verify`/`enrich`-kind observers
# (hosting_classifier, eol_enrichment, cpe_normalizer, shared_infra_verifier,
# domain_affinity, dangling_dns_analyzer) write claims about an asset but
# have NEVER contributed to its `sources` — they read/modify an
# already-persisted asset directly, outside write_assets' DiscoveredAsset
# path, and asset_writer's merge loop never puts them there. Restricting
# the bridge's `sources` to these kinds keeps it faithful to that existing
# meaning; the broader "every claim's observer" reading would silently pull
# derived-judgment observers into a field the frontend (and any consumer
# treating `sources` as "who observed this asset exists") has never seen
# them in.
_SOURCES_OBSERVER_KINDS: frozenset[str] = frozenset({"scan", "discovery", "connector"})


def load_bridge_sources(db: Session, asset_ids: list[uuid.UUID]) -> dict[uuid.UUID, dict]:
    """Batch-load `_bridge_metadata`'s per-asset sources for `asset_ids`:
    one `asset_state` query + one `asset_claims` (joined to `observers` for
    the name/kind) query, regardless of how many asset_ids are passed in.
    Callers (list_assets / get_asset) must call this once per request and
    pass the per-asset slice into `_serialize_asset` — no per-row query
    belongs in the serializer itself.

    Returns {asset_id: {"state", "by_type", "ports_by_observer", "observers",
    "shodan_last_observed_at"}} for every id in `asset_ids` (present with
    empty/None defaults even if the asset has no state row or claims yet).
    """
    result: dict[uuid.UUID, dict] = {
        aid: {
            "state": None,
            "by_type": {},
            "ports_by_observer": {},
            "observers": set(),
            "shodan_last_observed_at": None,
        }
        for aid in asset_ids
    }
    if not asset_ids:
        return result

    for state in db.query(AssetState).filter(AssetState.asset_canonical_id.in_(asset_ids)).all():
        result[state.asset_canonical_id]["state"] = state

    claim_rows = (
        db.query(
            AssetClaim.asset_canonical_id,
            AssetClaim.claim_type,
            AssetClaim.claim_value,
            AssetClaim.last_observed_at,
            Observer.name,
            Observer.kind,
        )
        .join(Observer, AssetClaim.observer_id == Observer.id)
        .filter(AssetClaim.asset_canonical_id.in_(asset_ids))
        .all()
    )

    # by_type keeps only the most-recently-observed row per (asset, claim_type)
    # — the same claim_type can theoretically be written by more than one
    # observer over an asset's lifetime (emit_claims attributes each batch's
    # claims to that batch's resolved observer), so this picks a single
    # current value the same way a fresh re-observation would in
    # asset_metadata (last write wins). port_observation is excluded from
    # this collapse — every observer's port list is kept separately in
    # `ports_by_observer`, since shodan_ports needs specifically the
    # shodan-observer's own claim, not a collapsed/merged view.
    latest_at: dict[tuple, datetime] = {}
    for asset_id, claim_type, claim_value, last_observed_at, observer_name, observer_kind in claim_rows:
        bucket = result[asset_id]
        if observer_kind in _SOURCES_OBSERVER_KINDS:
            bucket["observers"].add(observer_name)

        if claim_type == claim_emitter._PORT_OBSERVATION_CLAIM_TYPE:
            bucket["ports_by_observer"][observer_name] = claim_value
            continue

        key = (asset_id, claim_type)
        if key not in latest_at or last_observed_at > latest_at[key]:
            latest_at[key] = last_observed_at
            bucket["by_type"][claim_type] = claim_value

        if claim_type == claim_emitter._SHODAN_HOST_CLAIM_TYPE:
            current = bucket["shodan_last_observed_at"]
            if current is None or last_observed_at > current:
                bucket["shodan_last_observed_at"] = last_observed_at

    for bucket in result.values():
        bucket["observers"] = sorted(bucket["observers"])

    return result


def bridge_metadata(canonical: AssetCanonical, state: AssetState | None, claims: dict) -> dict:
    """Reconstruct `asset_metadata` from claims-layer sources — the inverse
    of claim_emitter.emit_claims' Table 1 mapping, plus the projector's
    asset_state derivations. `claims` is one asset's slice of
    `load_bridge_sources`' return value.

    Driven directly off claim_emitter's own key maps (_SIMPLE_KEY_CLAIMS /
    _SHODAN_HOST_KEYS / _CT_KEYS / the spf/port constants) rather than a
    hand-duplicated copy, so every value-key those maps carry has a
    reconstruction path here by construction, and a future addition to
    claim_emitter's Table 1 doesn't silently go unbridged.
    """
    md: dict = {}

    # identity — promoted to columns by L3b-1
    if canonical.record_type is not None:
        md["record_type"] = canonical.record_type
    if canonical.content is not None:
        md["content"] = canonical.content

    # asset_state projections
    if state is not None:
        if state.open_ports:
            md["open_ports"] = state.open_ports
        if state.eol_summary:
            md["eol_services"] = state.eol_summary
        attrs = state.attributes or {}
        if attrs.get("provider_mx"):
            md["provider_mx"] = attrs["provider_mx"]
        for attr_key in ("cdn", "cdn_domain", "naabu_last_scan_at"):
            if attr_key in attrs:
                md[attr_key] = attrs[attr_key]

    # sources: distinct scan/discovery/connector-kind observer names across
    # every claim this asset has (not just the ones individually bridged
    # below) — restricted to those three Observer.kind values so this
    # matches asset_metadata["sources"]'s existing meaning; see
    # _SOURCES_OBSERVER_KINDS.
    if claims.get("observers"):
        md["sources"] = sorted(claims["observers"])

    by_type: dict = claims.get("by_type", {})

    # dns_ttl / proxy_state / cloudflare_zone / mx_preference / host_tarpit /
    # reverse_hostname — every claim_emitter._SIMPLE_KEY_CLAIMS entry.
    for meta_key, (claim_type, value_key) in claim_emitter._SIMPLE_KEY_CLAIMS.items():
        claim_value = by_type.get(claim_type)
        if claim_value and value_key in claim_value:
            md[meta_key] = claim_value[value_key]

    # spf: the whole parsed dict rides straight through as claim_value.
    spf = by_type.get(claim_emitter._SPF_CLAIM_TYPE)
    if spf:
        md[claim_emitter._SPF_METADATA_KEY] = spf

    # ct_cert_issuance -> not_before / not_after / issuer
    ct = by_type.get(claim_emitter._CT_CLAIM_TYPE)
    if ct:
        for meta_key, value_key in claim_emitter._CT_KEYS.items():
            if value_key in ct:
                md[meta_key] = ct[value_key]

    # shodan_host -> shodan_org/os/country/isp/asn/tags/last_update
    shodan_host = by_type.get(claim_emitter._SHODAN_HOST_CLAIM_TYPE)
    if shodan_host:
        for meta_key, value_key in claim_emitter._SHODAN_HOST_KEYS.items():
            if value_key in shodan_host and shodan_host[value_key] is not None:
                md[meta_key] = shodan_host[value_key]
        shodan_last_observed_at = claims.get("shodan_last_observed_at")
        if shodan_last_observed_at is not None:
            md["shodan_last_seen"] = shodan_last_observed_at.isoformat()

    # shodan_ports: the shodan-observer's own port_observation claim, bare
    # port numbers only (distinct from `open_ports`, which is the merged
    # cross-observer view projected into asset_state).
    shodan_ports_claim = claims.get("ports_by_observer", {}).get("shodan")
    if shodan_ports_claim:
        ports = shodan_ports_claim.get("ports") or []
        port_numbers = [p["port"] for p in ports if isinstance(p, dict) and "port" in p]
        if port_numbers:
            md["shodan_ports"] = port_numbers

    return md
