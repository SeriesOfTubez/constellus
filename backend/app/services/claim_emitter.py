"""Claim emission from the batch writer (planning#143, L2 sub-slice A) +
single-claim TTL-cache helpers for enrichment services (planning#144, L3a).

Strangler-fig, additive: decomposes each incoming DiscoveredAsset's
asset_metadata into asset_claims rows per Table 1 of the L2 key->claim
mapping, alongside the existing asset_metadata merge in
_upsert_canonical_batch (asset_writer.py). The writer keeps authoring
asset_metadata exactly as before; nothing reads asset_claims yet. See:

  - the key->claim mapping (authoritative): L2 metadata-key -> claim
    mapping doc, Table 1 + the envelope/observer-derivation/
    change-detection sections (planning#143).
  - app/models/claim.py (AssetClaim, ClaimHistory, CLAIM_TYPES) and
    app/models/observer.py (Observer) for the L1 schema this writes to.

Grain:
  - Every claim type except port_observation is a single composite dict
    built from a fixed set of source keys present on one DiscoveredAsset,
    attributed to that asset's single resolved observer.
  - port_observation is one claim per (asset, observer): open_ports[]
    entries are grouped by their own per-entry `sources` list (each entry
    may name more than one source, e.g. naabu-confirmed-by-nmap), so a
    single asset's open_ports patch can fan out into multiple observers'
    claims. `sources` (and the per-entry `naabu_tier`, which is envelope
    data) are stripped from the stored port entries.

Observer resolution: DiscoveredAsset.observer if set, else the single
entry of asset_metadata["sources"]. A name not present in the seeded
`observers` table causes that claim (or, for port_observation, just that
source's group) to be skipped with a single warning per unknown name per
call — defensive, shouldn't happen for seeded producers.

Change-detection, per (asset, observer, claim_type):
  - no existing row -> INSERT asset_claims + INSERT claim_history.
  - existing, value differs (JSON-equal comparison) -> UPDATE asset_claims
    + INSERT claim_history.
  - existing, value identical -> UPDATE asset_claims.last_observed_at only.

Concurrency: called from write_assets() in the same transaction as
_upsert_canonical_batch, after it. That function already takes a
`FOR UPDATE` lock on the touched assets_canonical rows, which serializes
any concurrent writer touching the same asset before it reaches this
function too — so no separate locking is taken here.

`get_current_claim` / `upsert_single_claim` (bottom of this module) are a
separate, unrelated entry point: a single-claim analogue of the same
change-detection rule, for services (hosting_classifier,
shared_infra_verifier) that read-modify-write one (asset, observer,
claim_type) claim as a TTL cache on an already-persisted asset row, outside
this batch path entirely.
"""

import json
import logging
import uuid
from datetime import datetime

from sqlalchemy.orm import Session

from app.connectors.base import DiscoveredAsset
from app.models.claim import AssetClaim, ClaimHistory
from app.models.observer import Observer

log = logging.getLogger(__name__)

_TargetKey = tuple[uuid.UUID, uuid.UUID, str]  # (asset_canonical_id, observer_id, claim_type)

# ── Table 1: metadata key -> (claim_type, claim_value key) ──────────────────
# Single-key claims: one metadata key maps straight into a one-field
# claim_value dict, attributed to the asset's resolved observer.
_SIMPLE_KEY_CLAIMS: dict[str, tuple[str, str]] = {
    "ttl": ("dns_ttl", "ttl"),
    "proxied": ("proxy_state", "proxied"),
    "zone_id": ("cloudflare_zone", "zone_id"),
    "mx_preference": ("mx_preference", "mx_preference"),
    "tarpit_detected": ("host_tarpit", "tarpit_detected"),
    "shodan_hostnames": ("reverse_hostname", "hostnames"),
}

# spf carries the full parsed dict as claim_value directly (no wrapper key).
_SPF_METADATA_KEY = "spf"
_SPF_CLAIM_TYPE = "spf_policy"

# Composite claims: several metadata keys combine into one claim_value dict.
_CT_KEYS: dict[str, str] = {"not_before": "not_before", "not_after": "not_after", "issuer": "issuer"}
_CT_CLAIM_TYPE = "ct_cert_issuance"

_SHODAN_HOST_KEYS: dict[str, str] = {
    "shodan_org": "org",
    "shodan_os": "os",
    "shodan_country": "country",
    "shodan_isp": "isp",
    "shodan_asn": "asn",
    "shodan_tags": "tags",
    "shodan_last_update": "last_update",
}
_SHODAN_HOST_CLAIM_TYPE = "shodan_host"

# cdn / cdn_domain: dns_resolve's CDN-boundary judgment on a CNAME hop it
# declined to follow (discovery/dns_resolve.py). Composite like _CT_KEYS —
# `cdn` is the flag, `cdn_domain` the edge that matched. Emitted as a claim
# as of L3c-3 (planning#144) so the judgment survives the asset_metadata
# column drop; the projector previously mirrored it out of the persisted
# column as an explicit stopgap. #147 replaces the whole annotation with a
# real CNAME -> third-party edge and can retire this then.
_CDN_KEYS: dict[str, str] = {"cdn": "cdn", "cdn_domain": "cdn_domain"}
_CDN_CLAIM_TYPE = "cdn_boundary"

# third_party: the customer->third-party CNAME boundary TARGET, captured as a
# context node by dns_resolve._third_party_node (planning#147). Distinct from
# _CDN_KEYS above, which annotates the owned record on the near side of the
# same boundary — this one is the far side. The claim is what lets the
# projector derive estate=not_ours / probe_class=no_probe from an observation
# with an observer and a timestamp, rather than asserting it at read time.
_THIRD_PARTY_METADATA_KEY = "third_party"
_THIRD_PARTY_CLAIM_TYPE = "third_party_dependency"
_THIRD_PARTY_VALUE_KEYS = ("relationship", "discovered_via")

# cloud_inventory: credentialed proof the address belongs to a resource in a
# cloud account we control (planning#118a, connectors/wiz.py). The connector
# hands over a fully-formed claim value under one key rather than scattering
# its parts across metadata keys for this module to reassemble — the claim's
# shape is defined by planning#142 D1 (`confirmed` / `authorised_names` /
# `evidence_ref`), not by a metadata vocabulary, and every other producer of
# this claim type (cloudlist, a future cloud connector) has to satisfy that
# same contract. So this accumulator validates rather than constructs.
#
# Note the asymmetry with the other accumulators here: the only value this
# claim type may carry is an affirmative one. A `confirmed` that is not
# exactly True emits NOTHING, rather than a claim recording a negative —
# because a cloud inventory that has not heard of an address has not thereby
# established the address is not ours (see wiz._claim_from_nodes). The
# absence layer (planning#145) represents "looked, found nothing", and it
# does so by reading a claim's ABSENCE. Writing a row here would defeat it.
_CLOUD_INVENTORY_METADATA_KEY = "cloud_inventory"
_CLOUD_INVENTORY_CLAIM_TYPE = "cloud_inventory"
# Keys that move to the evidence column instead of riding in claim_value.
# Both are churny in a way ownership is not: `evidence_ref` carries the Wiz
# exposure ids that matched, and `exposure_count` how many — a firewall rule
# added or removed changes both while the answer to "is this address ours"
# stays exactly the same. Left in claim_value they would make every such
# edit look like a value change to `_upsert_claims`' JSON-equality check and
# append a claim_history row saying ownership changed, which it did not.
_CLOUD_INVENTORY_EVIDENCE_KEYS: tuple[str, ...] = ("evidence_ref", "exposure_count")

_PORT_OBSERVATION_CLAIM_TYPE = "port_observation"
# Per-entry keys that are envelope data, not part of the stored port claim value.
_PORT_ENTRY_ENVELOPE_KEYS = ("sources", "naabu_tier")

# Base-provenance claim type (L3c-2a, planning#144): recorded for EVERY
# asset+observer pair whose asset-level observer resolves, regardless of
# whether any other Table 1 key was present. Constant `{}` value means
# change-detection (_upsert_claims) treats every re-observation as a cheap
# last_observed_at bump, never a new claim_history row after the first.
# This exists so identity-only observers (dns_resolve/dns_records writing
# just {sources, record_type, content}, which trip none of the other
# _accumulate_* helpers below) still leave a trace in asset_claims — see
# the L3c-2 serializer bridge's `sources` reconstruction in api/assets.py.
_OBSERVATION_CLAIM_TYPE = "observation"


def emit_claims(
    db: Session,
    assets: list[DiscoveredAsset],
    canonical_map: dict[tuple, uuid.UUID],
    now: datetime,
) -> None:
    """Decompose `assets`' asset_metadata into asset_claims rows.

    Mirrors write_assets' canonical-key resolution via `_canonical_key`
    (imported lazily from asset_writer to avoid a module-load cycle — see
    the local import below). Call this after canonical rows are upserted
    (canonical_map populated) and before commit.
    """
    if not assets:
        return

    observer_ids = _load_observer_ids(db)
    if not observer_ids:
        return

    # Lazy import: asset_writer imports emit_claims from this module inside
    # write_assets() (a local import there too), so importing it back here
    # at module load time would be a circular import. By the time this
    # function actually runs, asset_writer has already fully executed its
    # module body, so this import is safe.
    from app.services.asset_writer import _canonical_key

    targets: dict[_TargetKey, dict] = {}
    warned_observers: set[str] = set()

    for asset in assets:
        meta = asset.asset_metadata or {}
        canonical_id = canonical_map.get(
            _canonical_key(asset.asset_type, asset.value, meta.get("record_type"), meta.get("content"))
        )
        if canonical_id is None:
            continue
        if not meta:
            continue

        # Non-port claims: attributed to this asset's single resolved observer.
        observer_name = asset.observer or _single_source(meta.get("sources"))
        if observer_name:
            observer_id = observer_ids.get(observer_name)
            if observer_id is None:
                _warn_unknown_observer_once(observer_name, warned_observers)
            else:
                _accumulate_observation_claim(targets, canonical_id, observer_id)
                _accumulate_simple_claims(targets, canonical_id, observer_id, meta)
                _accumulate_spf_claim(targets, canonical_id, observer_id, meta)
                _accumulate_ct_claim(targets, canonical_id, observer_id, meta)
                _accumulate_shodan_host_claim(targets, canonical_id, observer_id, meta)
                _accumulate_cdn_claim(targets, canonical_id, observer_id, meta)
                _accumulate_third_party_claim(targets, canonical_id, observer_id, meta)
                _accumulate_cloud_inventory_claim(targets, canonical_id, observer_id, meta)

        # port_observation: attributed per-entry by each port's own `sources`,
        # independent of (and possibly broader than) the asset-level observer
        # resolved above.
        _accumulate_port_observation(targets, canonical_id, observer_ids, meta, warned_observers)

    if targets:
        _upsert_claims(db, targets, now)


# ── observer resolution ──────────────────────────────────────────────────────

def _load_observer_ids(db: Session) -> dict[str, uuid.UUID]:
    return {name: observer_id for observer_id, name in db.query(Observer.id, Observer.name).all()}


def _single_source(sources) -> str | None:
    if isinstance(sources, list) and len(sources) == 1:
        return sources[0]
    if isinstance(sources, str) and sources:
        return sources
    return None


def _warn_unknown_observer_once(observer_name: str, warned_observers: set[str]) -> None:
    if observer_name in warned_observers:
        return
    warned_observers.add(observer_name)
    log.warning(
        "claim_emitter: unknown observer %r — skipping claim emission attributed to it",
        observer_name,
    )


# ── per-key accumulation into the batch's target map ─────────────────────────

def _accumulate_observation_claim(
    targets: dict[_TargetKey, dict],
    canonical_id: uuid.UUID,
    observer_id: uuid.UUID,
) -> None:
    """Base-provenance claim: this (asset, observer) pair was observed, full
    stop. Always {} — see _OBSERVATION_CLAIM_TYPE docstring above."""
    _merge_target(targets, (canonical_id, observer_id, _OBSERVATION_CLAIM_TYPE), {}, {})


def _accumulate_simple_claims(
    targets: dict[_TargetKey, dict],
    canonical_id: uuid.UUID,
    observer_id: uuid.UUID,
    meta: dict,
) -> None:
    for meta_key, (claim_type, value_key) in _SIMPLE_KEY_CLAIMS.items():
        if meta_key not in meta or meta[meta_key] is None:
            continue
        _merge_target(targets, (canonical_id, observer_id, claim_type), {value_key: meta[meta_key]}, {})


def _accumulate_spf_claim(
    targets: dict[_TargetKey, dict],
    canonical_id: uuid.UUID,
    observer_id: uuid.UUID,
    meta: dict,
) -> None:
    spf = meta.get(_SPF_METADATA_KEY)
    if not isinstance(spf, dict):
        return
    _merge_target(targets, (canonical_id, observer_id, _SPF_CLAIM_TYPE), dict(spf), {})


def _accumulate_ct_claim(
    targets: dict[_TargetKey, dict],
    canonical_id: uuid.UUID,
    observer_id: uuid.UUID,
    meta: dict,
) -> None:
    if not any(k in meta for k in _CT_KEYS):
        return
    value = {value_key: meta.get(meta_key, "") for meta_key, value_key in _CT_KEYS.items()}
    evidence = {}
    ct_source = meta.get("ct_source")
    if ct_source:
        evidence["sub_source"] = ct_source
    _merge_target(targets, (canonical_id, observer_id, _CT_CLAIM_TYPE), value, evidence)


def _accumulate_shodan_host_claim(
    targets: dict[_TargetKey, dict],
    canonical_id: uuid.UUID,
    observer_id: uuid.UUID,
    meta: dict,
) -> None:
    present = {mk: vk for mk, vk in _SHODAN_HOST_KEYS.items() if mk in meta and meta[mk] is not None}
    if not present:
        return
    value = {vk: meta[mk] for mk, vk in present.items()}
    _merge_target(targets, (canonical_id, observer_id, _SHODAN_HOST_CLAIM_TYPE), value, {})


def _accumulate_cdn_claim(
    targets: dict[_TargetKey, dict],
    canonical_id: uuid.UUID,
    observer_id: uuid.UUID,
    meta: dict,
) -> None:
    """CDN-boundary judgment (planning#144 L3c-3). Keyed off `cdn` alone:
    `cdn_domain` is the matched edge and is meaningless without the flag,
    while `cdn` without a domain is still a usable boundary signal. A
    falsy/absent `cdn` emits nothing — matching every other accumulator
    here, and matching the pre-claims behaviour where dns_resolve only ever
    SET the key (the merge loop never cleared it either)."""
    if not meta.get(_CDN_KEYS["cdn"]):
        return
    value = {
        value_key: meta[meta_key]
        for meta_key, value_key in _CDN_KEYS.items()
        if meta.get(meta_key) is not None
    }
    _merge_target(targets, (canonical_id, observer_id, _CDN_CLAIM_TYPE), value, {})


def _accumulate_third_party_claim(
    targets: dict[_TargetKey, dict],
    canonical_id: uuid.UUID,
    observer_id: uuid.UUID,
    meta: dict,
) -> None:
    """Third-party dependency node (planning#147). Keyed off a truthy
    `third_party` flag; the descriptive keys ride along in claim_value when
    present so the relationship axis is recorded with the observation rather
    than re-derived later."""
    if not meta.get(_THIRD_PARTY_METADATA_KEY):
        return
    value = {k: meta[k] for k in _THIRD_PARTY_VALUE_KEYS if meta.get(k) is not None}
    _merge_target(targets, (canonical_id, observer_id, _THIRD_PARTY_CLAIM_TYPE), value, {})


def _accumulate_cloud_inventory_claim(
    targets: dict[_TargetKey, dict],
    canonical_id: uuid.UUID,
    observer_id: uuid.UUID,
    meta: dict,
) -> None:
    """Credentialed cloud-inventory ownership proof (planning#118a).

    Unlike the accumulators above, this one does not assemble a claim value
    out of metadata keys — the producer supplies the whole D1 envelope under
    a single key and this validates it. Two rules, both load-bearing:

      * `confirmed` must be exactly `True`. Anything else — False, absent,
        a truthy non-True value — emits nothing at all. `cloud_inventory`
        promotes an asset to `estate = "proven_ours"`, which outranks EVERY
        other estate rule in the projector, so the bar for writing one is a
        producer that affirmatively says yes, not one that merely failed to
        say no.
      * `evidence` is split out of the claim value and stored in the
        evidence column, where the rest of the layer keeps provenance,
        rather than being left inline in `claim_value` where the projector's
        JSON-equality change detection would treat a re-observation with new
        exposure ids as a value CHANGE and append a spurious history row.
    """
    payload = meta.get(_CLOUD_INVENTORY_METADATA_KEY)
    if not isinstance(payload, dict):
        return
    if payload.get("confirmed") is not True:
        return

    value = {k: v for k, v in payload.items() if k not in _CLOUD_INVENTORY_EVIDENCE_KEYS}
    evidence = {k: payload[k] for k in _CLOUD_INVENTORY_EVIDENCE_KEYS if k in payload}
    _merge_target(targets, (canonical_id, observer_id, _CLOUD_INVENTORY_CLAIM_TYPE), value, evidence)


def _accumulate_port_observation(
    targets: dict[_TargetKey, dict],
    canonical_id: uuid.UUID,
    observer_ids: dict[str, uuid.UUID],
    meta: dict,
    warned_observers: set[str],
) -> None:
    """Group open_ports[] (plus bare shodan_ports[] ints) by observer.

    One claim per (asset, observer) — L1's unique key is (asset, observer,
    claim_type), so an observer's whole port list rides in one claim_value,
    not one claim per port.
    """
    groups: dict[str, list[dict]] = {}

    open_ports = meta.get("open_ports")
    if isinstance(open_ports, list):
        for entry in open_ports:
            if not isinstance(entry, dict):
                continue
            sources = entry.get("sources")
            source_names = sources if isinstance(sources, list) else ([sources] if sources else [])
            # "nmap" is naabu's own verification sub-tool, not a seeded
            # observer in its own right — naabu's claim already carries the
            # nmap-enriched entry. Drop it here so it doesn't fan out into
            # its own claim group and trip the unknown-observer warning.
            source_names = [s for s in source_names if s != "nmap"]
            if not source_names:
                continue
            stripped = {k: v for k, v in entry.items() if k not in _PORT_ENTRY_ENVELOPE_KEYS}
            for source_name in source_names:
                groups.setdefault(source_name, []).append(dict(stripped))

    # shodan_ports: bare port ints alongside the richer open_ports entries.
    # Fold in any port not already covered so no signal is silently dropped,
    # without duplicating a port already carried by an open_ports entry.
    shodan_ports = meta.get("shodan_ports")
    if isinstance(shodan_ports, list):
        shodan_group = groups.setdefault("shodan", [])
        existing_ports = {e.get("port") for e in shodan_group}
        for p in shodan_ports:
            if isinstance(p, int) and p not in existing_ports:
                shodan_group.append({"port": p, "protocol": "tcp"})
                existing_ports.add(p)

    for source_name, entries in groups.items():
        if not entries:
            continue
        observer_id = observer_ids.get(source_name)
        if observer_id is None:
            _warn_unknown_observer_once(source_name, warned_observers)
            continue

        evidence = {}
        if source_name == "naabu" and meta.get("naabu_tier"):
            evidence["naabu_tier"] = meta["naabu_tier"]

        claim_value = {
            "ports": sorted(
                entries, key=lambda e: e.get("port") if isinstance(e.get("port"), int) else 0
            )
        }
        _merge_target(
            targets, (canonical_id, observer_id, _PORT_OBSERVATION_CLAIM_TYPE),
            claim_value, evidence, merge_ports=True,
        )


def _merge_target(
    targets: dict[_TargetKey, dict],
    key: _TargetKey,
    claim_value: dict,
    evidence: dict,
    *,
    merge_ports: bool = False,
) -> None:
    """Fold a new contribution into the batch's running target map.

    Only matters when two DiscoveredAsset entries in the SAME batch
    contribute to the same (asset, observer, claim_type) — rare, but keeps
    later contributions from silently clobbering earlier ones instead of
    combining them.
    """
    existing = targets.get(key)
    if existing is None:
        targets[key] = {"claim_value": claim_value, "evidence": evidence}
        return

    if merge_ports:
        by_port = {
            e["port"]: e for e in existing["claim_value"].get("ports", [])
            if isinstance(e, dict) and isinstance(e.get("port"), int)
        }
        for e in claim_value.get("ports", []):
            if isinstance(e, dict) and isinstance(e.get("port"), int):
                by_port[e["port"]] = {**by_port.get(e["port"], {}), **e}
        existing["claim_value"] = {"ports": sorted(by_port.values(), key=lambda x: x["port"])}
    else:
        existing["claim_value"] = {**existing["claim_value"], **claim_value}
    existing["evidence"] = {**existing["evidence"], **evidence}


# ── upsert with change-detection ──────────────────────────────────────────────

def _upsert_claims(db: Session, targets: dict[_TargetKey, dict], now: datetime) -> None:
    canonical_ids = {k[0] for k in targets}
    observer_ids = {k[1] for k in targets}
    claim_types = {k[2] for k in targets}

    existing_rows = (
        db.query(AssetClaim)
        .filter(
            AssetClaim.asset_canonical_id.in_(canonical_ids),
            AssetClaim.observer_id.in_(observer_ids),
            AssetClaim.claim_type.in_(claim_types),
        )
        .all()
    )
    existing_by_key: dict[_TargetKey, AssetClaim] = {
        (r.asset_canonical_id, r.observer_id, r.claim_type): r for r in existing_rows
    }

    history_rows: list[ClaimHistory] = []

    for key, data in targets.items():
        canonical_id, observer_id, claim_type = key
        claim_value = data["claim_value"]
        evidence = data["evidence"]
        existing = existing_by_key.get(key)

        if existing is None:
            # id omitted: AssetClaim/ClaimHistory both carry
            # server_default=uuidv7() (L1 migration 0039) — let the DB assign
            # it rather than generating a uuid4 app-side. No refresh needed;
            # nothing here reads the assigned id back before commit.
            db.add(AssetClaim(
                asset_canonical_id=canonical_id,
                observer_id=observer_id,
                claim_type=claim_type,
                claim_value=claim_value,
                evidence=evidence,
                first_observed_at=now,
                last_observed_at=now,
            ))
            history_rows.append(ClaimHistory(
                asset_canonical_id=canonical_id,
                observer_id=observer_id,
                claim_type=claim_type,
                claim_value=claim_value,
                evidence=evidence,
                changed_at=now,
            ))
            continue

        if _json_equal(existing.claim_value, claim_value):
            existing.last_observed_at = now
            continue

        existing.claim_value = claim_value
        existing.evidence = evidence
        existing.last_observed_at = now
        history_rows.append(ClaimHistory(
            asset_canonical_id=canonical_id,
            observer_id=observer_id,
            claim_type=claim_type,
            claim_value=claim_value,
            evidence=evidence,
            changed_at=now,
        ))

    if history_rows:
        db.add_all(history_rows)
    db.flush()


def _json_equal(a: dict, b: dict) -> bool:
    """Canonical JSON comparison so key-order noise doesn't count as a change."""
    return json.dumps(a, sort_keys=True, default=str) == json.dumps(b, sort_keys=True, default=str)


# ── single-claim helpers (planning#144 L3a) ─────────────────────────────────
#
# For enrichment services (hosting_classifier, shared_infra_verifier) that
# read-modify-write a single (asset, observer, claim_type) claim as a TTL
# cache, on an already-persisted asset row, outside write_assets'/
# emit_claims' batch path. Same change-detection rule as _upsert_claims
# above (reusing _json_equal), just for one target instead of a whole
# batch's worth.

def _observer_id(db: Session, observer_name: str) -> uuid.UUID | None:
    row = db.query(Observer.id).filter(Observer.name == observer_name).first()
    return row[0] if row else None


def get_current_claim(
    db: Session,
    asset_canonical_id: uuid.UUID,
    observer_name: str,
    claim_type: str,
) -> AssetClaim | None:
    """The current (asset, observer, claim_type) claim row, or None if no
    such claim exists (or `observer_name` isn't a seeded observer). Callers
    doing TTL read-back compare against `.last_observed_at` themselves —
    this helper doesn't apply any freshness policy."""
    observer_id = _observer_id(db, observer_name)
    if observer_id is None:
        return None
    return (
        db.query(AssetClaim)
        .filter(
            AssetClaim.asset_canonical_id == asset_canonical_id,
            AssetClaim.observer_id == observer_id,
            AssetClaim.claim_type == claim_type,
        )
        .first()
    )


def upsert_single_claim(
    db: Session,
    asset_canonical_id: uuid.UUID,
    observer_name: str,
    claim_type: str,
    claim_value: dict,
    now: datetime,
    evidence: dict | None = None,
) -> AssetClaim | None:
    """Insert or update the one (asset, observer, claim_type) claim row.

    An unrecognised `observer_name` logs a warning and returns None without
    writing anything — mirrors emit_claims' own unknown-observer handling,
    defensive since this shouldn't happen for a seeded producer. Otherwise:
    no existing row -> INSERT AssetClaim + INSERT ClaimHistory; existing,
    value differs (JSON-equal comparison) -> UPDATE + INSERT ClaimHistory;
    existing, value identical -> bump last_observed_at only. Ids are left
    for the DB's uuidv7() default rather than generated app-side. Flushes
    (not commits) — the caller's own transaction/commit boundary is
    unchanged by this helper.
    """
    observer_id = _observer_id(db, observer_name)
    if observer_id is None:
        log.warning(
            "claim_emitter: unknown observer %r — skipping single-claim upsert (asset=%s, claim_type=%s)",
            observer_name, asset_canonical_id, claim_type,
        )
        return None

    evidence = evidence or {}
    existing = (
        db.query(AssetClaim)
        .filter(
            AssetClaim.asset_canonical_id == asset_canonical_id,
            AssetClaim.observer_id == observer_id,
            AssetClaim.claim_type == claim_type,
        )
        .first()
    )

    if existing is None:
        claim = AssetClaim(
            asset_canonical_id=asset_canonical_id,
            observer_id=observer_id,
            claim_type=claim_type,
            claim_value=claim_value,
            evidence=evidence,
            first_observed_at=now,
            last_observed_at=now,
        )
        db.add(claim)
        db.add(ClaimHistory(
            asset_canonical_id=asset_canonical_id,
            observer_id=observer_id,
            claim_type=claim_type,
            claim_value=claim_value,
            evidence=evidence,
            changed_at=now,
        ))
        db.flush()
        return claim

    if _json_equal(existing.claim_value, claim_value):
        existing.last_observed_at = now
        db.flush()
        return existing

    existing.claim_value = claim_value
    existing.evidence = evidence
    existing.last_observed_at = now
    db.add(ClaimHistory(
        asset_canonical_id=asset_canonical_id,
        observer_id=observer_id,
        claim_type=claim_type,
        claim_value=claim_value,
        evidence=evidence,
        changed_at=now,
    ))
    db.flush()
    return existing
