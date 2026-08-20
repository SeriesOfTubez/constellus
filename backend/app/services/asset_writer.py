import uuid
from datetime import datetime, timezone

from sqlalchemy import text, tuple_
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.connectors.base import DiscoveredAsset
from app.models.asset_canonical import AssetCanonical
from app.models.asset_edge import AssetEdge
from app.models.tag_rule import TagRule
from app.models.target_asset_link import TargetAssetLink
from app.services import projector
# _merge_open_ports / _prune_stale_ports (+ their grace-period constants)
# moved to projector.py (planning#143 L2 sub-slice C) — re-exported here so
# this module's own merge loop below, and existing external importers
# (scan_executor._hydrate_asset_ports, app.tests.test_prune_stale_ports),
# keep working unchanged against a single definition.
from app.services.projector import (  # noqa: F401
    _CONFIRMED_PORT_GRACE_DAYS,
    _SHODAN_PORT_GRACE_DAYS,
    _merge_open_ports,
    _prune_stale_ports,
)
from app.services.tag_service import apply_rules_preloaded, merge_tags


def write_assets(
    db: Session,
    scan_run_id: uuid.UUID,
    assets: list[DiscoveredAsset],
    target_ids: list[uuid.UUID] | None = None,
) -> set[uuid.UUID]:
    """Persist a batch of discovered assets to the canonical schema.

    Upserts assets_canonical rows, optionally links them to targets via
    target_asset_links, and emits asset_edges for in-batch relationships
    (resolves_to for A/AAAA/CNAME, plus belongs_to_apex).

    Returns the set of canonical asset IDs touched (new + updated). The
    executor accumulates these across chunks to populate
    scan_runs.asset_count at run completion.

    scan_run_id is currently unused — the legacy `assets` hypertable
    that stored per-run observation rows was dropped after readers
    moved to canonical. The parameter is retained so callers don't have
    to change; it may be wired back to an observation log later.
    """
    if not assets:
        return set()

    now = datetime.now(timezone.utc)

    # ── 1. Upsert canonical rows; build (type, value) → canonical_id map ──────
    canonical_map = _upsert_canonical_batch(db, assets, now)

    # ── 2. Link to targets if context provided ────────────────────────────────
    canonical_ids = set(canonical_map.values())
    if target_ids:
        _link_target_assets(db, target_ids, list(canonical_ids), now)

    # ── 3. Emit edges between in-batch assets ─────────────────────────────────
    _emit_edges_for_batch(db, assets, canonical_map, now)

    # ── 4. Emit claims in parallel with the asset_metadata merge above
    # (planning#143 L2 sub-slice A — strangler-fig additive, nothing reads
    # claims yet). Local import: claim_emitter imports `_canonical_key` back
    # from this module, so importing it at module load time here would be a
    # circular import; by the time write_assets() actually runs this module
    # is fully loaded, so a local import is safe.
    from app.services.claim_emitter import emit_claims
    emit_claims(db, assets, canonical_map, now)

    # ── 5. Project claims + still-authoritative asset_metadata into
    # asset_state (planning#143 L2 sub-slice C). Same transaction as the
    # claim emission and canonical/edge writes above, so the projection is
    # atomic with the write it reflects.
    projector.project(db, canonical_ids, now)

    db.commit()
    return canonical_ids


# ── Internal: canonical / link / edge helpers ─────────────────────────────────

def _upsert_canonical_batch(
    db: Session,
    assets: list[DiscoveredAsset],
    now: datetime,
) -> dict[tuple, uuid.UUID]:
    """Return {canonical_key: canonical_id}. Existing rows get last_seen_at
    touched; new rows are inserted. Tag rules are applied to new rows so
    auto-tagging works at discovery time.

    canonical_key is:
      - ("dns_record", value, record_type, content) for DNS records — each
        distinct record is its own canonical identity (matches the
        partial unique index from migration 0026).
      - (asset_type, value) for every other type.
    """
    unique: dict[tuple, DiscoveredAsset] = {}
    for a in assets:
        unique[_canonical_key(a.asset_type, a.value, a.asset_metadata)] = a

    if not unique:
        return {}

    # Pull all rows for the (type, value) pairs in the batch, then bucket by
    # full canonical key in Python — Postgres can't index on the full 4-tuple
    # in a way that's nice to query. FOR UPDATE serializes (blocks, doesn't
    # fail) any concurrent writer touching the same rows — planning#86: two
    # concurrent scans reading-then-writing the same asset_metadata JSONB
    # otherwise last-write-wins clobbers whichever wrote second.
    type_value_pairs = {(k[0], k[1]) for k in unique.keys()}
    existing_rows = (
        db.query(AssetCanonical)
        .filter(tuple_(AssetCanonical.asset_type, AssetCanonical.value).in_(list(type_value_pairs)))
        .with_for_update()
        .all()
    )
    existing: dict[tuple, AssetCanonical] = {
        _canonical_key(r.asset_type, r.value, r.asset_metadata): r
        for r in existing_rows
    }

    asset_rules = (
        db.query(TagRule)
        .filter(TagRule.entity_type == "asset", TagRule.enabled == True)  # noqa: E712
        .all()
    )

    # Build rows for keys not seen above, but don't insert them yet — a
    # concurrent transaction may insert the same key between our SELECT and
    # our INSERT. _defensive_insert_assets uses ON CONFLICT DO NOTHING so
    # that race can't raise IntegrityError and abort the whole batch (as a
    # plain INSERT would against migration 0026's partial unique indexes).
    to_insert: dict[tuple, AssetCanonical] = {}
    for key, asset in unique.items():
        if key in existing:
            continue
        new_row = AssetCanonical(
            id=uuid.uuid4(),
            asset_type=asset.asset_type,
            value=asset.value,
            parent_value=asset.parent_value,
            first_seen_at=now,
            last_seen_at=now,
            asset_metadata=asset.asset_metadata or {},
        )
        if asset_rules:
            new_row.tags = merge_tags([], apply_rules_preloaded(asset_rules, new_row))
        to_insert[key] = new_row

    result: dict[tuple, uuid.UUID] = {}
    if to_insert:
        inserted_ids = _defensive_insert_assets(db, list(to_insert.values()))
        for key, new_row in to_insert.items():
            if key in inserted_ids:
                result[key] = inserted_ids[key]
                continue
            # Lost the race — a concurrent transaction inserted this key
            # first. Re-fetch it locked and fold our observation into it via
            # the merge loop below instead of losing our data or raising.
            locked = (
                db.query(AssetCanonical)
                .filter(AssetCanonical.asset_type == key[0], AssetCanonical.value == key[1])
                .with_for_update()
                .all()
            )
            for r in locked:
                existing[_canonical_key(r.asset_type, r.value, r.asset_metadata)] = r

    for key, asset in unique.items():
        if key not in existing:
            continue
        row = existing[key]
        row.last_seen_at = now
        # parent_value: only fill if currently null — first observation wins
        if asset.parent_value and not row.parent_value:
            row.parent_value = asset.parent_value
        # Shallow-merge metadata so later observations enrich without
        # destroying earlier fields. `open_ports` is special-cased into a
        # per-port merge so successive port scans (and future service
        # enrichers like tlsx / httpx / banner-grab) can each contribute
        # a slice to the same port entry instead of overwriting it.
        if asset.asset_metadata:
            merged = {**(row.asset_metadata or {})}
            for mk, mv in asset.asset_metadata.items():
                if mv in (None, "", [], {}):
                    continue
                if mk == "sources":
                    existing_sources = merged.get("sources", [])
                    merged["sources"] = list(dict.fromkeys(
                        existing_sources + (mv if isinstance(mv, list) else [mv])
                    ))
                elif mk == "open_ports" and isinstance(mv, list):
                    merged["open_ports"] = _merge_open_ports(
                        merged.get("open_ports") or [], mv
                    )
                elif mk.endswith("_last_scan_at"):
                    # Scan-time markers always advance — keep the newer ISO timestamp
                    current = merged.get(mk)
                    if not current or mv > current:
                        merged[mk] = mv
                elif mk not in merged or merged[mk] in (None, "", [], {}):
                    merged[mk] = mv
            # Prune ports not re-confirmed in the latest naabu scan so storage
            # reflects current truth (no phantom accumulation). Keyed on the
            # post-merge naabu_last_scan_at; fresh ports written this scan
            # survive, stale phantoms are deleted (Shodan intel keeps its grace).
            nls = merged.get("naabu_last_scan_at")
            if nls and isinstance(merged.get("open_ports"), list):
                merged["open_ports"] = _prune_stale_ports(merged["open_ports"], nls, now)
            row.asset_metadata = merged
        result[key] = row.id

    # Flush so subsequent edge inserts see the new canonical rows — the
    # polymorphic-FK trigger queries them by id.
    db.flush()
    return result


def _defensive_insert_assets(
    db: Session,
    new_rows: list[AssetCanonical],
) -> dict[tuple, uuid.UUID]:
    """INSERT new asset rows with ON CONFLICT DO NOTHING, split by migration
    0026's two partial unique indexes — a single INSERT's ON CONFLICT clause
    can only target one conflict-inference index, and assets_canonical has
    two (dns_record rows vs everything else).

    Returns {canonical_key: id} for rows that were actually inserted. Any
    row NOT present in the returned dict lost a race to a concurrent
    transaction inserting the same key; the caller re-fetches those.
    """
    if not new_rows:
        return {}

    dns_rows = [r for r in new_rows if r.asset_type == "dns_record"]
    non_dns_rows = [r for r in new_rows if r.asset_type != "dns_record"]
    inserted: dict[tuple, uuid.UUID] = {}

    if non_dns_rows:
        stmt = (
            pg_insert(AssetCanonical.__table__)
            .values([_asset_row_values(r) for r in non_dns_rows])
            .on_conflict_do_nothing(
                index_elements=["asset_type", "value"],
                index_where=text("asset_type <> 'dns_record'"),
            )
            .returning(AssetCanonical.id, AssetCanonical.asset_type, AssetCanonical.value)
        )
        for row in db.execute(stmt):
            inserted[(row.asset_type, row.value)] = row.id

    if dns_rows:
        stmt = (
            pg_insert(AssetCanonical.__table__)
            .values([_asset_row_values(r) for r in dns_rows])
            .on_conflict_do_nothing(
                index_elements=[
                    "asset_type",
                    "value",
                    text("coalesce(metadata->>'record_type', '')"),
                    text("coalesce(metadata->>'content', '')"),
                ],
                index_where=text("asset_type = 'dns_record'"),
            )
            .returning(
                AssetCanonical.id,
                AssetCanonical.asset_type,
                AssetCanonical.value,
                text("coalesce(metadata->>'record_type', '') AS record_type"),
                text("coalesce(metadata->>'content', '') AS content"),
            )
        )
        for row in db.execute(stmt):
            inserted[(row.asset_type, row.value, row.record_type, row.content)] = row.id

    return inserted


def _asset_row_values(row: AssetCanonical) -> dict:
    return {
        "id": row.id,
        "asset_type": row.asset_type,
        "value": row.value,
        "parent_value": row.parent_value,
        "first_seen_at": row.first_seen_at,
        "last_seen_at": row.last_seen_at,
        "tags": row.tags or [],
        "metadata": row.asset_metadata or {},
    }


def _link_target_assets(
    db: Session,
    target_ids: list[uuid.UUID],
    canonical_ids: list[uuid.UUID],
    now: datetime,
) -> None:
    """Upsert target_asset_links rows for every (target, asset) pair. Existing
    links get last_observed_at touched."""
    rows = [
        {
            "target_id": tid,
            "asset_canonical_id": cid,
            "first_linked_at": now,
            "last_observed_at": now,
        }
        for tid in target_ids
        for cid in canonical_ids
    ]
    if not rows:
        return

    stmt = pg_insert(TargetAssetLink.__table__).values(rows)
    stmt = stmt.on_conflict_do_update(
        index_elements=["target_id", "asset_canonical_id"],
        set_={"last_observed_at": now},
    )
    db.execute(stmt)


def _emit_edges_for_batch(
    db: Session,
    assets: list[DiscoveredAsset],
    canonical_map: dict[tuple, uuid.UUID],
    now: datetime,
) -> None:
    """Emit asset_edges for in-batch graph relationships.

    Three edge kinds:
      • resolves_to (dns_record → ip_address) — A / AAAA records
      • resolves_to (dns_record → dns_record) — CNAME hops
      • belongs_to_apex (dns_record → dns_record) — child → apex

    CNAME and apex targets are looked up by name only — a target FQDN may
    have multiple canonicals (one per record) and the CNAME/apex edge
    semantically points at the name itself, so we attach to any one of
    them. Apex lookups also fall back to the canonical table for apexes
    not in the current batch.

    Ports are properties of an IP (stored in `metadata.open_ports[]`),
    not separate asset nodes, so port-scan observations don't produce
    edges — they just update the parent IP's metadata.
    """
    # Name-only fallback: any dns_record canonical for a given FQDN.
    # Each FQDN may have multiple canonicals (A, AAAA, MX, …); the CNAME
    # and apex edges target the name identity, not a specific record.
    canonical_by_name: dict[str, uuid.UUID] = {}
    for key, cid in canonical_map.items():
        if key[0] == "dns_record":
            canonical_by_name.setdefault(key[1], cid)

    edges: list[dict] = []
    pending_apex_lookups: dict[str, list[uuid.UUID]] = {}
    pending_cname_lookups: dict[str, list[uuid.UUID]] = {}
    pending_a_lookups: dict[str, list[tuple[uuid.UUID, str]]] = {}

    for a in assets:
        if a.asset_type != "dns_record":
            continue
        meta = a.asset_metadata or {}
        rtype = meta.get("record_type")
        content = meta.get("content")

        src_id = canonical_map.get(_canonical_key("dns_record", a.value, meta))
        if not src_id:
            continue

        # resolves_to: A / AAAA / CNAME edges to whatever the content points at.
        # Same DB-fallback pattern as belongs_to_apex below — relationships often
        # cross batch boundaries (CT discovers the CNAME, dns_resolve emits the A
        # in a later sweep) and we want the edge regardless of discovery order.
        if rtype in ("A", "AAAA") and content:
            ip_id = canonical_map.get(("ip_address", content))
            if ip_id:
                edges.append(_edge(src_id, ip_id, "resolves_to", now, {"record_type": rtype}))
            else:
                pending_a_lookups.setdefault(content, []).append((src_id, rtype))
        elif rtype == "CNAME" and content:
            target_id = canonical_by_name.get(content)
            if target_id:
                edges.append(_edge(src_id, target_id, "resolves_to", now, {"record_type": "CNAME"}))
            else:
                pending_cname_lookups.setdefault(content, []).append(src_id)

        # belongs_to_apex: child dns_record → apex dns_record
        if a.parent_value and a.parent_value != a.value:
            apex_id = canonical_by_name.get(a.parent_value)
            if apex_id:
                edges.append(_edge(src_id, apex_id, "belongs_to_apex", now))
            else:
                pending_apex_lookups.setdefault(a.parent_value, []).append(src_id)

    if pending_apex_lookups:
        rows = db.query(AssetCanonical.value, AssetCanonical.id).filter(
            AssetCanonical.asset_type == "dns_record",
            AssetCanonical.value.in_(list(pending_apex_lookups.keys())),
        ).all()
        # Same name may have multiple canonicals — first one wins.
        apex_by_name: dict[str, uuid.UUID] = {}
        for apex_value, apex_id in rows:
            apex_by_name.setdefault(apex_value, apex_id)
        for apex_value, child_ids in pending_apex_lookups.items():
            apex_id = apex_by_name.get(apex_value)
            if not apex_id:
                continue
            for child_id in child_ids:
                edges.append(_edge(child_id, apex_id, "belongs_to_apex", now))

    if pending_cname_lookups:
        rows = db.query(AssetCanonical.value, AssetCanonical.id).filter(
            AssetCanonical.asset_type == "dns_record",
            AssetCanonical.value.in_(list(pending_cname_lookups.keys())),
        ).all()
        target_by_name: dict[str, uuid.UUID] = {}
        for v, i in rows:
            target_by_name.setdefault(v, i)
        for target_value, src_ids in pending_cname_lookups.items():
            tid = target_by_name.get(target_value)
            if not tid:
                continue
            for sid in src_ids:
                edges.append(_edge(sid, tid, "resolves_to", now, {"record_type": "CNAME"}))

    if pending_a_lookups:
        rows = db.query(AssetCanonical.value, AssetCanonical.id).filter(
            AssetCanonical.asset_type == "ip_address",
            AssetCanonical.value.in_(list(pending_a_lookups.keys())),
        ).all()
        ip_by_value = {v: i for v, i in rows}
        for ip_value, items in pending_a_lookups.items():
            iid = ip_by_value.get(ip_value)
            if not iid:
                continue
            for sid, rtype in items:
                edges.append(_edge(sid, iid, "resolves_to", now, {"record_type": rtype}))

    if not edges:
        return

    # Postgres ON CONFLICT DO UPDATE rejects same-row duplicates inside a
    # single INSERT — the same dns_record can land in the batch from
    # multiple sources, so dedupe by edge identity here.
    deduped: dict[tuple, dict] = {}
    for e in edges:
        deduped[(e["source_id"], e["target_id"], e["edge_type"])] = e

    stmt = pg_insert(AssetEdge.__table__).values(list(deduped.values()))
    stmt = stmt.on_conflict_do_update(
        constraint="uq_asset_edges_unique",
        set_={"last_seen_at": now},
    )
    db.execute(stmt)


def _canonical_key(asset_type: str, value: str, metadata: dict | None) -> tuple:
    """Key matching the partial unique indexes from migration 0026.

    dns_records: (asset_type, value, record_type, content) so each distinct
    record gets its own canonical row. Empty/missing record_type or content
    are coalesced to '' to match the COALESCE() inside the unique index.
    """
    if asset_type == "dns_record":
        meta = metadata or {}
        return (asset_type, value, meta.get("record_type") or "", meta.get("content") or "")
    return (asset_type, value)


def _edge(
    source_id: uuid.UUID,
    target_id: uuid.UUID,
    edge_type: str,
    now: datetime,
    metadata: dict | None = None,
) -> dict:
    row = {
        "source_type": "asset_canonical",
        "source_id": source_id,
        "target_type": "asset_canonical",
        "target_id": target_id,
        "edge_type": edge_type,
        "first_seen_at": now,
        "last_seen_at": now,
    }
    if metadata:
        row["metadata"] = metadata
    return row
