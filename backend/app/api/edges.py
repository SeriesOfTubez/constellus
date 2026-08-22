"""Edges API — hydrated graph relationships for a single node.

`GET /api/edges/{node_type}/{node_id}` walks `asset_edges` in both directions
and returns the connected nodes, grouped by `(edge_type, direction)` and
hydrated from `assets_canonical` / `findings_canonical` / `targets`.

One endpoint serves every flyout (asset / finding / target) so the React
component is a pure renderer that doesn't need to know which kind of node it
is rendering — it just iterates groups and emits rows.

The verb shown on the group header is rendered server-side from the
`(edge_type, direction)` taxonomy below, so the frontend doesn't duplicate it.
"""

import uuid
from typing import Iterable

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.asset_canonical import AssetCanonical
from app.models.asset_edge import EDGE_TYPES, NODE_TYPES, AssetEdge
from app.models.finding_canonical import FindingCanonical
from app.models.target import Target
from app.services import metadata_bridge

router = APIRouter()


# Per-group cap for inline rendering. Total count is always returned so the
# frontend can render "View all (N) →" when more exist.
_INLINE_CAP = 10


# Directional verb taxonomy. None means edges in that direction are not
# expected — e.g. a finding never has outbound edges, only inbound `has_finding`.
_VERBS: dict[tuple[str, str], str] = {
    ("resolves_to", "out"):         "Resolves to",
    ("resolves_to", "in"):          "Resolved by",
    ("belongs_to_apex", "out"):     "Belongs to apex",
    ("belongs_to_apex", "in"):      "Has subdomain",
    ("has_finding", "out"):         "Has finding",
    ("has_finding", "in"):          "Finding on",
    ("runs_service", "out"):        "Runs service",
    ("runs_service", "in"):         "Service on",
    ("registered_to", "out"):       "Registered to",
    ("registered_to", "in"):        "Owns",
    ("discovered_in_target", "out"): "Discovered in",
    ("discovered_in_target", "in"): "Includes asset",
    # Derived (not in asset_edges; computed via 2-hop join). Lateral direction
    # — both endpoints sit at the same "level" rather than one owning the other.
    ("shares_ip_with", "lateral"):  "Shares IP with",
}


def _verb(edge_type: str, direction: str) -> str:
    return _VERBS.get((edge_type, direction), edge_type.replace("_", " "))


@router.get("/{node_type}/{node_id}")
def get_edges(
    node_type: str,
    node_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Return all hydrated edges touching this node, grouped by edge_type + direction."""
    if node_type not in NODE_TYPES:
        raise HTTPException(status_code=400, detail=f"Unknown node_type: {node_type}")

    rows: list[AssetEdge] = (
        db.query(AssetEdge)
        .filter(
            or_(
                (AssetEdge.source_type == node_type) & (AssetEdge.source_id == node_id),
                (AssetEdge.target_type == node_type) & (AssetEdge.target_id == node_id),
            )
        )
        .order_by(AssetEdge.last_seen_at.desc())
        .all()
    )

    # Bucket by (edge_type, direction). Direction "out" = node is the source of
    # this edge; "in" = node is the target.
    buckets: dict[tuple[str, str], list[tuple[str, uuid.UUID, dict]]] = {}
    for e in rows:
        if e.source_type == node_type and e.source_id == node_id:
            direction = "out"
            other_type, other_id = e.target_type, e.target_id
        else:
            direction = "in"
            other_type, other_id = e.source_type, e.source_id
        key = (e.edge_type, direction)
        buckets.setdefault(key, []).append((other_type, other_id, e.edge_metadata or {}))

    # Batch-hydrate other endpoints by their type so we make at most one query
    # per (node_type, batch) instead of N+1.
    ids_by_type: dict[str, set[uuid.UUID]] = {}
    for items in buckets.values():
        for other_type, other_id, _meta in items:
            ids_by_type.setdefault(other_type, set()).add(other_id)

    hydrated = _hydrate(db, ids_by_type)

    groups: list[dict] = []
    for (edge_type, direction), items in buckets.items():
        rendered_items: list[dict] = []
        for other_type, other_id, edge_meta in items:
            node = hydrated.get((other_type, other_id))
            if not node:
                continue  # node deleted but edge still around — skip
            rendered_items.append({
                "node_type": other_type,
                **node,
                "edge_metadata": edge_meta,
            })
        rendered_items.sort(key=_node_sort_key)
        groups.append({
            "edge_type": edge_type,
            "direction": direction,
            "verb": _verb(edge_type, direction),
            "total": len(rendered_items),
            "items": rendered_items[:_INLINE_CAP],
        })

    # Derived: shares_ip_with — DNS records that resolve to the same IPs as the
    # queried node. Computed via 2-hop join, not stored as edges (materializing
    # would blow up the table: N records sharing an IP → N*(N-1) edges).
    derived = _shares_ip_with(db, node_type, node_id)
    if derived:
        groups.append(derived)

    groups.sort(key=lambda g: (g["edge_type"], g["direction"]))
    return {"groups": groups}


def _shares_ip_with(
    db: Session,
    node_type: str,
    node_id: uuid.UUID,
) -> dict | None:
    """Find tracked DNS records that resolve to any IP this node resolves to.

    v1 covers direct A/AAAA → IP relationships. CNAME nodes don't get a
    sibling group here — clicking through to their resolved A record surfaces
    the signal one hop down. Generalising to recursive traversal is a follow-up.
    """
    if node_type != "asset_canonical":
        return None

    # Only compute for dns_record nodes. Skip ip_address nodes — their tracked
    # names already render via the existing "Resolved by" edge group.
    src = db.get(AssetCanonical, node_id)
    if not src or src.asset_type != "dns_record":
        return None

    # IPs this node resolves to (direct edges only).
    ip_id_rows = (
        db.query(AssetEdge.target_id)
        .filter(
            AssetEdge.source_id == node_id,
            AssetEdge.edge_type == "resolves_to",
            AssetEdge.target_type == "asset_canonical",
        )
        .all()
    )
    ip_ids = [r[0] for r in ip_id_rows]
    if not ip_ids:
        return None

    # Restrict to actual ip_address canonicals — CNAME resolves_to also lands
    # here but targets dns_records, which we don't want to treat as shared IPs.
    real_ips = (
        db.query(AssetCanonical.id)
        .filter(
            AssetCanonical.id.in_(ip_ids),
            AssetCanonical.asset_type == "ip_address",
        )
        .all()
    )
    ip_ids = [r[0] for r in real_ips]
    if not ip_ids:
        return None

    # Siblings: other DNS records pointing to any of these IPs.
    sibling_rows = (
        db.query(AssetCanonical, AssetEdge.target_id)
        .join(AssetEdge, AssetEdge.source_id == AssetCanonical.id)
        .filter(
            AssetEdge.target_id.in_(ip_ids),
            AssetEdge.edge_type == "resolves_to",
            AssetEdge.source_id != node_id,
            AssetCanonical.asset_type == "dns_record",
        )
        .all()
    )
    if not sibling_rows:
        return None

    # Collapse multi-IP siblings into one row; collect the shared IPs as metadata.
    summaries = _asset_summaries(db, [sibling for sibling, _via in sibling_rows])
    by_id: dict[uuid.UUID, dict] = {}
    ips_by_sibling: dict[uuid.UUID, list[uuid.UUID]] = {}
    for sibling, via_ip in sibling_rows:
        if sibling.id not in by_id:
            by_id[sibling.id] = {
                "node_type": "asset_canonical",
                "node_id": str(sibling.id),
                "value": sibling.value,
                "label": sibling.value,
                "asset_type": sibling.asset_type,
                "ignored": sibling.ignored,
                "metadata": summaries.get(sibling.id, {}),
            }
            ips_by_sibling[sibling.id] = []
        ips_by_sibling[sibling.id].append(via_ip)

    # Resolve via_ip uuids to actual IP value strings for the metadata chip.
    all_via_ips = {ip for ips in ips_by_sibling.values() for ip in ips}
    ip_value_rows = (
        db.query(AssetCanonical.id, AssetCanonical.value)
        .filter(AssetCanonical.id.in_(all_via_ips))
        .all()
    )
    ip_value_by_id = {r[0]: r[1] for r in ip_value_rows}

    items: list[dict] = []
    for sib_id, item in by_id.items():
        via = [ip_value_by_id[i] for i in ips_by_sibling[sib_id] if i in ip_value_by_id]
        item["edge_metadata"] = {"via_ips": via}
        items.append(item)

    items.sort(key=_node_sort_key)

    return {
        "edge_type": "shares_ip_with",
        "direction": "lateral",
        "verb": _verb("shares_ip_with", "lateral"),
        "total": len(items),
        "items": items[:_INLINE_CAP],
    }


def _hydrate(
    db: Session,
    ids_by_type: dict[str, set[uuid.UUID]],
) -> dict[tuple[str, uuid.UUID], dict]:
    """Load nodes by (type, ids) and return a flat lookup."""
    out: dict[tuple[str, uuid.UUID], dict] = {}

    asset_ids = ids_by_type.get("asset_canonical")
    if asset_ids:
        rows = db.query(AssetCanonical).filter(AssetCanonical.id.in_(asset_ids)).all()
        summaries = _asset_summaries(db, rows)
        for r in rows:
            out[("asset_canonical", r.id)] = {
                "node_id": str(r.id),
                "value": r.value,
                "label": r.value,
                "asset_type": r.asset_type,
                "ignored": r.ignored,
                "metadata": summaries.get(r.id, {}),
            }

    finding_ids = ids_by_type.get("finding_canonical")
    if finding_ids:
        rows = db.query(FindingCanonical).filter(FindingCanonical.id.in_(finding_ids)).all()
        for r in rows:
            out[("finding_canonical", r.id)] = {
                "node_id": str(r.id),
                "value": r.title,
                "label": r.title,
                "severity": r.severity,
                "state": r.state,
                "category": r.category,
                "cve_id": r.cve_id,
                "kev": r.kev,
            }

    target_ids = ids_by_type.get("target")
    if target_ids:
        rows = db.query(Target).filter(Target.id.in_(target_ids)).all()
        for r in rows:
            out[("target", r.id)] = {
                "node_id": str(r.id),
                "value": r.value,
                "label": r.value,
                "target_type": r.type,
                "verified": r.verified,
            }

    return out


_SUMMARY_KEYS = ("record_type", "content", "mx_preference", "provider_mx")


def _asset_summaries(db: Session, rows: list[AssetCanonical]) -> dict[uuid.UUID, dict]:
    """{asset_id: panel metadata} for `rows` — record_type/content (columns),
    mx_preference (claim) and provider_mx (asset_state.attributes).

    planning#144 L3c-3: reconstructed through `metadata_bridge` rather than
    read off `assets_canonical.metadata`. The bridge is batch-loaded once for
    the whole node set, so this stays two queries no matter how many nodes
    the panel is hydrating — a per-row lookup here would be an N+1 on a
    request that already caps out at _INLINE_CAP nodes per edge type.
    """
    if not rows:
        return {}
    sources = metadata_bridge.load_bridge_sources(db, [r.id for r in rows])
    out: dict[uuid.UUID, dict] = {}
    for row in rows:
        claims = sources.get(row.id, metadata_bridge.EMPTY_BRIDGE_SOURCES)
        meta = metadata_bridge.bridge_metadata(row, claims.get("state"), claims)
        out[row.id] = {k: meta[k] for k in _SUMMARY_KEYS if k in meta}
    return out


def _node_sort_key(item: dict) -> tuple:
    """Sort findings by severity desc, then everything by value asc."""
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sev = severity_order.get(item.get("severity") or "", 99)
    return (sev, str(item.get("value") or "").lower())
