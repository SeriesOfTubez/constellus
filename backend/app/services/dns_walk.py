"""The scoped DNS walk shared by the exposure path (planning#347) and the
attribution chain (planning#358).

It follows `resolves_to` / `cname` edges between `dns_record` and `ip_address`
assets, level by level, and returns the assets it reached as `HopCandidate`s.

Read scope: the caller passes `clause`, a callable taking the `AssetCanonical`
entity and returning a SQL boolean (the caller's `read_scope.asset_clause`, or
`false()` when the reader lacks the permission). Every asset read here carries
it, so a walk never passes through an asset the reader may not read, and
nothing derived from one is returned. A withheld asset and a missing one
produce the same result.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset_canonical import AssetCanonical
from app.models.asset_edge import AssetEdge
from app.schemas.exposure_path import HopCandidate

# Response-size bound on one walk's candidates (a shared address can have
# thousands of names), and the guard on how far a CNAME chain is followed.
MAX_CANDIDATES = 50
MAX_CHAIN_DEPTH = 8
_LEVEL_ROW_LIMIT = 500

_NODE = "asset_canonical"
# A CNAME step is normally a `resolves_to` edge; the hop into third-party CDN
# infrastructure is typed `cname` instead (planning#147). Both are DNS links.
_DNS_EDGE_TYPES = ("resolves_to", "cname")


def _norm_name(name: str) -> str:
    return name.lower().rstrip(".")


def record_ids_for_names(db: Session, clause: Callable, names) -> list[uuid.UUID]:
    """Every readable dns_record row for `names`. A hostname has one row
    per record, and a CNAME edge points at any one of them."""
    names = list(names)
    if not names:
        return []
    A = AssetCanonical
    return list(
        db.execute(
            select(A.id)
            .where(A.asset_type == "dns_record", A.value.in_(names), clause(A))
            .order_by(A.id)
            .limit(_LEVEL_ROW_LIMIT)
        ).scalars()
    )


def walk(
    db: Session,
    clause: Callable,
    start_ids: list[uuid.UUID],
    *,
    upward: bool,
    max_candidates: int | None = None,
    max_depth: int | None = None,
    keep: Callable[[str], bool] | None = None,
) -> tuple[list[HopCandidate], bool]:
    """Follow DNS edges from `start_ids`, level by level.

    Upward (from an address): collect the hostnames that point at it, then
    the names that CNAME to those. Downward (from a hostname's records):
    follow CNAMEs and collect the addresses they end at. Every asset read
    passes `clause`, so the walk stops at one the reader may not read.
    Returns (candidates, truncated).

    `max_candidates` and `max_depth` default to this module's constants, read
    at call time; the exposure path passes its own re-exported names so a test
    that patches those still takes effect.

    `keep`, when given, decides by value which reached assets are returned.
    It does not stop the walk: a name it turns down is still followed, since
    a wanted name may sit behind it (a CNAME through another party's name).
    The candidate cap counts kept assets only, so names that are turned down
    cannot crowd out the ones the caller asked for.
    """
    limit = MAX_CANDIDATES if max_candidates is None else max_candidates
    depth_limit = MAX_CHAIN_DEPTH if max_depth is None else max_depth
    A = AssetCanonical
    near, far = (AssetEdge.target_id, AssetEdge.source_id) if upward else (AssetEdge.source_id, AssetEdge.target_id)
    wanted = "dns_record" if upward else "ip_address"

    # Keyed by name: a hostname has one asset row per DNS record, and it is
    # one candidate, listed at the nearest row that links it.
    found: dict[str, HopCandidate] = {}
    truncated = False
    frontier = list(start_ids)
    expanded_ids: set[uuid.UUID] = set(start_ids)
    expanded_names: set[str] = set()

    for distance in range(1, depth_limit + 1):
        if not frontier:
            break
        rows = db.execute(
            select(
                A.id, A.asset_type, A.value,
                AssetEdge.edge_metadata, AssetEdge.first_seen_at, AssetEdge.last_seen_at,
            )
            .join(AssetEdge, far == A.id)
            .where(
                near.in_(frontier),
                AssetEdge.source_type == _NODE,
                AssetEdge.target_type == _NODE,
                AssetEdge.edge_type.in_(_DNS_EDGE_TYPES),
                A.asset_type.in_(("dns_record", "ip_address")),
                clause(A),
            )
            .order_by(A.value, A.id)
            .limit(_LEVEL_ROW_LIMIT + 1)
        ).all()
        if len(rows) > _LEVEL_ROW_LIMIT:
            truncated = True
            rows = rows[:_LEVEL_ROW_LIMIT]

        next_names: list[str] = []
        for asset_id, asset_type, value, metadata, link_first, link_last in rows:
            if asset_type == wanted and _norm_name(value) not in found and (keep is None or keep(value)):
                record_type = (metadata or {}).get("record_type") if isinstance(metadata, dict) else None
                found[_norm_name(value)] = HopCandidate(
                    asset_id=asset_id,
                    asset_type=asset_type,
                    value=value,
                    record_type=record_type if isinstance(record_type, str) else None,
                    distance=distance,
                    link_first_seen_at=link_first,
                    link_last_seen_at=link_last,
                )
            if asset_type == "dns_record" and _norm_name(value) not in expanded_names:
                expanded_names.add(_norm_name(value))
                next_names.append(value)

        if len(found) > limit:
            truncated = True
            break
        # The next level starts from every record row of the names just
        # reached; `expanded_names` is what stops a CNAME loop.
        frontier = [i for i in record_ids_for_names(db, clause, next_names) if i not in expanded_ids]
        expanded_ids.update(frontier)

    candidates = sorted(found.values(), key=lambda c: (c.distance, c.value, str(c.asset_id)))
    return candidates[:limit], truncated
