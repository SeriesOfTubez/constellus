"""Pure rules of the acquisitions roll-up (planning#277 S4a); no DB access.

- A candidate counts under its affiliate's nearest ACQUIRED ancestor, the
  affiliate itself included, among the confirmed tree nodes. No acquired node
  on the chain (the root, a subsidiary of the root) or an affiliate that is
  not a confirmed node gives `None`: the organic bucket.
- An asset linked to the targets of several claimed candidates is counted
  under exactly one: lowest kind rank (domain, cidr, asn), then earliest
  `decided_at`, then lowest candidate id.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

_EPOCH = datetime.min.replace(tzinfo=timezone.utc)
KIND_RANK = {"domain": 0, "cidr": 1, "asn": 2}


@dataclass(frozen=True)
class Claim:
    candidate_id: uuid.UUID
    kind: str
    target_id: uuid.UUID
    decided_at: datetime | None


def deal_of(nodes) -> dict[uuid.UUID, uuid.UUID | None]:
    """Every CONFIRMED node -> its nearest acquired ancestor-or-self, else None."""
    confirmed = {n.entity_id: n for n in nodes if n.status == "confirmed"}
    out: dict[uuid.UUID, uuid.UUID | None] = {}
    for start in confirmed:
        seen: set[uuid.UUID] = set()
        cur = confirmed.get(start)
        found: uuid.UUID | None = None
        while cur is not None and cur.entity_id not in seen:
            seen.add(cur.entity_id)
            if cur.relation == "acquired":
                found = cur.entity_id
                break
            cur = confirmed.get(cur.parent_id) if cur.parent_id is not None else None
        out[start] = found
    return out


def attribute(
    claims: Iterable[Claim], links: Iterable[tuple[uuid.UUID, uuid.UUID]]
) -> dict[uuid.UUID, uuid.UUID]:
    """asset_id -> the ONE candidate id it counts under."""
    by_target: dict[uuid.UUID, list[Claim]] = {}
    for c in claims:
        by_target.setdefault(c.target_id, []).append(c)

    def key(c: Claim):
        # A missing decided_at (a claim always has one) sorts last.
        return (KIND_RANK.get(c.kind, len(KIND_RANK)), c.decided_at is None, c.decided_at or _EPOCH, c.candidate_id)

    best: dict[uuid.UUID, Claim] = {}
    for target_id, asset_id in links:
        for c in by_target.get(target_id, ()):
            cur = best.get(asset_id)
            if cur is None or key(c) < key(cur):
                best[asset_id] = c
    return {a: c.candidate_id for a, c in best.items()}
