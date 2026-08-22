"""CNAME-chain resolution shared by the findings and risk rollups.

NOTE: keep in sync with its frontend twin, frontend/src/lib/assetChain.ts
(`resolveTerminalIp`). Both walk the same CNAME chain; they must agree on which
host a record resolves to. If this logic ever needs a third consumer, prefer
resolving the chain once at asset-write time over adding another walker.


Ports, TLS, and most service findings attach to the `ip_address` asset; a DNS
record borrows that data by resolving to the IP. A/AAAA records do this in one
hop, but a CNAME points at another *name*, so a chain like

    host1 → CNAME → host2 → A → 10.0.0.1

needs to be walked to the terminal IP before host1 can mirror the host it
ultimately resolves to. `chain_target_ids` returns every asset id along that
chain (each hop's record(s) plus the terminal IP), so a hostname inherits the
findings/risk of the host it points to across multi-hop chains.

Only A/AAAA/CNAME records resolve to a host. MX/NS/TXT/SOA/SPF point at
unrelated infrastructure (mail servers, nameservers, DNS policy) and must NOT
inherit the IP's risk — callers pass only resolving record types in, and the
walk itself follows only A/AAAA/CNAME, so those records yield no targets.
"""

from typing import Callable, Protocol


class _AssetLike(Protocol):
    id: object
    asset_type: str
    value: str
    record_type: str | None
    content: str | None


def _norm(name: str) -> str:
    return name.lower().rstrip(".")


def chain_target_ids(
    start: _AssetLike,
    get_by_value: Callable[[str], list[_AssetLike]],
) -> list:
    """Asset ids that `start` (a dns_record) resolves through.

    `get_by_value(value)` returns the assets whose `value` equals the argument —
    backed by an in-memory index (the assets already loaded for a list view) or
    a DB query (a single-asset detail view). Each returned asset exposes `id`,
    `asset_type`, `value`, `record_type`, and `content` — the dns_record
    identity columns (migration 0040), not `asset_metadata`.

    Returns the terminal IP id(s) plus every intermediate CNAME/A/AAAA record
    id, de-duplicated, preserving discovery order. Empty when the chain
    dead-ends (e.g. a CDN CNAME whose terminal records are suppressed) or loops.
    """
    out: list = []
    rt = start.record_type
    content = start.content
    visited: set[str] = {_norm(start.value)} if getattr(start, "value", None) else set()

    while rt in ("A", "AAAA", "CNAME") and content:
        if rt in ("A", "AAAA"):
            # `content` is an IP literal — attach the IP asset and stop.
            for t in get_by_value(content):
                if t.asset_type == "ip_address":
                    out.append(t.id)
            break

        # rt == CNAME: `content` is the next hostname in the chain.
        key = _norm(content)
        if key in visited:
            break
        visited.add(key)

        targets = get_by_value(content)
        if not targets:
            break
        for t in targets:
            out.append(t.id)

        # If the hop's name has address records, that's the terminal — collect
        # every IP (dual-stack hosts have both A and AAAA) and stop.
        addrs = [t for t in targets if t.record_type in ("A", "AAAA")]
        if addrs:
            for ar in addrs:
                ip_val = ar.content
                if not ip_val:
                    continue
                for ip_asset in get_by_value(ip_val):
                    if ip_asset.asset_type == "ip_address":
                        out.append(ip_asset.id)
            break

        # Otherwise follow the next CNAME hop.
        cname = next((t for t in targets if t.record_type == "CNAME"), None)
        if cname is None:
            break
        rt, content = cname.record_type, cname.content

    # De-dupe, preserve order.
    seen: set = set()
    deduped: list = []
    for i in out:
        if i not in seen:
            seen.add(i)
            deduped.append(i)
    return deduped
