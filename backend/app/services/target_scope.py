"""Target-scoped asset selection — planning#113, epic#81 Phase D follow-up L1.

Shared selection helper answering "which assets fall within this run's
authorized target scope" — independent of whether any connector happened to
touch them in this specific run. Built to fix a real gap found while
designing planning#108's Phase D widening: `shared_infra_verifier` (and,
later, `dangling_dns_analyzer` — planning#114) only ever classified findings
on assets `touched_asset_ids` this run, so a target that simply didn't get
re-touched (a connector skipped, a cadence gate, an off-cycle run) silently
stopped getting re-evaluated even though it's still fully authorized scope.

Three legs, unioned:

  1. `TargetAssetLink` walk — every asset a domain target's discovery batch
     already linked (`asset_writer._link_target_assets`). Already correct
     for the epic's own motivating case: `dns_resolve._emit_assets` links
     EVERY asset in a domain's discovery batch to that domain's target_id,
     including the shared-hosting IP a directly-resolved A/AAAA record
     points at — no extra traversal needed for that shape.
  2. Apex/parent_value string walk — a belt-and-suspenders safety net,
     independent of leg 1, for `dns_record`/`ip_address` assets whose own
     value (or, for an IP, its `parent_value` terminal hostname) is the
     domain or a subdomain of it. Catches anything leg 1 might miss (e.g. a
     write path that didn't thread `target_ids` through) — this module
     always unions rather than replaces, so a leg-2 miss never regresses
     anything leg 1 already covers, and vice versa.
  3. Direct IP/CIDR containment — `TargetAssetLink` is populated ONLY by the
     domain-discovery loop (`write_assets(..., target_ids=...)`); an
     IP/CIDR-scoped target never gets a link row at all, and leg 2's
     domain-suffix matching doesn't apply to a bare IP either. Without this
     leg, explicit IP/CIDR targets would have zero coverage from this
     helper. Python `ipaddress` containment against every owned IP/CIDR
     target, checked against the `ip_address` asset population.

Found during a Fable-model pressure-test of the original plan (epic#81
Phase D vault doc §9.2) against live code, not designed in from the start —
worth preserving as a permanent leg, not a one-off patch.

Callers MUST union this with `touched_asset_ids`, never replace it — the
three legs above are believed complete but unproven against every write
path in the codebase; the union guarantees a strict superset of prior
behavior regardless (nothing that verifies today can stop verifying).
"""

import ipaddress
import uuid

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models.asset_canonical import AssetCanonical
from app.models.target import Target, TargetType
from app.models.target_asset_link import TargetAssetLink


def target_scoped_asset_ids(db: Session, scope: dict) -> set[uuid.UUID]:
    """Every asset id within `scope` (`{"domains": [...], "ip_ranges": [...]}`,
    the same shape `scan_executor` threads through the whole pipeline) —
    regardless of whether this run's connectors happened to touch it."""
    domains: list[str] = scope.get("domains") or []
    ip_ranges: list[str] = scope.get("ip_ranges") or []
    return _domain_scoped_asset_ids(db, domains) | _ip_scoped_asset_ids(db, ip_ranges)


def _domain_scoped_asset_ids(db: Session, domains: list[str]) -> set[uuid.UUID]:
    if not domains:
        return set()
    ids: set[uuid.UUID] = set()

    # Leg 1 — TargetAssetLink.
    target_ids = [
        r[0] for r in db.query(Target.id)
        .filter(Target.type == TargetType.DOMAIN, Target.value.in_(domains))
        .all()
    ]
    if target_ids:
        ids |= {
            r[0] for r in db.query(TargetAssetLink.asset_canonical_id)
            .filter(TargetAssetLink.target_id.in_(target_ids))
            .all()
        }

    # Leg 2 — apex/parent_value string walk. dns_record assets whose own
    # value is an owned domain or subdomain of one; ip_address assets whose
    # parent_value (the terminal hostname dns_resolve resolved through — see
    # discovery/dns_resolve.py's _emit_assets) is an owned domain or
    # subdomain of one.
    value_match = _domain_suffix_clause(AssetCanonical.value, domains)
    ids |= {
        r[0] for r in db.query(AssetCanonical.id)
        .filter(AssetCanonical.asset_type == "dns_record", value_match)
        .all()
    }
    parent_match = _domain_suffix_clause(AssetCanonical.parent_value, domains)
    ids |= {
        r[0] for r in db.query(AssetCanonical.id)
        .filter(AssetCanonical.asset_type == "ip_address", parent_match)
        .all()
    }
    return ids


def _domain_suffix_clause(column, domains: list[str]):
    """`column == domain OR column LIKE '%.<domain>'` for every domain,
    OR'd together. Domain values are already validated hostnames
    (target_service._DOMAIN_RE) so `%`/`_` shouldn't appear in practice —
    escaped anyway since this builds a LIKE pattern from stored data."""
    conditions = []
    for d in domains:
        escaped = d.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")
        conditions.append(or_(column == d, column.like(f"%.{escaped}", escape="\\")))
    return or_(*conditions)


def _ip_scoped_asset_ids(db: Session, ip_ranges: list[str]) -> set[uuid.UUID]:
    if not ip_ranges:
        return set()

    bare_ips: list[str] = []
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for value in ip_ranges:
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if net.num_addresses == 1:
            bare_ips.append(str(net.network_address))
        else:
            networks.append(net)

    ids: set[uuid.UUID] = set()
    if bare_ips:
        ids |= {
            r[0] for r in db.query(AssetCanonical.id)
            .filter(AssetCanonical.asset_type == "ip_address", AssetCanonical.value.in_(bare_ips))
            .all()
        }
    if networks:
        # No CIDR-containment operator over a text column — only pay for a
        # full ip_address scan when a real CIDR (not a bare /32 or /128
        # target, handled above via direct equality) is actually in scope.
        rows = (
            db.query(AssetCanonical.id, AssetCanonical.value)
            .filter(AssetCanonical.asset_type == "ip_address")
            .all()
        )
        for asset_id, value in rows:
            try:
                ip_obj = ipaddress.ip_address(value)
            except ValueError:
                continue
            if any(ip_obj in net for net in networks):
                ids.add(asset_id)
    return ids
