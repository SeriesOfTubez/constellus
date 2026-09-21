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

import functools
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
    return {asset_id for asset_id, _ in _ip_scoped_rows(db, ip_ranges)}


def ip_range_member_values(db: Session, ip_ranges: list[str]) -> list[str]:
    """The `value` of every persisted `ip_address` asset contained by one of
    `ip_ranges`, sorted.

    The second rendering of `_ip_scoped_rows` — same containment, different
    projection — so there is one definition of "inside a declared range" and
    not two that can drift (planning#197).

    This one is NOT an authorisation answer, and callers must not read it as
    one. `target_scoped_asset_ids` composes this leg with the domain leg and
    the link leg to decide what a run's scope covers; this function answers
    only the containment question, for planning#175, where the caller needs
    the addresses a CIDR sweep physically covered rather than the assets a
    scope authorises.
    """
    return sorted({value for _, value in _ip_scoped_rows(db, ip_ranges)})


def _ip_scoped_rows(db: Session, ip_ranges: list[str]) -> list[tuple[uuid.UUID, str]]:
    if not ip_ranges:
        return []

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

    found: list[tuple[uuid.UUID, str]] = []
    if bare_ips:
        found.extend(
            db.query(AssetCanonical.id, AssetCanonical.value)
            .filter(AssetCanonical.asset_type == "ip_address", AssetCanonical.value.in_(bare_ips))
            .all()
        )
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
                found.append((asset_id, value))
    return found


@functools.lru_cache(maxsize=4096)
def _parse_network(value: str):
    """`ipaddress.ip_network(value, strict=False)`, or None if it is not a
    network — memoised on the string.

    The strings this is asked about are declared target values, so the
    distinct set is bounded by the target inventory and the cache cannot
    grow with traffic. It exists because the containment loops re-parse the
    SAME pool entry once per candidate: `value_in_target_scope` is called
    once per domain in `scan_executor`'s Phase 1 loop and once per scope
    entry by `entry_in_target_scope`, and each call walks every declared
    range. Measured before adding this, with 500 declared ranges against
    500 IP scope entries, the parsing alone cost 0.65s when every entry was
    covered and 1.3s when none was (the uncovered case walks the whole pool
    before giving up). Both drop to single-digit milliseconds once the
    parse is shared.

    Returning None rather than raising is deliberate: a cached exception
    would have to be re-raised on every hit, and every caller here treats
    an unparseable entry as "skip it", never as an error. Target values are
    validated on create, so an unparseable one is legacy junk, not input.
    """
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def _matches_domain_suffix(candidate: str, domains: list[str]) -> bool:
    """`candidate == d or candidate.endswith("." + d)` for any `d` in
    `domains`. Pure-Python mirror of `_domain_suffix_clause` above — same
    case-sensitive exact-or-suffix rule, kept in lockstep deliberately so
    the SQL path and this in-Python path can't drift apart."""
    return any(candidate == d or candidate.endswith("." + d) for d in domains)


def value_in_target_scope(
    db: Session,
    value: str,
    *,
    domains: list[str],
    ip_ranges: list[str],
) -> bool:
    """Is this single `value` (a bare hostname or a bare IP string, never a
    CIDR) inside declared scope — the value-shaped counterpart to
    `target_scoped_asset_ids`'s id-set answer (planning#128).

    Not implemented by calling `target_scoped_asset_ids`: that function
    returns a set of asset ids, and when a real CIDR is in scope, building
    that set costs a full `ip_address` table scan (see `_ip_scoped_asset_ids`
    above). This function is invoked once per candidate in a loop —
    `is_scan_authorised` once per domain in `scan_executor`'s Phase 1
    discovery loop, and `entry_in_target_scope` once per scope entry — so
    paying a per-call full-table-scan cost would be O(n) full scans across
    each of those loops.

    Two callers, not one. It was written for `is_scan_authorised` and its
    docstring named that as the sole caller, and separately placed the
    call site in `scan_executor`'s **Phase 3**; the Phase 3 filter was
    deleted by planning#148 step 2 and the surviving caller is the Phase 1
    domain loop. Both corrected here (planning#197).

    Leg 1 (`TargetAssetLink`) is deliberately OMITTED here, and this is not
    an oversight. `target_scoped_asset_ids` unions leg 1 because it selects
    assets for *analysis*, where over-inclusion is harmless. This function
    licenses *active probing* and is the sole gate on that path (nothing
    composes a `probe_class` cap on top of it in `scan_executor` Phase 3).
    Leg 1 links every asset in a domain's discovery batch to that domain's
    target — including a CNAME boundary target and a shared-hosting IP that
    belong to a third party. Authorising those would be exactly the
    unauthorised-scanning failure that `_extract_scan_targets`'s
    `third_party` exclusion exists to prevent. Omitting leg 1 makes this
    function's answer a subset of `_scope_cap`'s, i.e. it errs toward deny —
    the correct direction for a gate. Do not "fix" this by adding leg 1.

    `value` is normalised (trimmed, trailing dot stripped, lowercased)
    before anything is compared. This is NOT incidental tidying — it
    replaces normalisation that used to arrive for free. The call sites in
    `scan_executor` previously passed `apex_domain(value)`, and
    `apex_domain` lowercases and strips the trailing dot on its way to the
    registrable apex (`core/apex.py`). Dropping that wrapper — which is
    what fixes the apex-collapsing bug — would otherwise have dropped the
    case folding with it, silently denying `API.EXAMPLE.COM` or
    `api.example.com.` where the old path authorised them. A silent skip is
    the exact failure class planning#128 exists to remove, so the
    normalisation is reproduced here deliberately.

    The declared side needs no such treatment: `target_service` normalises
    every target value on create (trim / strip dot / lowercase / punycode),
    so `domains` and `ip_ranges` are already canonical. Punycode is
    deliberately NOT applied to the candidate — a unicode IDN asset value
    failing to match its punycode target row is a pre-existing gap on the
    asset write path, not something to paper over in the gate.
    """
    value = (value or "").strip().rstrip(".").lower()
    if not value:
        return False

    try:
        ip_obj = ipaddress.ip_address(value)
    except ValueError:
        ip_obj = None

    if ip_obj is not None:
        # Leg 3 — direct containment. A bare-IP target is a /32 or /128
        # network that contains exactly itself, so this also covers the
        # bare-IP-target case with no special-casing.
        for entry in ip_ranges:
            net = _parse_network(entry)
            if net is None:
                continue
            # ipaddress raises TypeError comparing an IPv4 address against
            # an IPv6 network (and vice versa) — only compare same-version.
            if ip_obj.version != net.version:
                continue
            if ip_obj in net:
                return True

        # Leg 2 — resolved from a declared domain: value is an ip_address
        # asset whose parent_value (the terminal hostname it resolved
        # through) is a domain or subdomain of a declared domain target.
        if domains:
            rows = (
                db.query(AssetCanonical.parent_value)
                .filter(AssetCanonical.asset_type == "ip_address", AssetCanonical.value == value)
                .all()
            )
            for (parent_value,) in rows:
                if parent_value and _matches_domain_suffix(parent_value, domains):
                    return True

        return False

    # Not an IP — a name. Match against the declared domains directly.
    return _matches_domain_suffix(value, domains)


# ── The authorisation half: mode semantics, shared by both gates ──────────────
#
# planning#197. Everything above answers *containment* ("is this thing inside
# these domains/ranges"). Everything below answers *authorisation* ("which
# declared targets count as scope at all, under this mode") — the half that
# used to be written out twice, once in `target_service.is_scan_authorised`
# and once in `probe_authorisation._resolve_scoped_ids`, kept in step by hand
# and with the two docstrings each claiming to mirror the other.


def authorised_target_pool(db: Session, auth_mode: str) -> tuple[list[str], list[str]]:
    """The declared target inventory that `auth_mode` counts as authorised,
    bucketed into `(domains, ip_ranges)` — planning#197.

    This is the ONE definition of what the modes mean, and the one place
    the verified-before-containment ordering is expressed:

      acknowledge — every declared target counts (adding it is implicit
                    confirmation).
      strict      — only verified targets count. The narrowing happens
                    HERE, on the declared side, before any containment is
                    computed by the caller. That ordering is the whole
                    point: a verified CIDR must license the addresses
                    inside it, and a verified apex its subdomains, which
                    no equality test against the target's own string
                    value can express.
      anything else — treated as `strict`. Fail closed.

    `disabled` is rejected rather than answered. It means "no scope gate at
    all", which is a statement about whether to consult scope, not about
    which targets are in it; every caller short-circuits on it before
    reaching here, and one that did not would be asking a question with no
    honest answer. Raising makes that a loud error instead of a silently
    over-narrow pool.

    Bucketing classifies from `detect_type(value)`, not from the stored
    `Target.type` column, so a stale or incorrect stored type cannot skew
    either gate. `scan_executor._resolve_dynamic_scope` does the same, for
    the same reason.

    The import of `detect_type` is function-local because `target_service`
    imports this module at module level; hoisting it would be a cycle.
    """
    if auth_mode == "disabled":
        raise ValueError(
            "authorised_target_pool() is not defined for 'disabled' — that mode "
            "means the scope gate is not consulted at all. Short-circuit before "
            "calling (see is_scan_authorised / _resolve_scoped_ids)."
        )

    from app.services.target_service import detect_type

    q = db.query(Target.value)
    if auth_mode != "acknowledge":
        # "strict", and any unrecognised mode — fail closed.
        q = q.filter(Target.verified == True)  # noqa: E712

    domains: list[str] = []
    ip_ranges: list[str] = []
    for (target_value,) in q.all():
        try:
            t_type = detect_type(target_value)
        except ValueError:
            continue
        if t_type == TargetType.DOMAIN:
            domains.append(target_value)
        else:
            ip_ranges.append(target_value)
    return domains, ip_ranges


def entry_in_target_scope(
    db: Session,
    entry: str,
    *,
    domains: list[str],
    ip_ranges: list[str],
) -> bool:
    """Is this *scope entry* covered by the authorised targets — planning#197.

    The entry-shaped counterpart to `value_in_target_scope`. The difference
    between an entry and a value is that an entry may be a **CIDR**: scope
    is `{"domains": [...], "ip_ranges": [...]}`, and an `ip_ranges` member
    can be a network rather than a single address. `value_in_target_scope`
    documents that it is never handed a CIDR, and it is not — a CIDR string
    reaches `ipaddress.ip_address()`, raises, and is then matched as a
    hostname, which silently answers False for a range that is genuinely in
    scope. So ranges are answered here, by subnet containment, and
    everything else is delegated unchanged.

    ## Why this exists at all

    `probe_authorisation._resolve_scoped_ids` used to narrow scope entries
    with `Target.value.in_(declared)` — **string equality** — and only
    under `strict`. That is planning#128's original bug, reintroduced one
    layer up in the very function whose docstring claimed to have fixed it,
    and it produced a divergence in both directions at once (both verified
    live before this was written):

      - under `strict`, TOO NARROW. A scope entry covered by a verified
        target but not equal to one — a subdomain of a verified apex, an
        address inside a verified CIDR, both of which arise from a
        per-asset recheck or a one-shot run whose scope is not itself a
        target row — was dropped. The scope set came back empty and every
        asset in the run was denied `scope:out_of_scope`, while the
        discovery gate authorised the same value. An availability failure
        that would have appeared exactly when planning#148 flips
        enforcement on.
      - under `acknowledge`, TOO WIDE. No entry filter ran at all, so an
        entry no target covers was kept and its assets authorised for
        probing — while the discovery gate denied the same value. The
        probe gate being the more permissive of the two is the wrong
        direction for a gate.

    ## Failure direction

    A range is covered only if it is a subnet of a declared range. A
    partially-overlapping range is NOT covered: half-authorised is not
    authorised, and the deny-by-default reading is the correct one for a
    gate. Mixed address families are skipped rather than compared —
    `subnet_of` raises `TypeError` across versions.

    Normalisation, leg coverage and the deliberate omission of leg 1 are
    all inherited from `value_in_target_scope`; see its docstring. Nothing
    here widens what that function will match.
    """
    entry = (entry or "").strip().rstrip(".").lower()
    if not entry:
        return False

    if "/" not in entry:
        return value_in_target_scope(db, entry, domains=domains, ip_ranges=ip_ranges)

    net = _parse_network(entry)
    if net is None:
        # Not a network, and a bare name cannot contain "/" — nothing can
        # cover it. Deny rather than guess.
        return False

    if net.num_addresses == 1:
        # A "/32" or "/128" written as a range is a single address. Hand the
        # bare address on, so it picks up leg 2 (resolved-through-a-declared-
        # domain) as well as arithmetic containment — a /32 entry and the
        # same address written bare must not answer differently.
        return value_in_target_scope(
            db, str(net.network_address), domains=domains, ip_ranges=ip_ranges
        )

    for candidate in ip_ranges:
        target_net = _parse_network(candidate)
        if target_net is None:
            continue
        if net.version != target_net.version:
            continue
        if net.subnet_of(target_net):
            return True
    return False
