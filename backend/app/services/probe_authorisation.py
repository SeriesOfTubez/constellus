"""Composed probe-authorisation gate (planning#148, slice 1 — the chassis).

This is the single choke point every active-probe connector MUST pass
through before it is handed any asset to send traffic at — Phase 1.5 port
discovery (naabu, banner_grab, httpx_probe, tlsx) and Phase 3 scanning
(nuclei) alike, plus anything added later. As of planning#148 step 2 there
is no active-probe path that bypasses it. A second
inline copy of this decision anywhere else in the codebase — a connector
that reads `asset_state.attributes["probe_class"]` itself and decides,
a script that re-derives "is this ours" ad hoc — is a bug, not a
convenience. This module exists precisely because that duplication is how
the shared-infra false-attribution problem happened in the first place
(see epic#81, and `app.models.observer`'s migration-0039 docstring): once
two code paths can each independently decide "yes, probe this", they will
eventually disagree, and disagreeing about active network traffic against
a third party is the failure this whole claims-layer epic (planning#142)
was built to prevent.

## What it computes

`authorise_probes()` composes three independent caps —
`min(scope, probe_class, posture)`, tightest wins, no cap can widen another
— into one `ProbePermission` per (asset, connector): permitted addressing
modes (`ip`/`name`/`ip_handshake`) plus the concrete set of names authorised
for name-addressed probing. It returns a descriptor, **never a boolean** —
"can we probe this" is not one bit, it's "with what addressing mode, at
what name(s)", and collapsing that to a bool is exactly what let a
name-addressed probe fire at an unauthorised hostname in the first place.

Each cap is owned by a different issue and lands on a different schedule:

  - **scope** (planning#128) — is this address inside declared/authorised
    scope at all. **Real body**, using `target_scope`'s IP/CIDR containment
    and domain-suffix matching. It must NOT be implemented by calling
    `is_scan_authorised`/`apex_domain`: that pairing has a real bug (an IP
    never matches a `Target` row by string equality, and an IP inside a
    declared CIDR fails the same equality check against the CIDR's own
    string value), and wiring this gate to it would inherit that bug at the
    foundation of the thing meant to fix it. See `_scope_cap`.
  - **probe_class** (planning#129 + #143) — is this specific asset's
    projected reachability class (`no_probe` / `name_only` /
    `direct_addressable`, `app.services.projector`) one that permits active
    probing at all. See `_probe_class_cap`.
  - **posture** (planning#132) — engagement posture (pre-close diligence
    vs. post-close monitoring, etc.). **Still a permissive stub.**

Posture is deliberately present-and-permissive rather than omitted. The
whole reason this issue was split from #128/#132 in the first place is so
the *shape* of the composition (three independent, composable caps,
tightest wins) shipped first and is never re-litigated later — a cap that's
absent today and "added" in a future PR is a signature change (and a
re-review of every call site); a cap that's present-and-permissive today
and tightened later is a body change. That bet paid off: filling in scope
(planning#128) touched this function's body and `authorise_probes`'
batch-precompute block, and nothing else. Shipping the narrower version
first and bolting the axis on later is precisely the mistake this
issue-split exists to prevent (see the accompanying planning notes on
#141/#142/#143/#148's design chain).

## Deny-by-default is about connector *declarations*, not asset state

Independent of the three caps above, a connector must declare which
`observers` row is its identity (`connector.observer`, a class attribute —
see the five connector files that declare one) and that row must address
*something* (`addressing != "none"`). A connector with no declaration, an
unrecognised one, or one that claims to emit traffic while addressing
nothing is refused outright — this is what closes the old
`hasattr(c, "port_scan")` duck-typed hole (the Phase 1.5 candidate-set
comprehension in `scan_executor._run_pipeline` — deliberately still
`hasattr`-based, see the comment planted there: an undeclared connector
must reach this gate and be refused *loudly*, not be filtered out of the
candidate list silently): previously, exposing `port_scan` was enough on its
own to get handed every asset in the Phase 1.5 batch. Now the connector
must also assert an identity that resolves to a real, addressing-capable
observer. This check is **always enforced, in both gate modes** (see
below) — an undeclared connector is a code defect to catch at review/CI
time, not a policy question the log-only rollout should be allowed to
ride through.

## Gate mode — why the default must not stop the product scanning

`probe_class` is `direct_addressable` only for an `ip_address` that is
either inside a declared CIDR target *or* (composed tenancy ==
`single_tenant` AND `estate == confirmed_ours`; planning#182 rung 3
replaced `hosting.is_datacenter` here) — and `shared_infra_verifier` (which is what
actually sets `confirmed_ours`) runs *after* Phase 1.5 in the scan
pipeline. On a brand-new target's first run, literally no IP has had a
chance to earn `direct_addressable` yet. Enforcing the probe_class cap by
default would therefore silently stop naabu from ever discovering a first
port on a first run — an availability regression dressed up as a safety
improvement. So the gate ships in **`log_only` mode by default**
(`app_settings.DEFAULTS["probe_authorisation_mode"]`):

  - **`log_only`** — `GateResult.permitted` is the *unfiltered* input list
    (nothing is blocked) and `GateResult.enforced` is `False`. Critically,
    **the decision rows written to `authorisation_decisions` still record
    the real, fully-computed verdict in `allowed`** — i.e. what *would*
    happen under `enforce` — because the entire purpose of the log-only
    rollout is to build up an audit trail an operator can read to decide
    whether the deny rate is understood and safe before flipping the
    switch. A log that only ever wrote `allowed=True` because nothing was
    being enforced would be worthless for that purpose.
  - **`enforce`** — `GateResult.permitted` is the narrowed subset actually
    authorised; `GateResult.enforced` is `True`.

The connector-declaration check above is the one exception: it narrows to
nothing in **both** modes, because it isn't a graduated-rollout policy
question the way the three caps are — it's "does this connector exist and
say who it is", and there's no safe interim state where a connector with
no verifiable identity gets to probe anyway.

## Batching / performance

Every asset handed to `authorise_probes` in one call is resolved to its
`assets_canonical` row (the exact `(asset_type, value[, record_type,
content])` identity key `asset_writer._upsert_canonical_batch` /
`claim_emitter.emit_claims` use — imported lazily from `asset_writer` to
avoid a module-load cycle, matching `claim_emitter`'s own pattern) and its
projected `asset_state` row (`projector.load_states`) via one batched
query each, not one query per asset — the same batching discipline as
`scan_executor._persisted_port_hints` and every reader in
`app.services.claims_query`. Decision-log rows are written with one
batched `INSERT`, never one per asset.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass

from sqlalchemy import insert, tuple_
from sqlalchemy.orm import Session

from app.models.asset_canonical import AssetCanonical
from app.models.authorisation_decision import AuthorisationDecision
from app.models.observer import Observer
from app.models.target import Target
from app.models.target_asset_link import TargetAssetLink
from app.services import app_settings as settings_svc
from app.services import posture
from app.services import projector
from app.services import target_scope

log = logging.getLogger(__name__)

# Addressing modes a probe can actually be issued in. Deliberately NOT the
# full `app.models.observer.OBSERVER_ADDRESSING` vocabulary — "none" means
# "this observer never sends traffic to the target itself" (passive
# discovery/enrichment/verify observers), which is not a probe mode at all,
# it's the absence of one. An observer declaring "none" is refused by the
# connector-declaration check below before this set is ever consulted.
# "ip_handshake" IS a probe mode — it sends traffic — but a strictly
# narrower one than "ip" (a single unauthenticated TLS handshake to a bare
# IP, no payload, no port sweep), which is why it is a separate member
# rather than folded into "ip" (planning#181 Tier 1b).
ADDRESSING_MODES: frozenset[str] = frozenset({"ip", "name", "ip_handshake"})


@dataclass(frozen=True)
class Cap:
    """One independent cap in the `min(scope, probe_class, posture)`
    composition. `None` for `modes`/`names` means "this cap does not
    constrain that axis" — the top of the lattice, so intersecting it with
    anything else is the identity operation and it can never be the thing
    that narrows the result. An empty `frozenset` means the opposite
    extreme: "this cap permits nothing on that axis." `rule` is a short,
    stable, human-and-grep-friendly label (`"probe_class:no_probe"`,
    `"scope:permissive"`, …) used both as the denial reason and as the
    audit trail in `authorisation_decisions.evidence_snapshot`.
    """

    allowed: bool
    modes: frozenset[str] | None
    names: frozenset[str] | None
    rule: str


@dataclass(frozen=True)
class ProbePermission:
    """The allowed-probe descriptor for one (asset, connector) pair. NOT a
    boolean — "can we probe this" is meaningless without "with what
    addressing mode, at what name(s)", which is exactly the distinction a
    bool erases.

    `names` is always the resolved authorised-names set for this asset
    (see `_resolve_authorised_names`), regardless of whether this
    particular connector is name-addressing — it describes what the ASSET
    permits, not what this one connector happened to need. `modes` follows
    the stricter rule noted below: it is the *connector-scoped* outcome,
    empty exactly when this connector was denied.
    """

    allowed: bool
    modes: frozenset[str]  # empty iff not allowed
    names: tuple[str, ...]  # sorted; the authorised names for name-addressed probing
    rule_fired: str | None
    evidence: dict


@dataclass(frozen=True)
class GateResult:
    """The result of one `authorise_probes()` call, covering every asset
    passed in for one connector.

    `enforced` reports whether this call's outcome actually reflects
    enforcement — `True` under the `enforce` setting; also `True` for a
    connector-declaration failure (§ module docstring: that check narrows
    to nothing in both modes, so its `permitted` is never a passthrough);
    and also `True`, as of planning#193, when one or more assets were
    denied by `posture:ma_pre_close` under `log_only` — that denial too
    narrows to nothing in both modes (see `_posture_cap`'s docstring), so
    a `permitted` list that has actually been narrowed must report
    `enforced=True` even though the gate as a whole is still in
    `log_only`. It is `False` only for the ordinary `log_only` path with
    no posture denials, where `permitted` is the unfiltered input and the
    real verdict lives solely in the decision log. Callers that just want
    to know whether to keep going check `permitted` — `enforced` is for
    logging/tests that care WHY `permitted` looks the way it does.
    """

    permitted: list  # subset of the input assets
    permissions: dict[tuple[str, str], ProbePermission]  # (asset_type, value) -> descriptor
    enforced: bool  # False in log-only mode
    # planning#204 — the canonical asset ids, among the assets evaluated in
    # THIS call, whose `probe_class` cap did not license the `ip`
    # addressing mode (i.e. port scanning — naabu/banner_grab are the only
    # two declared `addressing = "ip"`). Derived from `caps[1].modes`
    # inside the per-asset loop, never by re-reading `probe_class` off
    # `state` a second time — if `_probe_class_cap`'s mapping ever changes,
    # this follows automatically instead of silently drifting from it.
    # Assets with `canonical is None` are skipped (no id to report).
    #
    # Understated, not wrong, on the two early-return paths: an empty
    # `assets` list returns the empty default correctly (there is nothing
    # to evaluate), but a connector-declaration failure ALSO returns the
    # empty default even though every asset was in fact denied `ip` —
    # `states` is never loaded on that path, so there is no cap to derive
    # from. Not fixed here: the executor unions this set across every
    # connector in a phase, and a healthy connector's own gate call still
    # reports the true denial for the same assets, so the phase-level count
    # is correct even though this one connector's GateResult understates it.
    #
    # ⚠ One asymmetry with the asset-level surface, found in review and
    # recorded rather than fixed. An UNPROJECTED asset (no `asset_state`
    # row, or a `probe_class` the cap does not recognise) has empty modes,
    # so it lands in this set and raises the run's count — but
    # `api/assets.py` serializes its `probe_class` as `None`, and the UI
    # renders nothing for `None`. A user can therefore see a run count of
    # N and find fewer than N assets that explain it. Both alternatives are
    # worse: excluding unprojected assets would make the count understate a
    # denial that is real and fail-closed by design (§ `_probe_class_cap`),
    # and rendering a line for `None` would put "not authorised" on every
    # asset the projector has simply not reached yet, which is a different
    # and false claim.
    port_scan_unauthorised_ids: frozenset = frozenset()


# ── the three caps ──────────────────────────────────────────────────────────
#
# Separate module-level functions, called by their bare names from
# `authorise_probes` (never bound to a local alias first) so a test can
# monkeypatch exactly one of the three by raw attribute assignment
# (`probe_authorisation._scope_cap = lambda **kw: Cap(...)`) and have the
# other two run their real bodies unchanged — the acceptance test this
# issue is itself built around (see test_probe_authorisation.py).

def _scope_cap(
    db: Session,
    *,
    scope: dict,
    asset_ref,
    canonical: AssetCanonical | None,
    scoped_ids: frozenset[uuid.UUID],
    auth_mode: str,
) -> Cap:
    """Scope cap — planning#128. Real body as of this slice.

    Answers one question: is this asset inside declared, authorised scope?

    ## What it must not do, and why

    It is still NOT implemented by calling
    `target_service.is_scan_authorised(db, apex_domain(value), auth_mode)`.
    That pairing has a real, verified defect: `apex_domain()` returns a
    bare IP unchanged (there's no apex to extract), so an IP address never
    matches a `Target` row by string equality, and an IP *inside* a
    declared CIDR target fails the same equality check against the CIDR's
    own string value — the CIDR row's value is e.g. "203.0.113.0/24", never
    equal to any single address inside it. That is precisely the bug this
    issue exists to fix; wiring the gate to it would inherit the bug at the
    foundation of the thing meant to fix it.

    Instead it uses `target_scope.target_scoped_asset_ids`, which already
    does correct IP/CIDR containment and domain-suffix matching, and which
    `dangling_dns_analyzer` and `shared_infra_verifier` already rely on.
    Membership is by canonical asset id, resolved once per batch — see
    `authorise_probes`, which precomputes `scoped_ids` the same way it
    precomputes `states` for `_probe_class_cap`. Computing it per asset
    would mean a full `ip_address` table scan per asset, because there is
    no CIDR-containment operator over a text column.

    ## How `auth_mode` composes with containment

    The two are orthogonal and both are honoured. Containment answers "is
    this asset inside the declared scope"; `scan_authorisation_mode`
    answers "which declared scope entries count as authorised at all":

      - `disabled` — no scope gate. Permissive, matching the setting's
        documented meaning ("the act of adding a target IS the
        authorisation") and today's default, so this slice changes no
        deployed behaviour on its own.
      - `acknowledge` — the target must exist. Every entry in `scope`
        counts, and the asset must be contained by one of them.
      - `strict` — as `acknowledge`, but only *verified* targets count.
        Narrowing happens on the scope entries before containment is
        computed, not after: a verified CIDR still licenses every address
        inside it, which string equality could never express.

    ## Failure direction

    An asset with no canonical row is DENIED under `acknowledge`/`strict`
    (`scope:unresolved_asset`), not waved through. Containment is defined
    over canonical ids, so an unresolved asset cannot be shown to be in
    scope — and "cannot be shown to be in scope" must not read as "is in
    scope" in a gate whose whole purpose is deny-by-default. It is a
    distinct rule from `scope:out_of_scope` because the remedies differ:
    one is an identity-resolution miss, the other a genuine policy denial,
    and the log-only rollout is read to tell them apart.

    ## Phase 3 (RESOLVED — planning#148 step 2)

    This section previously recorded the interim Phase 3 enforcement —
    `_extract_scan_targets` + `is_scan_authorised`/`apex_domain` in
    `scan_executor.py` — as still in place, and listed the two things
    blocking its retirement. Both are now done and the interim filter is
    DELETED: `nuclei` has a seeded `observers` row (migration 0049,
    `addressing="name"`, following 0039's tlsx/httpx precedent) and
    `NucleiConnector` carries a matching `observer` attribute, so it clears
    the always-enforced connector-declaration check.

    The second blocker dissolved rather than being solved, which is worth
    keeping: Phase 3 was assumed to need reshaping from flat target STRINGS
    to per-asset descriptors. It did not. That string list was always
    DERIVED from assets by `_extract_scan_targets`, so that function is
    itself the adapter, and the entire change was to run it over
    `gate.permitted` instead of over `all_assets`. Under the default
    `log_only` mode `gate.permitted` IS the unfiltered input, so the target
    list is byte-identical to before and only the decision log is new.

    So as of planning#148 step 2 this function is the only path to an
    active probe — Phase 1.5 and Phase 3 alike. The one live caller of
    `is_scan_authorised` left in `scan_executor.py` is the Phase 1
    domain-discovery filter, which gates ENUMERATION, not probing.

    Phase 1.5 port discovery was gated on scope for the first time as of
    the slice that introduced this cap — that was the larger hole.
    """
    _ = asset_ref  # containment is by canonical id; the in-batch ref adds nothing

    if auth_mode == "disabled":
        return Cap(allowed=True, modes=None, names=None, rule="scope:disabled")

    if canonical is None:
        return Cap(allowed=False, modes=frozenset(), names=None, rule="scope:unresolved_asset")

    if canonical.id in scoped_ids:
        return Cap(allowed=True, modes=None, names=None, rule=f"scope:in_scope:{auth_mode}")

    return Cap(allowed=False, modes=frozenset(), names=None, rule=f"scope:out_of_scope:{auth_mode}")


def _resolve_scoped_ids(db: Session, scope: dict, auth_mode: str) -> frozenset[uuid.UUID]:
    """The canonical asset ids inside `scope`, narrowed by `auth_mode`.

    Computed once per `authorise_probes` call. Returns an empty set under
    `disabled` without touching the database — `_scope_cap` short-circuits
    on that mode before ever reading this, so paying for a full scan to
    build a set nobody consults would be waste.

    ## Two steps, and the one that was wrong (planning#197)

    Step 1, **authorisation**: which scope entries count as scope at all
    under this mode. Step 2, **containment**: which canonical assets sit
    inside the surviving entries.

    Step 2 was always right. Step 1 was not. It used to read

        Target.value.in_(declared)

    — string equality between a scope entry and a target's own stored
    value — and it only ran under `strict`. That is exactly the defect
    planning#128 exists to remove, reintroduced one layer up in the
    function whose previous docstring asserted it had been fixed ("what
    makes a verified CIDR license the addresses inside it"). It licensed
    the addresses inside a verified CIDR on the *asset* side while
    discarding the *entry* side by equality, so the two halves disagreed
    with each other.

    Both failure directions were reproduced live before the rewrite, and
    `entry_in_target_scope` records them: too narrow under `strict` (a
    recheck whose scope entry is a subdomain of a verified apex, or an
    address inside a verified CIDR, scoped nothing and denied every asset
    in the run), and too wide under `acknowledge` (no entry filter ran, so
    an entry no target covers was probed while the discovery gate refused
    to enumerate it).

    Both steps are now delegated to `target_scope`, which is also where
    `target_service.is_scan_authorised` gets them, so the mode semantics
    and the verified-before-containment ordering have one definition
    between the two gates rather than two hand-synchronised ones. The
    keyspace difference is the only difference that remains, and it is
    real — see `is_scan_authorised`'s docstring for the precise statement.

    ## The pool is the declared inventory, not this run's scope

    Worth stating because it is the subtlest part of the change. The
    entries being *filtered* are this run's scope; the targets they are
    filtered *against* are every declared target, which is what
    `is_scan_authorised` has always used. Those are different sets — scope
    comes from `scan_executor._resolve_dynamic_scope`, which partitions
    the inventory by tag-based cadence tier, so a scan template's scope is
    a SUBSET of the declared targets.

    Using the run's own scope as its own authorisation pool would make
    "authorised" mean "whatever this template happens to own this cycle".
    Cadence tiers are a scheduling mechanism; they carry no statement
    about what the user permitted. A verified apex authorises its
    subdomains whether or not the tier template currently executing
    happens to own that apex.

    Under the default `disabled` mode this changes nothing, as with every
    slice of planning#128 and #148 before it.
    """
    if auth_mode == "disabled":
        return frozenset()

    domains = list(scope.get("domains") or [])
    ip_ranges = list(scope.get("ip_ranges") or [])
    if not domains and not ip_ranges:
        return frozenset()

    pool_domains, pool_ip_ranges = target_scope.authorised_target_pool(db, auth_mode)
    domains = [
        d for d in domains
        if target_scope.entry_in_target_scope(
            db, d, domains=pool_domains, ip_ranges=pool_ip_ranges
        )
    ]
    ip_ranges = [
        r for r in ip_ranges
        if target_scope.entry_in_target_scope(
            db, r, domains=pool_domains, ip_ranges=pool_ip_ranges
        )
    ]

    return frozenset(target_scope.target_scoped_asset_ids(db, {
        "domains": domains,
        "ip_ranges": ip_ranges,
    }))


def _resolve_ma_pre_close_ids(db: Session, canonical_ids: set[uuid.UUID]) -> frozenset[uuid.UUID]:
    """The subset of `canonical_ids` linked — via `target_asset_links` — to
    at least one `targets` row with `ma_pre_close = True` (planning#193).

    Computed once per `authorise_probes` call, the same pattern as
    `_resolve_scoped_ids` above: one query bounded by `canonical_ids`, not
    a lookup per asset. This is the direct answer to the planning#193
    hand-off's "untested at scale, runs per asset per connector" concern —
    membership is a single set built once and consulted per asset in the
    loop, exactly like `scoped_ids`.

    Returns an empty set immediately, without touching the database, when
    `canonical_ids` is empty — mirroring `_resolve_scoped_ids`'s
    short-circuit on `disabled` mode.

    ## Any linked target wins

    `target_asset_links` is N-to-N. If an asset is linked to one pre-close
    target and three ordinary ones, it is STILL DENIED — the presence of
    ordinary targets does not dilute or overrule the pre-close flag. The
    flag is a statement that someone has not authorised this system to
    touch the asset; one target's authorisation cannot cancel another
    target's lack of it. Fail closed.
    """
    if not canonical_ids:
        return frozenset()

    rows = (
        db.query(TargetAssetLink.asset_canonical_id)
        .join(Target, Target.id == TargetAssetLink.target_id)
        .filter(
            TargetAssetLink.asset_canonical_id.in_(canonical_ids),
            # planning#196 step 2 — the predicate itself lives in
            # `app.services.posture`, not inline here. This is the SQL
            # rendering; `authorise_discovery` below uses the Python one
            # (`posture.is_passive_only`) over an already-loaded row. Two
            # query shapes, ONE policy — so planning#132's eventual move
            # from a boolean to a posture enum is one edit in one file,
            # not a hunt for every inline `ma_pre_close` comparison.
            posture.passive_only_filter(),
        )
        .distinct()
        .all()
    )
    return frozenset(r[0] for r in rows)


def _probe_class_cap(db: Session, *, asset_ref, canonical: AssetCanonical | None, state) -> Cap:
    """Probe-class cap — the only cap with a real body in this slice.

    Reads `state.attributes["probe_class"]` (`app.services.projector`,
    planning#129 + #143) and maps it straight onto a permitted addressing
    set:

      - `"no_probe"` — third-party-boundary or provider-managed-MX asset;
        never probe it at all (empty modes).
      - `"name_only"` — not inside a declared CIDR and not a confirmed
        single-tenant address of ours; licenses `name` (SNI/Host-header
        probing) **and** `ip_handshake` — one unauthenticated TLS handshake
        to one port on the bare address: no port sweep, no payload, no
        application-layer request. `ip_handshake` is licensed here because
        an address whose tenancy is undetermined cannot otherwise produce
        the certificate evidence that would resolve its tenancy — the rung
        that needs the evidence is denied by the very state the evidence
        would clear (planning#181 §4's circularity). It is a deliberate,
        argued widening of the gate, not an oversight, and it is granted
        per-asset through the normal cap composition so every use of it
        lands in `authorisation_decisions` and is auditable and reversible.
        The alternative — collecting the same evidence from a background
        job declaring `addressing = "none"` — would route around the gate
        silently and was rejected. Full `ip` probing (a bare-IP connect,
        a port sweep) remains denied at `name_only`: `ip_handshake` does
        NOT imply `ip`. Note the three reasons an address lands here are
        NOT separable from this rule string — see the `tenancy` key in
        `_compose`'s evidence.
      - `"direct_addressable"` — inside a declared CIDR, or a composed
        `single_tenant` address with a confirmed-ours affinity verdict
        (planning#182 rung 3); all three modes (`ip`, `name`,
        `ip_handshake`) licensed.
      - anything else — **deny**, under one of two DISTINCT rules, because
        they are different failures and the decision log is read to tell
        them apart:

          - `"unresolved_asset"` — no canonical row matched this in-batch
            asset at all, so there is nothing to look a projection up for.
            The common cause is an identity-key miss, not a missing
            projection: `_canonical_key` includes `record_type`/`content`
            for `dns_record`, so a bare `DiscoveredAsset(asset_type=
            "dns_record", value=...)` carrying neither (the `skip_discovery`
            seeds at `scan_executor.py`'s Phase 1 branch, and CT/subfinder/
            bruteforce's bare rows) will not match a *typed* canonical row
            for the same hostname. Deliberately NOT resolved by falling
            back to an `(asset_type, value)` match: that is precisely the
            ambiguity the composite key exists to prevent (see
            `finding_writer`'s `asset_id` override comment for the same
            hazard), and picking an arbitrary A/AAAA/MX row to authorise a
            probe against would be worse than declining to.
          - `"probe_class:unprojected"` — the canonical row resolved fine
            but has no `asset_state` row, or one whose `probe_class` is
            missing or not one of the three recognised strings (a projector
            bug, schema drift, a stale/partial row).

        Both fail closed: an asset we cannot currently vouch for is an
        asset we do not probe. Keeping them as separate rules matters
        because a log-only rollout is read to decide whether enforcing is
        safe, and "we could not identify this asset" and "this asset has
        never been projected" call for completely different remedies —
        collapsing them into one label would make the deny rate
        uninterpretable. This is a real, permanent denial — NOT a stub
        awaiting a future issue — and it is safe to ship as a hard `deny`
        specifically *because* the gate defaults to `log_only` mode
        (§ module docstring): on a fresh install where nothing has been
        projected yet, this cap would deny every asset if it were
        enforced, but in `log_only` it only records that fact for
        inspection while `naabu` et al. keep scanning as they do today.

    `db`/`asset_ref` are accepted for signature symmetry with the other two
    caps and because a future revision of this cap shouldn't need a
    signature change — unused today. `canonical` IS used, for the
    `unresolved_asset` branch above.
    """
    _ = (db, asset_ref)  # unused this slice — see docstring
    if canonical is None:
        return Cap(False, frozenset(), None, "unresolved_asset")
    if state is None:
        return Cap(False, frozenset(), None, "probe_class:unprojected")

    probe_class = (state.attributes or {}).get("probe_class")
    if probe_class == "no_probe":
        return Cap(False, frozenset(), None, "probe_class:no_probe")
    if probe_class == "name_only":
        return Cap(True, frozenset({"name", "ip_handshake"}), None, "probe_class:name_only")
    if probe_class == "direct_addressable":
        return Cap(True, frozenset({"ip", "name", "ip_handshake"}), None, "probe_class:direct_addressable")
    return Cap(False, frozenset(), None, "probe_class:unprojected")


def _posture_cap(
    db: Session, *, scope: dict, asset_ref, canonical: AssetCanonical | None,
    ma_pre_close_ids: frozenset[uuid.UUID], noise_class: str | None,
) -> Cap:
    """Posture cap — engagement posture (pre-close diligence vs. post-close
    monitoring, etc.), planning#132. planning#193 gives it its first real
    body: pre-close M&A denial. planning#196 step 2 makes that denial
    depend on the CALLING OBSERVER's noise class rather than firing
    unconditionally for every asset linked to a pre-close target — see the
    dedicated section below. The rest of the posture axis (post-close
    monitoring and whatever else #132 eventually enumerates) remains
    permissive until that issue lands — this is a body change on an
    already-composed cap, not the cap's introduction, exactly as the
    module docstring's "present-and-permissive" bet intended.

    `db`/`scope`/`asset_ref` remain unused this slice, for the same
    forward-signature-stability reason `_scope_cap` documents; kept in the
    signature so a future #132 body change does not also have to touch
    every call site again.

    ## Why this cap takes the observer's noise class (planning#196)

    Before planning#196, this cap denied EVERY asset linked to a pre-close
    target regardless of which observer was asking — no `noise_class`
    parameter existed, so there was nothing else it could do. That was
    correct only BY ACCIDENT: every connector that reaches this gate today
    (naabu, banner_grab, httpx, tlsx, nuclei, tenancy_tls) happens to be
    seeded with `noise_class="target_host"`, the noisiest class, so
    "deny unconditionally" and "deny because target_host is denied under
    passive-only" produced the same answer for every asset this cap has
    ever actually been asked about. Leaving that unconditional shape in
    place while the discovery phase (`probe_authorisation.
    authorise_discovery`, added in this same step) consults `noise_class`
    to decide the identical question would express one policy two
    different ways — exactly the drift planning#196 exists to remove (see
    `app.services.posture`'s module docstring). Behaviour is unchanged
    TODAY precisely because of that accident: every real caller of this
    cap still passes `noise_class="target_host"`, so
    `posture.observer_permitted` still denies it exactly as the old
    unconditional check did. `test_posture_policy.py`'s
    `test_posture_cap_permits_a_pre_close_asset_for_a_silent_observer`
    pins the new, real branch (a hypothetical silent asset-shaped observer
    would now be permitted) alongside the unchanged one.

    `asset_ref`/`canonical` are here because posture is **per-asset, not
    tenant-global**. The M&A case is the one that forces it: an acquired
    company's cloud lands in its own Wiz Project (or its own Wiz tenant
    entirely), and the engagement posture that applies to those assets —
    pre-close diligence, where the acquirer may hold no authorisation to
    probe at all — differs from the posture over the parent org's own
    estate at the same instant. A posture cap that could only read a
    global setting would be structurally unable to express that, and #132
    would have to widen this signature and revisit every call site and
    test. Taking the asset now costs nothing and keeps #132 a body change.

    ## `posture:ma_pre_close` is always-enforced, in BOTH gate modes

    Every other cap's denial is subject to `probe_authorisation_mode`
    (module docstring, "Gate mode"): under `log_only`,
    `GateResult.permitted` is the unfiltered list regardless of what the
    caps decided, because `probe_authorisation_mode` is a graduated-rollout
    switch for verdicts THIS SYSTEM INFERS — scope containment, projected
    reachability class. A pre-close M&A flag is not inferred; an operator
    asserted it directly on the target. There is no safe interim state in
    which a target an operator has explicitly marked "we are not
    authorised to touch this" gets probed anyway just because the rollout
    hasn't reached `enforce` yet — the same argument the
    connector-declaration check (`_resolve_connector_observer`) already
    makes for itself, and enforced the same way: see `authorise_probes`'
    `posture_denied` handling, not a mode check in this function.

    ## `canonical is None` is deliberately PERMISSIVE here

    An unresolved asset is not denied by this cap, even though that reads
    as the more cautious choice. Two reasons:

      1. It is already denied by `_scope_cap`'s `scope:unresolved_asset` —
         this cap does not need to duplicate that denial to close the same
         hole.
      2. If posture denied unresolved assets too, the always-enforced path
         (§ above) would turn into a global block on every unresolved
         asset in every scan in every deployment, M&A or not — an
         availability regression far larger than the hole it would close.

    The hole this leaves is narrow, not open-ended: Phase 1 writes
    `target_asset_links` (`scan_executor._run_pipeline`'s domain loop, the
    `write_assets(..., target_ids=target_ids)` call) before Phase 1.5 ever
    calls this gate, so an asset discovered THIS run against a pre-close
    target is already linked — and therefore already resolved to a
    canonical row — by the time it reaches here. The residual case is a
    `skip_discovery` run (a per-asset recheck) against an asset that was
    never linked by any previous run; that asset arrives with `canonical
    is None` and slips this cap, but is still caught by `_scope_cap`.
    """
    _ = (db, scope, asset_ref)  # unused this slice — see docstring
    if canonical is not None and canonical.id in ma_pre_close_ids:
        if not posture.observer_permitted(passive_only=True, noise_class=noise_class):
            return Cap(allowed=False, modes=frozenset(), names=None, rule="posture:ma_pre_close")
    return Cap(allowed=True, modes=None, names=None, rule="posture:permissive")


# ── authorised names ────────────────────────────────────────────────────────

def _resolve_authorised_names(canonical: AssetCanonical | None) -> frozenset[str]:
    """The concrete names a name-addressed probe is authorised to use for
    this asset, resolved from the canonical row alone — no new inference,
    no new query, no re-derivation of anything `target_scope`/`projector`
    already established:

      - `dns_record` — `{canonical.value}` (the record's own hostname).
      - `ip_address` — `{canonical.parent_value}` if set, else empty.
        `parent_value` on an `ip_address` row is the terminal hostname
        `dns_resolve` resolved *through* to reach this IP (see
        `target_scope.py`'s leg-2 comment for the same field, same
        meaning — reused here, not redefined).
      - anything else (no canonical row at all; an asset type with no
        established naming convention) — empty.

    Known narrowing, accepted deliberately: an IP with several hostnames
    pointing at it only ever carries ONE `parent_value` (whichever
    resolution last wrote it), so this under-reports the true set of names
    that legitimately reach that IP. Under-reporting names is safe here —
    fewer authorised names means a *tighter* gate, consistent with
    deny-by-default — whereas over-reporting would not be. Planning#128 is
    expected to widen this (e.g. by joining every `dns_record` that
    resolves to the IP) once the scope cap's real body exists to compose
    with it.

    Deliberately NOT `shared_infra_verifier._owned_hostnames_for_ip`: that
    function answers a different question (which hostnames' *ownership
    claims* does this IP corroborate, for finding-attribution purposes) and
    returns a different shape (a verification-oriented structure, not a
    plain authorised-name set for gating a probe). Reusing it here would
    conflate "what can we say this IP is associated with" with "what names
    are we authorised to send traffic to" — two different epistemic
    questions that happen to share an IP.
    """
    if canonical is None:
        return frozenset()
    if canonical.asset_type == "dns_record":
        return frozenset({canonical.value}) if canonical.value else frozenset()
    if canonical.asset_type == "ip_address":
        return frozenset({canonical.parent_value}) if canonical.parent_value else frozenset()
    return frozenset()


# ── connector declaration (deny-by-default on the connector itself) ────────

def _resolve_connector_observer(db: Session, connector: object) -> tuple[Observer | None, str | None]:
    """Resolve `connector.observer` (a class attribute — see the four
    Phase 1.5 connector files) to its seeded `observers` row.

    Returns `(observer_row, None)` when the connector is properly declared
    and its observer addresses something; `(observer_row_or_None,
    denial_rule)` otherwise, where `denial_rule` is one of:

      - `"undeclared_observer"` — no `observer` attribute at all (or it's
        falsy). This is the old `hasattr(c, "port_scan")` hole, closed:
        exposing `port_scan` used to be sufficient to get handed every
        asset in the batch; now the connector must also assert a
        verifiable identity.
      - `"unknown_observer"` — the declared slug isn't a seeded
        `observers.name`. Almost certainly a typo or a connector renamed
        without updating its declaration.
      - `"observer_addressing_none"` — the observer resolves fine, but its
        seeded `addressing` is `"none"` — i.e. it's registered as an
        observer that never sends traffic to the target itself (a
        discovery/verify/enrich role). A Phase 1.5 connector that emits
        traffic but claims to address nothing is misconfigured, not
        passive; passive producers don't expose `port_scan` in the first
        place.

    Any of these three fails **regardless of `probe_authorisation_mode`**
    — see the module docstring's "Gate mode" section for why this one
    check is not subject to the log-only rollout.
    """
    slug = getattr(connector, "observer", None)
    if not slug:
        return None, "undeclared_observer"
    row = db.query(Observer).filter(Observer.name == slug).first()
    if row is None:
        return None, "unknown_observer"
    if row.addressing == "none":
        return row, "observer_addressing_none"
    return row, None


# ── canonical-row resolution (batched) ──────────────────────────────────────

def _canonical_key_for(asset) -> tuple:
    """The same `(asset_type, value[, record_type, content])` identity key
    `asset_writer._upsert_canonical_batch` uses to resolve a
    `DiscoveredAsset` to its canonical row — imported lazily to avoid a
    module-load cycle (mirrors `claim_emitter.emit_claims`'s identical lazy
    import of the same private helper, for the same reason: by the time
    this function actually runs, `asset_writer` has already fully executed
    its module body, so the import is safe; importing it at this module's
    load time would not be, since nothing here needs to load before
    `asset_writer` in the first place, but keeping the import local matches
    the established convention rather than inventing a second one).
    """
    from app.services.asset_writer import _canonical_key

    meta = getattr(asset, "asset_metadata", None) or {}
    return _canonical_key(asset.asset_type, asset.value, meta.get("record_type"), meta.get("content"))


def _resolve_canonical_batch(db: Session, assets: list) -> dict[tuple, AssetCanonical]:
    """One batched query resolving every asset in `assets` to its canonical
    row, keyed by the same identity key `_canonical_key_for` computes for
    each asset — never one query per asset. Every entry in `assets` at
    Phase 1.5 has already been through `write_assets` (see module
    docstring), so in the ordinary case every key resolves; a miss simply
    means the caller gets `None` back for that asset (handled throughout
    this module — a decision can still be logged with a NULL
    `asset_canonical_id`, per `AuthorisationDecision`'s own docstring).
    """
    from app.services.asset_writer import _canonical_key

    type_value_pairs = {(a.asset_type, a.value) for a in assets}
    if not type_value_pairs:
        return {}

    rows = (
        db.query(AssetCanonical)
        .filter(tuple_(AssetCanonical.asset_type, AssetCanonical.value).in_(list(type_value_pairs)))
        .all()
    )
    return {_canonical_key(r.asset_type, r.value, r.record_type, r.content): r for r in rows}


# ── composition ──────────────────────────────────────────────────────────────

def _cap_evidence(cap: Cap) -> dict:
    """One cap's contribution to `evidence_snapshot`, JSON-safe (frozensets
    turned into sorted lists so the JSONB column can store them)."""
    return {
        "allowed": cap.allowed,
        "modes": sorted(cap.modes) if cap.modes is not None else None,
        "names": sorted(cap.names) if cap.names is not None else None,
        "rule": cap.rule,
    }


def _compose(
    caps: tuple[Cap, Cap, Cap],
    *,
    connector_id: str,
    observer_slug: str,
    observer_addressing: str,
    observer_noise_class: str | None,
    canonical: AssetCanonical | None,
    asset_ref,
    state,
    mode: str,
    scan_run_id: uuid.UUID | None,
) -> ProbePermission:
    """Compose the three caps (`scope`, `probe_class`, `posture`, in that
    fixed order) into one `ProbePermission` for this (asset, connector)
    pair.

    `min()` composition: the asset is allowed only if every cap allows it;
    the permitted addressing modes are `ADDRESSING_MODES` intersected with
    every cap that actually constrains that axis (a cap with `modes=None`
    contributes nothing to the intersection — "top of the lattice", see
    `Cap`'s docstring); the authorised names are the canonical row's own
    resolved names (`_resolve_authorised_names`), further narrowed by any
    cap that constrains the names axis (none does, in this slice — see
    each cap's docstring — so this is currently a no-op narrowing, present
    for when #128/#132 add a real names constraint).

    `rule_fired`:
      - if the composed caps deny (`not all(c.allowed ...)`), it is
        **the posture cap's rule if posture denied, regardless of whether
        scope or probe_class also denied** — otherwise the `.rule` of the
        first cap, in scope → probe_class → posture order, that returned
        `allowed=False`. This precedence flip is planning#193's: the
        reported rule must be the rule that ACTUALLY blocks. Under
        `log_only`, posture is the only one of the three caps whose denial
        takes effect (§ `_posture_cap`'s docstring, "always-enforced") —
        reporting `scope:out_of_scope` for an asset that is in fact being
        blocked because its target is pre-close M&A would put a
        misleading reason in the one table planning#189 established is
        read to make policy decisions from. Nothing about the other two
        caps' own verdicts is lost by this — `evidence["caps"]["scope"]`
        and `evidence["caps"]["probe_class"]` still carry each cap's
        independent verdict regardless of which one wins `rule_fired`.
      - else, if the connector's own declared `addressing` isn't in the
        composed `modes`, it's `"addressing_not_permitted"`.
      - else, if the connector is name-addressing and the resolved names
        are empty, it's `"no_authorised_names"` — the concrete meaning of
        "name-only is meaningless without *which* names" (planning#129
        delta 1): a cap can license name-addressed probing in the abstract,
        but if there is no actual name to address, there is nothing
        licensed to do.
      - else (allowed), it's the `.rule` of the first cap that actually
        narrowed `modes` below `ADDRESSING_MODES`, or `"unconstrained"` if
        none did. Note `direct_addressable`'s own modes
        (`{"ip", "name", "ip_handshake"}`) equal the full `ADDRESSING_MODES`
        set, so a fully-open `direct_addressable` asset reports
        `"unconstrained"` too — that's intentional: "unconstrained"
        describes the OUTCOME (nothing is restricting this decision), not
        "no cap fired".

    `ProbePermission.modes` is forced to the empty set whenever the final
    outcome is denied (whatever the reason), so `modes` empty <=> not
    allowed holds unconditionally for callers that only look at `modes`.
    `ProbePermission.names` is populated from the resolved name set
    regardless of the outcome — it describes what the ASSET authorises,
    which is meaningful audit information even for a denial (e.g. it shows
    whether "no_authorised_names" or "addressing_not_permitted" was the
    denial's real cause).
    """
    scope_cap, probe_cap, posture_cap = caps

    composed_allowed = all(c.allowed for c in caps)

    modes: set[str] = set(ADDRESSING_MODES)
    narrowing_rule: str | None = None
    for cap in caps:
        if cap.modes is None:
            continue
        narrowed = modes & cap.modes
        if narrowing_rule is None and narrowed != modes:
            narrowing_rule = cap.rule
        modes = narrowed
    composed_modes = frozenset(modes)

    cap_name_constraints = [c.names for c in caps if c.names is not None]
    cap_names = frozenset.intersection(*cap_name_constraints) if cap_name_constraints else None
    resolved_names = _resolve_authorised_names(canonical)
    names = resolved_names if cap_names is None else (cap_names & resolved_names)
    sorted_names = tuple(sorted(names))

    evidence = {
        "connector_id": connector_id,
        "observer": observer_slug,
        "observer_addressing": observer_addressing,
        "probe_class": (state.attributes or {}).get("probe_class") if state is not None else None,
        # planning#182 / planning#177 acceptance criterion 3. `rule_fired`
        # cannot separate the three ways an IP lands at `name_only` — never
        # enriched, enriched but unanswerable, and a genuine "not a
        # single-tenant address" — because all three project the same
        # probe_class and an ip-addressing connector reports
        # `addressing_not_permitted` for all of them. The composed verdict's
        # own `rule` field does separate them (`no_rungs_reported` /
        # `all_rungs_undetermined` / `dissent_wins_outright`, see
        # `projector._compose_tenancy`), so it rides on the decision row at
        # the TOP level rather than nested under `caps` — the #148 flip is
        # decided by counting these rows, and the deny rate has to be one
        # GROUP BY away, not a JSON path spelunk.
        #
        # Deliberately NOT recomputed here: this gate reads the projection,
        # it does not re-derive it. A second copy of the composition rule in
        # this module is exactly the duplication the module docstring calls a
        # bug rather than a convenience.
        "tenancy": (state.attributes or {}).get("tenancy") if state is not None else None,
        "observer_noise_class": observer_noise_class,
        # Distinguishes this asset-shaped decision row from the
        # domain-shaped rows `authorise_discovery` writes (planning#196
        # step 2), so a query over the log does not have to infer the
        # shape from `asset_canonical_id IS NULL` — that column alone is
        # ambiguous, because the asset path also writes NULL-canonical
        # rows for an unresolved asset (see `_decision_row`).
        "decision_scope": "asset",
        # planning#195 made `asset_canonical_id` `ON DELETE SET NULL`, so an
        # orphaned row would otherwise retain no trace of what it was
        # about. Derived from `canonical` (not the in-batch asset ref)
        # deliberately: orphaning can only happen where a canonical row
        # existed, so that is exactly the population this needs to cover,
        # and reading it off `canonical` avoids widening this function's
        # signature. Flat keys, not a nested object — `authorise_discovery`
        # below already carries a flat `"domain": domain` for the same
        # purpose, and flat keys stay `GROUP BY`-able.
        # planning#209 — identity falls back to the IN-BATCH asset when no
        # canonical row matched. `canonical is None` is not a rare edge: it
        # is exactly the `unresolved_asset` denial, and it is the one branch
        # where `asset_canonical_id` is ALSO null, so reading identity off
        # `canonical` alone left that row unattributable in both directions
        # at once. planning#195 added these keys so an orphaned row would
        # still say what it was about; it read them off the object that is
        # missing in the case being guarded against.
        #
        # The in-batch ref always has both — `authorise_probes` keys
        # `permissions` on `(asset.asset_type, asset.value)` one line after
        # calling this, so they are load-bearing already. `canonical` still
        # wins when present: it is the durable identity, and for a
        # `dns_record` it is the row the composite key actually resolved to.
        "asset_type": canonical.asset_type if canonical is not None else getattr(asset_ref, "asset_type", None),
        "asset_value": canonical.value if canonical is not None else getattr(asset_ref, "value", None),
        "gate_mode": mode,
        "scan_run_id": str(scan_run_id) if scan_run_id is not None else None,
        "caps": {
            "scope": _cap_evidence(scope_cap),
            "probe_class": _cap_evidence(probe_cap),
            "posture": _cap_evidence(posture_cap),
        },
    }

    if not composed_allowed:
        # posture wins the rule_fired slot over scope/probe_class when it
        # denied, regardless of composition order — see the docstring
        # above ("rule_fired") for why: it's the only one of the three
        # whose denial is not subject to the log_only rollout, so it's the
        # only one that's guaranteed to actually be the operative reason.
        denial_rule = posture_cap.rule if not posture_cap.allowed else next(c.rule for c in caps if not c.allowed)
        return ProbePermission(False, frozenset(), sorted_names, denial_rule, evidence)

    if observer_addressing not in composed_modes:
        return ProbePermission(False, frozenset(), sorted_names, "addressing_not_permitted", evidence)

    if observer_addressing == "name" and not names:
        return ProbePermission(False, frozenset(), sorted_names, "no_authorised_names", evidence)

    return ProbePermission(True, composed_modes, sorted_names, narrowing_rule or "unconstrained", evidence)


# ── decision-log writer ──────────────────────────────────────────────────────

def _decision_row(canonical: AssetCanonical | None, observer_row: Observer | None, permission: ProbePermission) -> dict:
    return {
        "asset_canonical_id": canonical.id if canonical is not None else None,
        "observer_id": observer_row.id if observer_row is not None else None,
        "allowed": permission.allowed,
        "probe_modes": sorted(permission.modes),
        "authorised_names": list(permission.names),
        "rule_fired": permission.rule_fired,
        "evidence_snapshot": permission.evidence,
    }


def _write_decisions(db: Session, rows: list[dict]) -> None:
    """One batched INSERT for every decision row this call produced —
    never one INSERT per asset (planning#148 §3.7).

    A write failure here must NEVER fail the scan that's in progress: the
    `ProbePermission`/`GateResult` this call returns to its caller are
    already fully computed by the time this runs, so a logging failure
    only loses the audit trail, never widens what was actually authorised.
    Rolled back on failure so a poisoned transaction here can't cascade
    into the surrounding Phase 1.5 loop's own later commits (the same
    concern `scan_executor._run`'s chunk-failure handler documents for
    exactly this class of bug).
    """
    if not rows:
        return
    try:
        db.execute(insert(AuthorisationDecision.__table__), rows)
        db.commit()
    except Exception:
        log.exception(
            "probe_authorisation: failed to write %d decision row(s) — "
            "the permission already returned to the caller is unaffected, "
            "only this audit trail entry is lost",
            len(rows),
        )
        db.rollback()


# ── the gate ─────────────────────────────────────────────────────────────────

def authorise_probes(
    db: Session,
    *,
    connector_id: str,
    connector: object,
    assets: list,
    scope: dict,
    scan_run_id: uuid.UUID | None = None,
) -> GateResult:
    """Authorise `assets` for `connector`, composing the three caps and the
    connector-declaration check into one `GateResult`.

    `connector` is accepted as a loosely-typed `object` (duck-typed, like
    the rest of the Phase 1.5 machinery) — the only attribute this
    function reads off it is `.observer`. `assets` is similarly loose
    (`list`, not `list[DiscoveredAsset]`): the only attributes read are
    `.asset_type`, `.value`, and `.asset_metadata`, which is the same
    minimal contract `claim_emitter`/`asset_writer` already rely on.

    See the module docstring for the full mode/composition/audit-trail
    story; in short: `GateResult.permitted` is the narrowed subset under
    `enforce`, but the FULL unfiltered `assets` list under the default
    `log_only` — while `authorisation_decisions` rows always carry the
    real, fully-computed verdict either way, because the log-only rollout
    exists to be read, not to be a no-op.
    """
    mode = settings_svc.get(db, "probe_authorisation_mode")
    enforce = mode == "enforce"

    if not assets:
        return GateResult(permitted=[], permissions={}, enforced=enforce)

    observer_row, declaration_rule = _resolve_connector_observer(db, connector)
    canonical_by_key = _resolve_canonical_batch(db, assets)

    if declaration_rule is not None:
        # Always-enforced, non-mode-gated (module docstring, "Gate mode"):
        # a connector that can't prove its own identity gets nothing,
        # regardless of `probe_authorisation_mode` — reopening the old
        # hasattr(c, "port_scan") hole permissively here would defeat the
        # entire point of this check.
        permissions: dict[tuple[str, str], ProbePermission] = {}
        rows: list[dict] = []
        for asset in assets:
            canonical = canonical_by_key.get(_canonical_key_for(asset))
            permission = ProbePermission(
                allowed=False,
                modes=frozenset(),
                names=(),
                rule_fired=declaration_rule,
                evidence={
                    "connector_id": connector_id,
                    "observer": getattr(connector, "observer", None),
                    "observer_addressing": observer_row.addressing if observer_row is not None else None,
                    "probe_class": None,
                    # Same key as the composed path above, always present so a
                    # count over `evidence_snapshot->'tenancy'` never has to
                    # special-case which branch wrote the row. Null here is
                    # correct and not a gap: the connector was refused on its
                    # own declaration, before any asset state was consulted.
                    "tenancy": None,
                    # Same discipline as `tenancy` above, for the same reason:
                    # always present so a query never has to special-case this
                    # branch. See `_compose`'s evidence dict for what
                    # `decision_scope` separates.
                    "observer_noise_class": observer_row.noise_class if observer_row is not None else None,
                    "decision_scope": "asset",
                    # planning#195 — same discipline as `tenancy`/
                    # `observer_noise_class` above: always present so an
                    # orphaned row (asset_canonical_id now ON DELETE SET
                    # NULL) still says what it was about.
                    #
                    # planning#209 — and falling back to the in-batch `asset`
                    # (in scope in this loop, and already keying
                    # `permissions` below) when nothing resolved, for the
                    # reason spelled out on `_compose`'s copy of these two
                    # keys. This path matters MORE than that one, not less:
                    # it denies every asset in the batch for a whole
                    # connector, so an unattributable row here loses the
                    # whole batch rather than one asset.
                    "asset_type": canonical.asset_type if canonical is not None else asset.asset_type,
                    "asset_value": canonical.value if canonical is not None else asset.value,
                    "gate_mode": mode,
                    "scan_run_id": str(scan_run_id) if scan_run_id is not None else None,
                    "caps": {},
                },
            )
            permissions[(asset.asset_type, asset.value)] = permission
            rows.append(_decision_row(canonical, observer_row, permission))
        _write_decisions(db, rows)
        # WARNING, not INFO: this is a code/seed defect (a connector that
        # can't prove its identity), not a policy outcome, and it silences
        # a whole connector for the rest of the run. The caller's own "no
        # assets authorised" line is INFO because a full denial can be a
        # perfectly legitimate composed verdict — this one never is.
        log.warning(
            "Probe gate: connector %s denied outright — %s (declared observer: %r). "
            "It will emit no probes until this is fixed; see planning#148.",
            connector_id, declaration_rule, getattr(connector, "observer", None),
        )
        return GateResult(permitted=[], permissions=permissions, enforced=True)

    # observer_row is resolved and addresses something (ip/name/ip_handshake)
    # beyond this point — safe to read observer_row.name/.addressing directly.
    canonical_ids = {c.id for c in canonical_by_key.values()}
    states = projector.load_states(db, canonical_ids)
    # Batch-resolved once, like `states` above and for the same reason: the
    # scope cap's containment check is set membership, but BUILDING the set
    # costs a full ip_address scan when a real CIDR is in scope (there is no
    # CIDR-containment operator over a text column). Per-asset resolution
    # would repeat that scan for every asset in the batch.
    auth_mode = settings_svc.get(db, "scan_authorisation_mode") or "strict"
    scoped_ids = _resolve_scoped_ids(db, scope, auth_mode)
    # planning#193 — resolved once per call, the same batching discipline
    # as scoped_ids/states above: one query bounded by canonical_ids, not
    # a lookup per asset.
    ma_pre_close_ids = _resolve_ma_pre_close_ids(db, canonical_ids)

    permitted: list = []
    permissions = {}
    rows = []
    # planning#193 — assets denied specifically by posture, tracked
    # separately from `permitted` because posture denial is
    # always-enforced (§ `_posture_cap` docstring) and must narrow the
    # `log_only` return below even though nothing else does. Detected from
    # the cap itself, NOT from `rule_fired`: `_compose` now prefers
    # posture's rule when posture denies (§193, precedence flip), but an
    # asset could in principle be denied by scope/probe_class alone with
    # posture separately permissive, and the reverse check (deriving
    # "posture denied" from rule_fired) would only be safe because of that
    # flip — checking the cap directly is simpler and doesn't depend on
    # `_compose`'s internals staying in sync with this loop.
    posture_denied: set[tuple[str, str]] = set()
    # planning#204 — see GateResult.port_scan_unauthorised_ids' docstring
    # for the exact definition. Built alongside `posture_denied` in the
    # same loop, from the same per-asset `caps` tuple, for the same reason:
    # one pass, no second read of `state`.
    port_scan_unauthorised_ids: set[uuid.UUID] = set()

    for asset in assets:
        canonical = canonical_by_key.get(_canonical_key_for(asset))
        state = states.get(canonical.id) if canonical is not None else None

        caps = (
            _scope_cap(
                db, scope=scope, asset_ref=asset, canonical=canonical,
                scoped_ids=scoped_ids, auth_mode=auth_mode,
            ),
            _probe_class_cap(db, asset_ref=asset, canonical=canonical, state=state),
            _posture_cap(
                db, scope=scope, asset_ref=asset, canonical=canonical,
                ma_pre_close_ids=ma_pre_close_ids, noise_class=observer_row.noise_class,
            ),
        )
        if not caps[2].allowed:
            posture_denied.add((asset.asset_type, asset.value))
        if canonical is not None and "ip" not in caps[1].modes:
            port_scan_unauthorised_ids.add(canonical.id)
        permission = _compose(
            caps,
            connector_id=connector_id,
            observer_slug=observer_row.name,
            observer_addressing=observer_row.addressing,
            observer_noise_class=observer_row.noise_class,
            canonical=canonical,
            asset_ref=asset,
            state=state,
            mode=mode,
            scan_run_id=scan_run_id,
        )

        permissions[(asset.asset_type, asset.value)] = permission
        rows.append(_decision_row(canonical, observer_row, permission))
        if permission.allowed:
            permitted.append(asset)

    _write_decisions(db, rows)

    if enforce:
        return GateResult(
            permitted=permitted, permissions=permissions, enforced=True,
            port_scan_unauthorised_ids=frozenset(port_scan_unauthorised_ids),
        )

    # log_only, but posture denials are NOT subject to the rollout switch —
    # same standing as the connector-declaration check above, for the
    # reason in `_posture_cap`'s docstring. Everything else still passes
    # through unfiltered, so this does not become an early #148 enforce
    # flip by the back door: only the posture axis bites here.
    if posture_denied:
        return GateResult(
            permitted=[a for a in assets if (a.asset_type, a.value) not in posture_denied],
            permissions=permissions,
            enforced=True,
            port_scan_unauthorised_ids=frozenset(port_scan_unauthorised_ids),
        )
    return GateResult(
        permitted=list(assets), permissions=permissions, enforced=False,
        port_scan_unauthorised_ids=frozenset(port_scan_unauthorised_ids),
    )


# ── the ownership/affinity-probe gate (planning#205) ────────────────────────

# The observer identity `authorise_ownership_probe` keys on. A module
# constant here (not an import of `app.services.domain_affinity`) because
# `domain_affinity` imports THIS module (§ that function's docstring below);
# importing it back would be the exact module-load cycle `_canonical_key_for`
# already avoids by importing `asset_writer` lazily. `domain_affinity.py`
# mirrors this literal as its own `OBSERVER` constant — the two are the same
# string on purpose, not two names for one thing that happen to agree today.
_OWNERSHIP_PROBE_OBSERVER = "domain_affinity"


def authorise_ownership_probe(
    db: Session,
    *,
    asset_canonical_ids: list[uuid.UUID],
    subject: str,
    scan_run_id: uuid.UUID | None = None,
) -> bool:
    """Authorise ONE ownership/affinity probe — `domain_affinity._probe_worker`
    and `domain_affinity.probe_corroboration_candidates`, the module's only
    two network-egress functions — against every asset in
    `asset_canonical_ids`. Returns a bare `bool`: unlike `authorise_probes`,
    there is no addressing mode or authorised-name set to describe here, the
    probe either goes out or it doesn't (see "Why not `authorise_discovery`"
    below for the same point put the other way).

    ## Why this exists

    `domain_affinity` sends real HTTP/TLS to target hosts and, before
    planning#205, never consulted the gate at all — the two-line hole
    `scan_executor._precompute_probe_evidence`'s own docstring already
    flagged and deferred ("It does not gate the affinity probe ... a real
    hole in planning#148's 'one choke point' claim"). Gating only
    `check_affinity` would have been PARTIALLY inert: a denied
    `check_affinity` returns `indeterminate`, which
    `shared_infra_verifier.classify_ip_ownership` turns into `unverified`,
    which is exactly the branch Phase D's `corroborate_liveness` fires from
    — so a denial at the first probe would simply route traffic into the
    second, ungated one. Both `_probe_worker` and
    `probe_corroboration_candidates` call this function, at their own top,
    before their own `httpx.post` — see each function's body, not their
    call sites, which is what makes "nothing in this module can reach the
    network without passing the gate" true rather than aspirational.

    ## Why not `authorise_probes`

    That function composes `_scope_cap`, which needs a `scope` dict. One of
    the three call sites this feeds — `app/api/findings.py`'s manual
    Re-verify button, reached via `shared_infra_verifier.verify_findings(...,
    force=True)` — has no scan run and no scope at all. Composing scope
    there would deny an explicit human action for a reason that has nothing
    to do with posture or reachability class, the two axes this issue is
    actually about.

    ## Why not `authorise_discovery`

    That function is domain-shaped: it takes one `target_row` and one
    `domain` string, because a domain being enumerated has no canonical
    identity yet. The call sites here are the opposite shape — they already
    HAVE `AssetCanonical` rows (one hostname's, one IP's, or just the IP's;
    see each call site) and no single target: the probe is one owned
    hostname against a shared IP, which is N-to-1 with hostnames and, across
    a target's whole estate, N-to-N with targets by construction. Composing
    over a list of canonical ids (this function) rather than one domain
    string is the natural fit for that shape, not a third, ad hoc interface.

    ## Composes exactly two caps — posture, and only the `no_probe` half of
    probe_class

    Deliberately NOT `_scope_cap` (see above) and deliberately NOT the FULL
    `_probe_class_cap` (`name_only`/`direct_addressable` say nothing here —
    this probe is `name`-addressed by construction, always at the owned
    hostname's own name, so there is no addressing-mode question for those
    two states to answer; only the "never probe this at all" state matters).

      - **posture** — resolved via `_resolve_ma_pre_close_ids(db,
        set(asset_canonical_ids))` (same helper `_posture_cap` uses) and
        decided with `posture.observer_permitted(passive_only=...,
        noise_class=...)`. `rule_fired` is `"posture:ma_pre_close"` — the
        SAME string `_posture_cap` and `authorise_discovery` both use,
        deliberately (planning#196: one rule, one spelling, so a query for
        "everything posture blocked" never has to know a third spelling).
        **Always-enforced, in BOTH gate modes** — same standing as
        `_posture_cap`'s own posture denial: a pre-close M&A flag is an
        operator assertion, not a verdict this system inferred, so the
        graduated `log_only`/`enforce` rollout that governs probe_class
        below does not apply to it.
      - **`no_probe`** — read from `state.attributes["probe_class"]`
        (`projector.load_states`, the same source `_probe_class_cap` reads)
        for each id in `asset_canonical_ids`. Denies ONLY on an EXPLICIT
        `probe_class == "no_probe"`; `rule_fired` is `"probe_class:no_probe"`
        — the SAME string `_probe_class_cap` uses. **Mode-gated**: enforced
        only when `probe_authorisation_mode == "enforce"`, matching
        `_probe_class_cap`'s own standing under the planning#148 log_only
        rollout. Under `log_only` the denial is still COMPUTED and a
        decision row is still WRITTEN (the log_only rollout exists to be
        read, not to be a no-op — see the module docstring's "Gate mode"),
        but the probe proceeds.

    ## Deliberate differences from `_probe_class_cap` — recorded
    limitations, not oversights

      - A missing `asset_state`, an unprojected asset, or a `probe_class`
        string this module doesn't recognise all **permit** here, where
        `_probe_class_cap` denies them outright (`probe_class:unprojected`).
        Denying unprojected assets here would block every first-run
        affinity probe under `enforce` — an availability regression this
        issue is not the place to relitigate, the same reasoning
        `_probe_class_cap`'s own docstring gives for why THAT denial is
        safe to ship specifically because the gate defaults to `log_only`.
        `authorise_ownership_probe` has no such safety net for this one
        axis: composing the full unprojected-denial here would make EVERY
        call site's very first probe of a newly-discovered asset deny
        outright the moment `enforce` is flipped, regardless of the rest of
        `_probe_class_cap`'s reasoning, since this function does not also
        compose scope — so the narrower "explicit no_probe only" rule is
        the one that ships.
      - An asset with no resolvable canonical row is **permitted** — it
        simply is not a member of `ma_pre_close_ids` and has no
        `asset_state` row for `no_probe` to fire against. This is not a
        regression: today, with no gate on this module at all, such an
        asset is unconditionally probed. It is also not an improvement —
        the hole is simply left exactly where it already was, same as the
        residual gap `_posture_cap`'s own docstring records for a
        `skip_discovery` recheck against a never-linked asset.

    ## Fail-closed across the list: deny if ANY id is denied

    `asset_canonical_ids` is N-to-N by construction (one hostname, one IP;
    or just an IP) — mirrors `_resolve_ma_pre_close_ids`'s own documented
    "any linked target wins": the presence of one clean id does not dilute
    or overrule another id's denial. When posture denies at least one id in
    the list, `rule_fired` is `"posture:ma_pre_close"` regardless of whether
    `no_probe` also denied a (possibly different) id in the same call — the
    same precedence `_compose` already gives posture over the other caps,
    for the same reason: posture is the one axis guaranteed to actually be
    the operative denial reason in every gate mode.

    ## Logging: denials write a decision row; permits do not

    Same argument as `authorise_discovery`: a permit here records only "the
    two caps had nothing to say", which is the default state of nearly
    every probe and would dominate the very table the planning#148 enforce
    flip is counted from. `evidence_snapshot["decision_scope"]` is
    `"ownership_probe"` — a THIRD value alongside `authorise_probes`'
    `"asset"` and `authorise_discovery`'s `"domain"` (no CHECK constraint on
    this column; it lives in the jsonb, so adding a value here is a body
    change, not a migration). The row is attached to whichever canonical id
    in the list actually caused the denial — the first one found, posture
    taking priority over `no_probe` per the precedence above.

    Observer identity is always `_OWNERSHIP_PROBE_OBSERVER` ("domain_affinity")
    — resolved from the seeded `observers` row by that name — **deliberately
    NOT the calling module's own slug**. The seeded table has:

        domain_affinity        | name | target_host | derived
        shared_infra_verifier   | name | target_host | derived
        dangling_dns_analyzer   | name | silent      | derived

    `dangling_dns_analyzer` is seeded `silent` while calling a `target_host`
    probe (it triggers Layer 1/3 network traffic through `domain_affinity`,
    but attributable network I/O is not itself `dangling_dns_analyzer`'s own
    behaviour). Keying posture's noise-class check on the CALLING module's
    slug would read that `silent` row and PERMIT a passive-only target under
    posture — reopening the exact hole this issue exists to close. Keying
    on the observer that actually emits the traffic, regardless of which
    module's call stack triggered it, is the only version of this that is
    correct for all three call sites (`shared_infra_verifier`,
    `dangling_dns_analyzer`, and `origin_corroboration` alike).

    `_write_decisions` commits (pre-existing, accepted — `authorise_discovery`
    does the same); it only runs on a denial, which is rare, and never on
    the permit path.
    """
    ids = list(asset_canonical_ids)
    if not ids:
        return True

    mode = settings_svc.get(db, "probe_authorisation_mode") or "log_only"
    enforce = mode == "enforce"

    observer_row = db.query(Observer).filter(Observer.name == _OWNERSHIP_PROBE_OBSERVER).first()
    noise_class = observer_row.noise_class if observer_row is not None else None

    id_set = set(ids)
    ma_pre_close_ids = _resolve_ma_pre_close_ids(db, id_set)
    states = projector.load_states(db, id_set)

    posture_permitted = posture.observer_permitted(passive_only=True, noise_class=noise_class)
    posture_denied_ids = [cid for cid in ids if cid in ma_pre_close_ids] if not posture_permitted else []

    no_probe_ids = [
        cid for cid in ids
        if states.get(cid) is not None
        if (states[cid].attributes or {}).get("probe_class") == "no_probe"
    ]

    posture_cap = Cap(
        allowed=not posture_denied_ids,
        modes=frozenset() if posture_denied_ids else None,
        names=None,
        rule="posture:ma_pre_close" if posture_denied_ids else "posture:permissive",
    )
    probe_class_cap = Cap(
        allowed=not no_probe_ids,
        modes=frozenset() if no_probe_ids else None,
        names=None,
        rule="probe_class:no_probe" if no_probe_ids else "probe_class:permitted",
    )

    if not posture_cap.allowed:
        denial_id = posture_denied_ids[0]
        rule_fired = posture_cap.rule
    elif not probe_class_cap.allowed:
        denial_id = no_probe_ids[0]
        rule_fired = probe_class_cap.rule
    else:
        return True  # nothing denied — no log, see docstring

    enforced_denied = (not posture_cap.allowed) or (enforce and not probe_class_cap.allowed)

    denial_state = states.get(denial_id)
    probe_class_value = (denial_state.attributes or {}).get("probe_class") if denial_state is not None else None

    # planning#209 — this scope wrote NO identity keys at all, which made
    # `AuthorisationDecision`'s own docstring false for it: that docstring
    # tells a reader an orphaned row is still readable because
    # `evidence_snapshot` carries `asset_type`/`asset_value`, and named
    # `_compose` as the writer — but this gate does not go through
    # `_compose`. `asset_canonical_id` is ON DELETE SET NULL, so deleting
    # the asset would have left an ownership-probe denial with no identity
    # anywhere on it.
    #
    # One query, on the denial path only: this function returns early
    # ("nothing denied — no log") for every permit, so permits pay nothing.
    denial_asset = db.get(AssetCanonical, denial_id)

    evidence = {
        "decision_scope": "ownership_probe",
        "asset_type": denial_asset.asset_type if denial_asset is not None else None,
        "asset_value": denial_asset.value if denial_asset is not None else None,
        "subject": subject,
        "observer": _OWNERSHIP_PROBE_OBSERVER,
        "observer_noise_class": noise_class,
        "observer_addressing": observer_row.addressing if observer_row is not None else None,
        "gate_mode": mode,
        "scan_run_id": str(scan_run_id) if scan_run_id is not None else None,
        "probe_class": probe_class_value,
        "tenancy": None,
        "caps": {
            "posture": _cap_evidence(posture_cap),
            "probe_class": _cap_evidence(probe_class_cap),
        },
    }
    row = {
        "asset_canonical_id": denial_id,
        "observer_id": observer_row.id if observer_row is not None else None,
        "allowed": False,
        "probe_modes": [],
        "authorised_names": [],
        "rule_fired": rule_fired,
        "evidence_snapshot": evidence,
    }
    _write_decisions(db, [row])

    return not enforced_denied


# ── the domain-level gate (planning#196) ────────────────────────────────────

def authorise_discovery(
    db: Session,
    *,
    observer_slug: str | None,
    target_row,
    domain: str,
    scan_run_id: uuid.UUID | None = None,
) -> bool:
    """Authorise one discovery TOOL against one DOMAIN, before any asset
    exists to route through `authorise_probes`.

    ## Why this is not `authorise_probes`

    `authorise_probes` is asset-shaped: it resolves each asset to its
    `assets_canonical` row and composes caps over that row. A domain being
    enumerated has no such identity yet. `assets_canonical` identity for a
    `dns_record` is `(asset_type, value, record_type, content)` — one row
    per RECORD, not per domain — and `write_assets(...,
    target_ids=target_ids)` (`scan_executor.py`'s Phase 1 domain loop) runs
    AFTER the discovery tools in that same loop, so on a target's
    first-ever scan there is nothing to resolve to a canonical row at all.
    Routing this check through `authorise_probes` would therefore deny ALL
    first-run discovery — the same availability regression that already
    forced `probe_authorisation_mode` to default to `log_only` (see the
    module docstring's "Gate mode" section). This function exists instead
    of widening that one.

    ## Posture only — scope and probe_class are deliberately NOT composed

    This function composes exactly one cap: posture. `_scope_cap` denies
    an unresolved asset by design (`scope:unresolved_asset`), and for a
    domain pre-discovery "unresolved" is the ordinary state, not an
    exception — composing it here would deny every domain on every first
    run for a reason that has nothing to do with posture. `probe_class` is
    meaningless for a domain that has no projected `asset_state` at all.
    The containment duplication this left on the table
    (`target_service.is_scan_authorised` vs.
    `probe_authorisation._resolve_scoped_ids`) was handled separately, as
    planning#197, rather than being silently absorbed into this function.
    That issue did NOT merge the two into one call — the reasoning above
    still holds, and `_scope_cap` still must not gate first-run discovery.
    It unified the half that was genuinely shared (the `auth_mode`
    semantics and the verified-before-containment ordering, now
    `target_scope.authorised_target_pool`) and left the keyspaces apart.

    ## Always-enforced — no `probe_authorisation_mode` check

    Same standing as `_posture_cap`'s own posture denial (see that
    function's docstring): a pre-close M&A flag is an operator assertion,
    not a verdict this system inferred, so the graduated `log_only` /
    `enforce` rollout that governs scope/probe_class does not apply to it.
    `gate_mode` is still RECORDED in the evidence below, purely for
    comparability with the asset path's rows — it is not consulted to
    decide anything here.

    ## `rule_fired` is `"posture:ma_pre_close"` — the SAME string the asset
    path uses, deliberately

    `rule_fired` names the rule that fired, and it IS the same rule,
    decided by the same function (`posture.observer_permitted`) in
    `app.services.posture`. Giving the domain path its own string would
    mean any future query for "everything posture blocked" has to know
    both spellings — exactly the drift planning#196 exists to remove. The
    asset/domain distinction is carried explicitly by
    `evidence_snapshot->>'decision_scope'` (`"asset"` vs. `"domain"`), and
    structurally by `asset_canonical_id IS NULL` alongside that rule — not
    by inventing a second rule string.

    ## Denials are logged; permits are not

    This function composes exactly one cap, so a permit row here would
    record only "posture had nothing to say" — the default state for
    every domain in every scan, which would dominate the very table the
    planning#148 enforce flip is counted from. The asset path's permit
    rows earn their place in the log because they carry `probe_modes`,
    `authorised_names`, `probe_class` and `tenancy`; a domain-level permit
    carries none of that — there is nothing informative to record. The
    question this log has to answer is "was this target's enumeration
    blocked?", and that is a denial, not a permit.

    ## Fail-closed on an unknown or undeclared observer

    Under passive-only, a tool whose `OBSERVER` slug is missing (the
    caller passes `observer_slug=None`) or not a seeded `observers.name`
    resolves `noise_class` to `None`, and `posture.observer_permitted`
    denies on the fail-closed membership test (see that function's
    docstring) — a tool that cannot prove what noise it makes does not get
    to make it against a target we are not authorised to touch.

    Returns a bare `bool` — unlike `authorise_probes`'s `ProbePermission`,
    there is no addressing mode or authorised-name set to describe for a
    domain-level enumeration decision; "was this tool allowed to run" is
    the whole question.
    """
    passive_only = posture.is_passive_only(target_row)
    if not passive_only:
        # The overwhelmingly common path — an ordinary target — must cost
        # zero database work. Short-circuit BEFORE resolving the observer.
        return True

    observer_row = db.query(Observer).filter(Observer.name == observer_slug).first() if observer_slug else None
    noise_class = observer_row.noise_class if observer_row is not None else None
    allowed = posture.observer_permitted(passive_only=True, noise_class=noise_class)
    if allowed:
        return True

    if observer_row is None:
        # An undeclared or unseeded discovery observer is a code/seed
        # defect, not a policy outcome — mirror the tone of the
        # connector-declaration WARNING in `authorise_probes` above. It is
        # still denied fail-closed under passive-only, same as any other
        # unrecognised noise class.
        log.warning(
            "Discovery gate: %s denied outright for domain %s under "
            "passive-only posture — observer slug %r did not resolve to a "
            "seeded observers row (noise_class treated as unknown); see "
            "planning#196.",
            observer_slug, domain, observer_slug,
        )
    else:
        log.info(
            "Discovery gate: %s (noise_class=%s) denied for domain %s — "
            "target is pre-close M&A (passive-only); see planning#196.",
            observer_slug, noise_class, domain,
        )

    mode = settings_svc.get(db, "probe_authorisation_mode") or "log_only"
    permission = ProbePermission(
        allowed=False,
        modes=frozenset(),
        names=(),
        rule_fired="posture:ma_pre_close",
        evidence={
            "connector_id": observer_slug,
            "observer": observer_slug,
            "observer_addressing": observer_row.addressing if observer_row is not None else None,
            "observer_noise_class": noise_class,
            "probe_class": None,
            "tenancy": None,
            "gate_mode": mode,
            "scan_run_id": str(scan_run_id) if scan_run_id is not None else None,
            "decision_scope": "domain",
            "domain": domain,
            "caps": {"posture": _cap_evidence(Cap(False, frozenset(), None, "posture:ma_pre_close"))},
        },
    )
    _write_decisions(db, [_decision_row(None, observer_row, permission)])
    return False
