"""Composed probe-authorisation gate (planning#148, slice 1 — the chassis).

This is the single choke point every Phase 1.5 active-probe connector
(naabu, banner_grab, httpx_probe, tlsx today; anything added later) MUST
pass through before it is handed any asset to send traffic at. A second
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
modes (`ip`/`name`) plus the concrete set of names authorised for
name-addressed probing. It returns a descriptor, **never a boolean** —
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
see the four Phase 1.5 connector files) and that row must address
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
either inside a declared CIDR target *or* (`hosting.is_datacenter` AND
`estate == confirmed_ours`) — and `shared_infra_verifier` (which is what
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
from app.services import app_settings as settings_svc
from app.services import projector
from app.services import target_scope

log = logging.getLogger(__name__)

# Addressing modes a probe can actually be issued in. Deliberately NOT the
# full `app.models.observer.OBSERVER_ADDRESSING` vocabulary — "none" means
# "this observer never sends traffic to the target itself" (passive
# discovery/enrichment/verify observers), which is not a probe mode at all,
# it's the absence of one. An observer declaring "none" is refused by the
# connector-declaration check below before this set is ever consulted.
ADDRESSING_MODES: frozenset[str] = frozenset({"ip", "name"})


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
    enforcement — `True` under the `enforce` setting, and also `True` for
    a connector-declaration failure (§ module docstring: that check narrows
    to nothing in both modes, so its `permitted` is never a passthrough).
    It is `False` only for the ordinary `log_only` path, where `permitted`
    is the unfiltered input and the real verdict lives solely in the
    decision log. Callers that just want to know whether to keep going
    check `permitted` — `enforced` is for logging/tests that care WHY
    `permitted` looks the way it does.
    """

    permitted: list  # subset of the input assets
    permissions: dict[tuple[str, str], ProbePermission]  # (asset_type, value) -> descriptor
    enforced: bool  # False in log-only mode


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

    ## Still outstanding (planning#128, second slice)

    The interim Phase 3 enforcement — `_extract_scan_targets` +
    `is_scan_authorised`/`apex_domain` in `scan_executor.py` — is STILL IN
    PLACE and still doing its job. It is NOT retired by this slice, and it
    must not be retired until Phase 3 actually routes through this gate:
    removing it first would leave Phase 3 scanning ungated entirely.

    Folding it in is not a small edit, which is why it is separated.
    `nuclei` has no `observers` row and `NucleiConnector` has no `observer`
    attribute, so the always-enforced connector-declaration check would
    refuse it outright and kill Phase 3 scanning; and Phase 3 operates on
    flat target STRINGS while this gate takes assets and returns per-asset
    descriptors, so the phase has to be reshaped, not merely rerouted.

    Phase 1.5 port discovery, by contrast, is gated on scope for the first
    time as of this slice — that was the larger hole.
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

    Under `strict`, the scope entries are filtered down to verified targets
    BEFORE containment runs. Doing it in this order is what makes a
    verified CIDR license the addresses inside it; filtering afterwards
    would be the string-equality bug wearing a different hat.
    """
    if auth_mode == "disabled":
        return frozenset()

    domains = list(scope.get("domains") or [])
    ip_ranges = list(scope.get("ip_ranges") or [])

    if auth_mode not in ("acknowledge", "disabled"):
        # "strict" (and any unrecognised mode, which target_service treats
        # as strict — fail closed, and stay consistent with it).
        declared = domains + ip_ranges
        if not declared:
            return frozenset()
        verified = {
            r[0] for r in db.query(Target.value)
            .filter(Target.value.in_(declared), Target.verified == True)  # noqa: E712
            .all()
        }
        domains = [d for d in domains if d in verified]
        ip_ranges = [r for r in ip_ranges if r in verified]

    return frozenset(target_scope.target_scoped_asset_ids(db, {
        "domains": domains,
        "ip_ranges": ip_ranges,
    }))


def _probe_class_cap(db: Session, *, asset_ref, canonical: AssetCanonical | None, state) -> Cap:
    """Probe-class cap — the only cap with a real body in this slice.

    Reads `state.attributes["probe_class"]` (`app.services.projector`,
    planning#129 + #143) and maps it straight onto a permitted addressing
    set:

      - `"no_probe"` — third-party-boundary or provider-managed-MX asset;
        never probe it at all (empty modes).
      - `"name_only"` — not inside a declared CIDR and not a confirmed
        datacenter IP; only name-addressed probing (SNI/Host-header) is
        licensed, never a bare-IP connect.
      - `"direct_addressable"` — inside a declared CIDR, or a datacenter IP
        with a confirmed-ours affinity verdict; both modes licensed.
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
        return Cap(True, frozenset({"name"}), None, "probe_class:name_only")
    if probe_class == "direct_addressable":
        return Cap(True, frozenset({"ip", "name"}), None, "probe_class:direct_addressable")
    return Cap(False, frozenset(), None, "probe_class:unprojected")


def _posture_cap(db: Session, *, scope: dict, asset_ref, canonical: AssetCanonical | None) -> Cap:
    """Posture cap — engagement posture (pre-close diligence vs. post-close
    monitoring, etc.), planning#132. Slice 1: **permissive**.

    Present-and-permissive is a deliberate choice, not an oversight:
    omitting this axis now and retrofitting it once #132 lands would mean
    every call site (and every test) that assumes a fixed 2-cap
    composition has to be revisited when the 3rd cap shows up. Shipping it
    now as an inert identity cap means #132 is purely a body change here,
    exactly like #128's relationship to `_scope_cap` above.

    `db`/`scope`/`asset_ref`/`canonical` are accepted now, unused, for the
    same forward-signature-stability reason as `_scope_cap`.

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
    """
    _ = (db, scope, asset_ref, canonical)  # unused this slice — see docstring; kept for #132's signature stability
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
    canonical: AssetCanonical | None,
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
      - if the composed caps deny (`not all(c.allowed ...)`), it's the
        `.rule` of the FIRST cap, in scope → probe_class → posture order,
        that returned `allowed=False`.
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
        (`{"ip", "name"}`) equal the full `ADDRESSING_MODES` set, so a
        fully-open `direct_addressable` asset reports `"unconstrained"`
        too — that's intentional: "unconstrained" describes the OUTCOME
        (nothing is restricting this decision), not "no cap fired".

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
        "gate_mode": mode,
        "scan_run_id": str(scan_run_id) if scan_run_id is not None else None,
        "caps": {
            "scope": _cap_evidence(scope_cap),
            "probe_class": _cap_evidence(probe_cap),
            "posture": _cap_evidence(posture_cap),
        },
    }

    if not composed_allowed:
        denial_rule = next(c.rule for c in caps if not c.allowed)
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

    # observer_row is resolved and addresses something (ip/name) beyond
    # this point — safe to read observer_row.name/.addressing directly.
    canonical_ids = {c.id for c in canonical_by_key.values()}
    states = projector.load_states(db, canonical_ids)
    # Batch-resolved once, like `states` above and for the same reason: the
    # scope cap's containment check is set membership, but BUILDING the set
    # costs a full ip_address scan when a real CIDR is in scope (there is no
    # CIDR-containment operator over a text column). Per-asset resolution
    # would repeat that scan for every asset in the batch.
    auth_mode = settings_svc.get(db, "scan_authorisation_mode") or "strict"
    scoped_ids = _resolve_scoped_ids(db, scope, auth_mode)

    permitted: list = []
    permissions = {}
    rows = []

    for asset in assets:
        canonical = canonical_by_key.get(_canonical_key_for(asset))
        state = states.get(canonical.id) if canonical is not None else None

        caps = (
            _scope_cap(
                db, scope=scope, asset_ref=asset, canonical=canonical,
                scoped_ids=scoped_ids, auth_mode=auth_mode,
            ),
            _probe_class_cap(db, asset_ref=asset, canonical=canonical, state=state),
            _posture_cap(db, scope=scope, asset_ref=asset, canonical=canonical),
        )
        permission = _compose(
            caps,
            connector_id=connector_id,
            observer_slug=observer_row.name,
            observer_addressing=observer_row.addressing,
            canonical=canonical,
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
        return GateResult(permitted=permitted, permissions=permissions, enforced=True)
    return GateResult(permitted=list(assets), permissions=permissions, enforced=False)
