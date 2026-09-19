"""Synchronous, incremental claims -> asset_state projector (planning#143, L2
sub-slice C).

Reads `asset_claims` + `assets_canonical`'s own columns and folds them into
one projected row per asset in `asset_state`. As of planning#144 L3c-3 this
module no longer reads `assets_canonical.metadata` at all — every source is
either a claim or a real column:

  - `open_ports` <- `port_observation` claims, folded across observers.
  - `hosting` <- a `hosting_class` claim; `estate` <- an
    `affinity_confirmation` claim's `verdict` (L3a — hosting_classifier and
    shared_infra_verifier's asset_metadata TTL-caches moved to claims).
  - `eol_summary` <- the eol_enrichment observer's `eol_status` claim
    (L3c-3 — converted this slice; it was the last path-2 read here).
  - `attributes["cdn"]`/`["cdn_domain"]` <- a `cdn_boundary` claim (L3c-3 —
    replaces L3b-2's stopgap passthrough of the same keys out of the
    metadata column, which had no source surviving the L3c-4 drop).
  - `attributes["provider_mx"]` (and the `no_probe` half of `probe_class`
    that depends on it) is RECOMPUTED here from the
    `assets_canonical.record_type`/`.content` columns (L3b-1 promoted those
    to columns; L3b-2 stopped reading the transitional metadata mirror).
  - `attributes["naabu_last_scan_at"]` <- the naabu `port_observation`
    claim's `last_observed_at`, isoformatted — the same value used as the
    prune cutoff. Only taken from a claim whose evidence does not say
    `complete: False` (planning#169) — an incomplete sweep may not advance
    this cutoff.
  - `attributes["tenancy"]` <- every rung's `tenancy` claim (any observer in
    `_TENANCY_OBSERVERS`) plus the Tier 2 opinion derived from the
    `reverse_ip` claim, folded by `_compose_tenancy` (planning#182 rung 3).
    This replaces `hosting.is_datacenter` in the `direct_addressable` rung;
    `hosting` itself is untouched and still serves the finding-attribution
    path (epic#81 Phase D / planning#107), where "is this shared infra whose
    CVE is not ours" genuinely is the question being asked.
  - `estate = "proven_ours"` <- a `cloud_inventory` claim with
    `claim_value.get("confirmed") is True` (planning#145 L4 — the epic's
    missing promotion path; see the precedence comment at the estate
    derivation below).

`asset_writer`'s merge loop still authors `asset_metadata` for the readers
L3c-3 has not reached, and L3c-4 removes that write along with the column.
Nothing in THIS module depends on it either way.

`_merge_open_ports` / `_prune_stale_ports` (plus their grace-period
constants) used to live in `asset_writer.py`; they moved here verbatim as
part of this slice so the projector and the writer's own asset_metadata
merge share one definition. `asset_writer.py` imports them back and keeps
calling them exactly as before — that's a pure move, not a rewrite.
"""

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.connectors.base import is_provider_managed_mx
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.claim import AssetClaim
from app.models.observer import Observer
from app.models.target import Target, TargetType
from app.services import target_scope

# ── moved verbatim from asset_writer.py ────────────────────────────────────

# A Shodan-sourced port (never seen by our active scan) is kept as time-boxed
# intel for this many days past its last_seen_at before the prune drops it.
# Mirrors the read-time grace in app.api.assets._filter_stale_ports.
_SHODAN_PORT_GRACE_DAYS = 14

# A port confirmed by an active prober (l7_confirmed=True) is kept this many days
# past its last confirmation even if later scans miss it. Real services flap —
# intermittent / firewall throttling — so a single missed scan must not retire a
# known-real port (validated 2026-06-23, planning#69: port 80 flapped
# open<->filtered within seconds from two WANs). Shorter than the Shodan grace: a
# confirmed port we can't re-confirm for days is probably genuinely closed.
_CONFIRMED_PORT_GRACE_DAYS = 3


def _prune_stale_ports(open_ports: list, naabu_last_scan_at: str, now: datetime) -> list:
    """Drop ports not re-confirmed in the latest naabu scan, so stored
    `open_ports` == the current truth (instead of accumulating forever).

    A port is kept if it was re-observed at/after the latest naabu scan, OR it
    was previously app-confirmed (l7_confirmed) within the confirmed grace window
    (flap-guard for intermittent real ports), OR it's Shodan-sourced intel inside
    the Shodan grace window, OR it has no timestamp to judge by. Everything else
    (e.g. a firewall phantom that a later nmap-authoritative scan no longer
    confirms) is removed at the source. This is the write-time counterpart of the
    read-time `_filter_stale_ports` hide — here we delete, which also stops any
    consumer from re-probing stale phantoms.
    """
    try:
        cutoff = datetime.fromisoformat(naabu_last_scan_at)
        if cutoff.tzinfo is None:
            cutoff = cutoff.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError, AttributeError):
        return open_ports  # can't parse the marker — don't risk dropping anything
    grace_cutoff = now - timedelta(days=_SHODAN_PORT_GRACE_DAYS)
    confirmed_grace_cutoff = now - timedelta(days=_CONFIRMED_PORT_GRACE_DAYS)
    kept: list = []
    for entry in open_ports:
        if not isinstance(entry, dict):
            continue
        raw = entry.get("last_seen_at")
        if not raw:
            kept.append(entry)  # no timestamp — keep, can't judge staleness
            continue
        try:
            ts = datetime.fromisoformat(raw)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except (ValueError, AttributeError):
            kept.append(entry)
            continue
        if ts >= cutoff:
            kept.append(entry)
        elif entry.get("l7_confirmed") is True and ts >= confirmed_grace_cutoff:
            # Flap-guard: a previously-confirmed real port is kept through brief
            # misses (it flaps) until the confirmed grace expires.
            kept.append(entry)
        elif "shodan" in (entry.get("sources") or []) and ts >= grace_cutoff:
            kept.append(entry)
        # else: stale / grace-expired — drop
    return kept


def _merge_open_ports(existing: list, new: list) -> list:
    """Merge two `open_ports` lists keyed by port number.

    Each entry is `{port, protocol, sources, last_seen_at, …}` plus any
    fields contributed by service enrichers (`service`, `service_version`,
    `tech_stack[]`, `tls_cert_sans[]`, etc.). Merge rules per port:

    * `sources` — union, preserving first-seen order.
    * Other primitive fields — last-write-wins for non-empty values.
    * `last_seen_at` — the newer one wins (lexicographic ISO 8601 ordering).

    A previously-known port that wasn't re-observed in this batch is kept
    untouched; cleanup of stale ports is a separate lifecycle concern.
    """
    by_port: dict[int, dict] = {}
    for entry in existing:
        if isinstance(entry, dict) and isinstance(entry.get("port"), int):
            by_port[entry["port"]] = dict(entry)

    for entry in new:
        if not isinstance(entry, dict):
            continue
        port = entry.get("port")
        if not isinstance(port, int):
            continue
        current = by_port.get(port)
        if current is None:
            by_port[port] = dict(entry)
            continue
        for k, v in entry.items():
            if k == "port":
                continue
            if v in (None, "", [], {}):
                continue
            if k == "sources":
                existing_sources = current.get("sources", [])
                src_list = v if isinstance(v, list) else [v]
                current["sources"] = list(dict.fromkeys(existing_sources + src_list))
            elif k == "last_seen_at":
                if not current.get("last_seen_at") or v > current["last_seen_at"]:
                    current["last_seen_at"] = v
            else:
                current[k] = v

    return sorted(by_port.values(), key=lambda p: p["port"])


def _carry_forward_unclaimed_ports(merged: list, prior: list) -> list:
    """Re-add ports from the previous projection that NO current claim
    mentions, leaving every port the claims DO mention exactly as folded.

    planning#172 — `_prune_stale_ports` can only keep a port it can SEE, and
    the fold builds purely from current claim values, so a port every observer
    dropped is gone before the prune's `l7_confirmed` / shodan grace branches
    ever run. That made the flap-guard dead for naabu's own ports: disabling
    the prune entirely changed nothing. Carrying the port forward restores the
    accumulated input the prune had before planning#144 L3c-4 moved it, with
    no change to what a claim MEANS — the carried entry is still the last
    thing an observer actually said about that port, and whether it survives
    is still the prune's decision alone.

    Scoped to whole missing ports on purpose. Seeding the whole fold from the
    previous projection instead (the first cut of this fix) also dragged stale
    PER-FIELD values onto ports the claims still describe, which silently
    broke clear-by-omission: `cpe_normalizer` retracts `software` by dropping
    the port from its claim, and `_merge_open_ports` only overwrites a key the
    new entry carries — it never deletes one the new entry omits — so a stale
    `software` became unclearable
    (test_cpe_normalizer.py::test_enrich_cpe_software_removal_propagates_to_projected_state).
    A port the claims still describe must be rebuilt from those claims alone.
    """
    claimed = {e["port"] for e in merged if isinstance(e, dict) and isinstance(e.get("port"), int)}
    carried = [
        dict(e) for e in prior
        if isinstance(e, dict)
        and isinstance(e.get("port"), int)
        and e["port"] not in claimed
    ]
    if not carried:
        return merged
    return _merge_open_ports(merged, carried)


# ── tenancy composition (planning#182, rung 3) ─────────────────────────────
#
# Tenancy is COMPOSED HERE, not produced as a verdict by any one source.
# That is planning#182's 2026-09-17 design decision, and it supersedes the
# issue body's original "replace the is_datacenter half with a tenancy
# verdict": every rung of the tenancy ladder emits its own opinion under its
# own observer, they are all read together, and no rung gets to be "the
# tenancy answer" on its own.
#
# The reason is coverage, measured rather than assumed (planning#181's
# hand-off, against the live 125k-row cloud_ranges dataset): Azure, GCP and
# OCI publish ZERO `compute` records between them — Azure has no VM tag at
# all, GCP carries one token across every prefix, OCI's tag spans customer
# and Oracle-run space alike. A single verdict derived from the range feeds
# alone would therefore pin every Azure/GCP/OCI estate at `undetermined`
# forever, which is the same silent, non-self-healing denial planning#177
# documented, just narrowed to three providers.
#
# ── the composition rule, and why it is asymmetric ─────────────────────────
#
# Copied from `shared_infra_verifier.classify_ip_ownership`, which composes a
# multi-signal verdict over hostnames the same way: one direction wins
# outright, the other requires unanimity. The principle being copied is "the
# outright win goes to the verdict whose error is cheap; unanimity guards the
# verdict whose error is expensive" — NOT the literal labels, because the
# expensive direction is the other one here. There, a false rejection loses
# us a real finding; here, a false `single_tenant` promotes an address to
# `direct_addressable` and points a port scanner at what may be someone
# else's host.
#
#   1. Any rung reporting `not_single_tenant` wins OUTRIGHT. Tier 0's
#      `edge`/`storage`/`managed` is the provider's own published statement
#      that no customer VM lives in that prefix, and Tier 2's `shared` is a
#      positive observation of live multi-tenancy. Each is self-sufficient,
#      and denial is the safe direction, so one is enough.
#
#   2. `single_tenant` requires UNANIMITY AMONG THE RUNGS THAT VOTED, plus at
#      least one rung whose `single_tenant` is structural rather than
#      inferred from absence (`_PROMOTING_TIERS`). Unanimity is rule 1
#      running first: a single dissent has already denied by the time we get
#      here.
#
#   3. Anything else is `undetermined`, which denies — and is recorded
#      DISTINCTLY from rule 1, because planning#177's whole lesson is that
#      "we could not check" and "we checked and the answer is no" are
#      different facts the decision log has to be able to separate.
#
# ── abstention is not a vote, and that is where this deliberately differs ──
#
# shared_infra_verifier's unanimity counts an `indeterminate` hostname as
# BLOCKING: "Only when indeterminate is entirely ABSENT and every hostname
# voted not_affine do we reject." That is right there and wrong here, and the
# difference is what the abstention means. There, each hostname is a
# different potentially-vulnerable vhost, so a hostname we failed to probe is
# unexamined risk sitting on the same address. Here every rung is talking
# about the SAME address, and `undetermined` means "my data source has
# nothing to say" — which is not partial evidence of multi-tenancy.
#
# Counting abstentions as blocking would also be self-defeating: `reverse_ip`
# reports `unknown` whenever passive DNS returns nothing at all, so a merely
# silent rung would veto every promotion an authoritative rung could make.
# planning#182 states the rule directly — "No claim from a rung is that rung
# abstaining, never that rung voting no."
#
# ── what this does NOT do ──────────────────────────────────────────────────
#
# It does not decide ownership. The composed verdict is ANDed with
# `verdict == "confirmed_ours"` at the probe_class rung below, as two
# independent caps — see planning#178, and `tenancy_enricher._claim_value`'s
# docstring for the producer half of the same constraint. Collapsed into one
# signal, a recycled address that happens to sit in a single-tenant range
# authorises scanning a stranger's host.

_SINGLE_TENANT = "single_tenant"
_NOT_SINGLE_TENANT = "not_single_tenant"
_TENANCY_UNDETERMINED = "undetermined"

# Observers entitled to assert a `tenancy` claim. This is the one place
# `_OWNED_CLAIMS`' claim-type -> single-observer pin becomes claim-type ->
# SET of observers (planning#182's design decision): `asset_claims` is keyed
# (asset, observer, claim_type) by `uq_asset_claims_asset_observer_type`, so
# several rungs can assert `tenancy` about one IP and disagree — which is the
# situation this ladder is in by construction. It must NOT collapse to
# most-recently-observed-wins the way `cdn_boundary`/`cloud_inventory` do:
# the whole point is that every live rung is read together.
#
# Tier 1 is two observers, not one, because the two halves have different
# gate status and `asset_claims`' uniqueness constraint is
# (asset, observer, claim_type) — so one observer could only ever hold one
# of them:
#   - `tenancy_ptr` — reverse-DNS, a resolver query, emits no traffic to the
#     target, `addressing = "none"`, never passes through the gate.
#   - `tenancy_tls` — bare-IP no-SNI TLS handshake, emits traffic,
#     `addressing = "ip_handshake"`, passes through the gate like any
#     connector.
# Tier 2 needs no entry — it is derived from the `reverse_ip` claim
# hosting_classifier already writes, see `_tier2_tenancy_opinion`.
_TENANCY_OBSERVERS = frozenset({"tenancy_enricher", "tenancy_ptr", "tenancy_tls"})

# Which tiers may PROMOTE on their own. Deliberately an allowlist rather than
# "any rung that decided": Tier 0's `compute` is single-tenant by
# construction (one address, one ENI — AWS `EC2` and the pure-VPS providers),
# which is a different quality of evidence from a rung that infers single
# tenancy from not having seen anyone else. A future rung inherits no
# promotion power merely by existing; it has to be added here on purpose,
# with the argument written down.
#
# Tier 1 joined on 2026-09-19 (planning#181), on a separate, explicitly
# weaker argument:
#   - Tier 1 evidence (a provider-assigned reverse name, or the certificate
#     a host presents to a no-SNI connection) is inference from what a host
#     presents, not Tier 0's one-address-one-ENI construction. It is
#     genuinely weaker evidence.
#   - It is admitted anyway because the promotion never fires on tenancy
#     alone: `probe_class` ANDs the composed `single_tenant` verdict with
#     `estate == "confirmed_ours"` (see the disjunct below in this module),
#     so a Tier 1 promotion also requires a positive affinity proof that one
#     of our own hostnames serves from that address.
#   - Rule 1 is the second guard: Tier 2 (`reverse_ip.sharing == "shared"`)
#     is specialised in exactly the failure mode a default certificate would
#     hide — a genuinely multi-tenant host carries many names in passive
#     DNS — and its dissent wins outright over any Tier 1 promotion.
#   - The residual exposure, stated so it is not discovered later: a shared
#     host on which passive DNS is silent, where Tier 2 abstains and Tier 1
#     promotes on a default certificate.
#   - Azure, GCP and OCI publish zero Tier-0-promotable prefixes, so without
#     this Tier 1 would yield `single_tenant_not_corroborated` and deny for
#     the entire population it was built to serve.
_PROMOTING_TIERS = frozenset({0, 1})


def _tier2_tenancy_opinion(reverse_ip_claim_value) -> dict | None:
    """Derive the Tier 2 (passive-DNS) tenancy opinion from the `reverse_ip`
    claim `hosting_classifier` already writes (planning#180).

    No new claim type, no new observer, and — the point — no mnemonic call:
    the quota was already spent when that claim was written. planning#182's
    design decision notes this rung falls out for free once tenancy is
    composed at the gate rather than produced as a verdict.

    `sharing` maps onto a tenancy opinion, NOT one-to-one:

      - `shared` — many domains currently resolving here. A positive
        observation of live multi-tenancy; denies outright under rule 1.
      - `dedicated` — few enough domains to look like one tenant. An argument
        from ABSENCE over a source with incomplete coverage, so it votes
        `single_tenant` but is not in `_PROMOTING_TIERS`: it can corroborate
        a promotion, never carry one alone.
      - `historically_shared` — abstains. planning#180 and #182 both say this
        value must not be extrapolated into a tenancy verdict: it asserts the
        sharing we can see is old, which says nothing about whether the
        address is single-tenant NOW. `_sharing_verdict` also refuses to emit
        it on a truncated page, so its absence is not evidence either.
      - `unknown` / anything unrecognised — abstains.
    """
    if not isinstance(reverse_ip_claim_value, dict):
        return None
    sharing = reverse_ip_claim_value.get("sharing")
    if sharing == "shared":
        tenancy, reason = _NOT_SINGLE_TENANT, "reverse_ip_sharing_shared"
    elif sharing == "dedicated":
        tenancy, reason = _SINGLE_TENANT, "reverse_ip_sharing_dedicated"
    elif sharing in ("historically_shared", "unknown"):
        tenancy, reason = _TENANCY_UNDETERMINED, f"reverse_ip_sharing_{sharing}"
    else:
        return None
    return {
        "observer": "hosting_classifier",
        "claim_type": "reverse_ip",
        "tier": 2,
        "tenancy": tenancy,
        "reason": reason,
        "promoting": 2 in _PROMOTING_TIERS,
    }


def _tenancy_opinion_from_claim(observer_name: str, claim_value) -> dict | None:
    """One rung's opinion, read off a `tenancy` claim (planning#181's claim
    contract). Returns None for a claim whose shape we do not recognise —
    which is an abstention, never a `no` (see the module rule above)."""
    if not isinstance(claim_value, dict):
        return None
    tenancy = claim_value.get("tenancy")
    if tenancy not in (_SINGLE_TENANT, _NOT_SINGLE_TENANT, _TENANCY_UNDETERMINED):
        return None
    tier = claim_value.get("decided_by_tier")
    return {
        "observer": observer_name,
        "claim_type": "tenancy",
        "tier": tier,
        "tenancy": tenancy,
        "reason": claim_value.get("reason"),
        "promoting": tier in _PROMOTING_TIERS,
        # Pinned so a past authorisation decision stays reconstructable
        # against the exact dataset that informed it — SCHEMA.md asks
        # consumers to record this digest alongside the decision it informed,
        # and planning#181 already stamps it on the claim, so it is free.
        "dataset_sha256": claim_value.get("dataset_sha256"),
    }


def _compose_tenancy(opinions: list[dict]) -> dict:
    """Fold every rung's opinion into one composed tenancy verdict.

    Pure — no DB, no I/O — so the rule itself is unit-testable without a
    session. The module rationale above says WHY it is shaped this way; this
    function is only its mechanics.

    The returned dict is what lands in `asset_state.attributes["tenancy"]`
    and, through it, in `authorisation_decisions.evidence_snapshot`. `rule` is
    the field that makes planning#177's three collapsed cases separable in
    the decision log:

        no_rungs_reported              we never looked (unenriched)
        all_rungs_undetermined         we looked; no source could answer
        single_tenant_not_corroborated a non-promoting rung said single-tenant
                                       and nothing authoritative backed it
        dissent_wins_outright          a genuine negative
        unanimous_with_promoting_rung  a genuine positive

    Only the last promotes. The first three are all `undetermined`, and
    keeping them apart is this issue's third acceptance criterion: a denial
    that reads `no_rungs_reported` is a broken or lagging enricher and is
    fixed by operators, while `dissent_wins_outright` is the gate working.
    """
    if not opinions:
        return {"tenancy": _TENANCY_UNDETERMINED, "rule": "no_rungs_reported", "rungs": []}

    rungs = [
        {k: o[k] for k in ("observer", "claim_type", "tier", "tenancy", "reason")}
        for o in opinions
    ]
    dataset_sha256 = next((o["dataset_sha256"] for o in opinions if o.get("dataset_sha256")), None)
    composed: dict = {"tenancy": _TENANCY_UNDETERMINED, "rule": "", "rungs": rungs}
    if dataset_sha256 is not None:
        composed["dataset_sha256"] = dataset_sha256

    # Rule 1 — any dissent wins outright, and runs FIRST so that rule 2's
    # "unanimity among the rungs that voted" is already guaranteed below.
    if any(o["tenancy"] == _NOT_SINGLE_TENANT for o in opinions):
        composed["tenancy"] = _NOT_SINGLE_TENANT
        composed["rule"] = "dissent_wins_outright"
        return composed

    # Rule 2 — unanimous single_tenant, with at least one promoting rung.
    voted_single = [o for o in opinions if o["tenancy"] == _SINGLE_TENANT]
    if voted_single:
        if any(o.get("promoting") for o in voted_single):
            composed["tenancy"] = _SINGLE_TENANT
            composed["rule"] = "unanimous_with_promoting_rung"
        else:
            composed["rule"] = "single_tenant_not_corroborated"
        return composed

    # Rule 3 — rungs reported, none of them could answer.
    composed["rule"] = "all_rungs_undetermined"
    return composed


# ── asset_state read helpers (planning#144 L3c-3) ──────────────────────────
#
# Every backend reader repointed off `assets_canonical.metadata` in L3c-3
# comes through one of these, so the batching lives in one place instead of
# being re-derived (or forgotten) per caller.

def load_states(db: Session, asset_ids) -> dict[uuid.UUID, AssetState]:
    """Batch-load the `asset_state` row for each id in `asset_ids`, in one
    query (planning#144 L3c-3).

    The shared entry point for every backend reader that used to reach for
    `assets_canonical.metadata`: `open_ports`, `eol_summary`, `hosting`,
    `estate` and `attributes` all live here now. Ids with no projected row
    yet are simply absent from the result, so callers treat a miss the same
    way they used to treat an absent metadata key — `.get(id)` then fall
    back to empty.

    Read-only. Note this returns what the LAST `project()` call folded, so
    a caller that needs to see claims written earlier in the same scan
    pipeline must run after the projection pass that covers them — see the
    ordering comments in scan_executor's post-scan block.
    """
    ids = list(asset_ids)
    if not ids:
        return {}
    return {
        row.asset_canonical_id: row
        for row in db.query(AssetState).filter(AssetState.asset_canonical_id.in_(ids)).all()
    }


def open_ports_by_asset(db: Session, asset_ids) -> dict[uuid.UUID, list]:
    """`load_states` narrowed to just `open_ports` — the shape most of the
    repointed readers actually want. Ids with no state row (or an empty
    port list) map to `[]`."""
    return {
        asset_id: (state.open_ports or [])
        for asset_id, state in load_states(db, asset_ids).items()
    }


# ── standalone attributes upsert (planning#144 L3b-3) ──────────────────────

def merge_state_attributes(db: Session, asset_id: uuid.UUID, patch: dict) -> None:
    """Upsert `patch` into one asset's `asset_state.attributes`, JSONB `||`
    merged in — the same merge operator `project()`'s own upsert uses for
    `attributes` (see the on_conflict_do_update below). That's what lets the
    two compose safely: this function and the projector write disjoint keys
    (e.g. `dangling_dns_analyzer` writes `dangling_probe_at`, `project()`
    writes `probe_class`/`provider_mx`/...), so neither ever clobbers the
    other's key, regardless of which runs first or last.

    For callers outside the projector proper that need to persist a single
    attributes key straight to `asset_state` without doing a full claims
    projection (first user: `dangling_dns_analyzer`'s `dangling_probe_at`
    freshness stamp, moved off `asset_metadata` in this slice). On a fresh
    row — no projector run has touched this asset yet — the other NOT-NULL
    columns get their table defaults (`open_ports=[]`, `hosting={}`,
    `eol_summary={}`); `estate`/`projected_at` stay NULL until a real
    projection runs. Does not commit — same convention as `project()`.
    """
    stmt = pg_insert(AssetState.__table__).values(
        asset_canonical_id=asset_id,
        open_ports=[],
        hosting={},
        eol_summary={},
        attributes=patch,
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["asset_canonical_id"],
        set_={
            "attributes": AssetState.__table__.c.attributes.op("||")(stmt.excluded.attributes),
        },
    )
    db.execute(stmt)


# ── projector ────────────────────────────────────────────────────────────

def project(db: Session, asset_ids: set[uuid.UUID], now: datetime) -> None:
    """Fold claims + canonical columns into `asset_state`, one row per id.

    Read-only on `asset_claims` + `assets_canonical`; reads AND writes
    `asset_state` — planning#172 carries ports no current claim mentions
    forward from the previous projection so `_prune_stale_ports`' grace
    windows have an input at all (see `_carry_forward_unclaimed_ports`).
    Never writes `asset_metadata`. Idempotent — running twice over the same
    ids yields the same asset_state rows: what is carried forward is the
    pruned output of the previous run, and re-folding the same claims over
    it re-derives the same set.

    Projects every id that still resolves to an `assets_canonical` row —
    skipping only ids that don't (deleted mid-scan). Before planning#144
    L3c-3 this also skipped ids with no claims AND no asset_metadata; with
    the metadata read gone that guard would have started dropping
    identity-only DNS records, which carry no port claim but whose
    `probe_class`/`provider_mx` are derived from their columns alone and so
    always have something to project.
    """
    if not asset_ids:
        return

    canonical_by_id: dict[uuid.UUID, AssetCanonical] = {
        r.id: r
        for r in db.query(AssetCanonical).filter(AssetCanonical.id.in_(asset_ids)).all()
    }

    # planning#172 — the flap-guard's missing input, batch-loaded here and
    # applied per asset by _carry_forward_unclaimed_ports below.
    prior_ports_by_asset: dict[uuid.UUID, list] = {
        asset_id: state.open_ports
        for asset_id, state in load_states(db, asset_ids).items()
        if isinstance(state.open_ports, list)
    }

    claim_rows = (
        db.query(
            AssetClaim.asset_canonical_id,
            AssetClaim.claim_value,
            AssetClaim.last_observed_at,
            AssetClaim.evidence,
            Observer.name,
        )
        .join(Observer, AssetClaim.observer_id == Observer.id)
        .filter(
            AssetClaim.asset_canonical_id.in_(asset_ids),
            AssetClaim.claim_type == "port_observation",
        )
        .all()
    )
    claims_by_asset: dict[uuid.UUID, list[tuple[str, dict, datetime, dict]]] = {}
    for asset_id, claim_value, last_observed_at, evidence, observer_name in claim_rows:
        claims_by_asset.setdefault(asset_id, []).append(
            (observer_name, claim_value, last_observed_at, evidence)
        )

    # Single-value claims, batch-loaded up front like port_observation above
    # rather than a get_current_claim() call per asset in the loop below.
    #
    # Three of the four are single-owner TTL caches or service outputs, so
    # they are pinned to the observer that owns them (planning#144 L3a for
    # hosting_class/affinity_confirmation, L3c-3 for eol_status) — a claim of
    # that type from anyone else is not the value this projection means.
    # cdn_boundary is deliberately NOT pinned: the CDN judgment is made by
    # whichever discovery observer resolved the CNAME (dns_resolve today,
    # dns_records or a future resolver tomorrow), so it is taken from any
    # observer, most-recently-observed winning.
    _OWNED_CLAIMS = {
        "hosting_class": "hosting_classifier",
        "affinity_confirmation": "shared_infra_verifier",
        "eol_status": "eol_enrichment",
        # planning#182 Tier 2: the passive-DNS tenancy signal is DERIVED from
        # this claim rather than produced as a second one — hosting_classifier
        # already writes `sharing` here and already paid mnemonic's quota for
        # it. Pinned like its `hosting_class` sibling, and for the same
        # reason: it is that service's own TTL cache.
        "reverse_ip": "hosting_classifier",
    }
    observer_name_by_id = {
        observer_id: name for observer_id, name in db.query(Observer.id, Observer.name).all()
    }
    hosting_class_by_asset: dict[uuid.UUID, dict] = {}
    affinity_confirmation_by_asset: dict[uuid.UUID, dict] = {}
    eol_status_by_asset: dict[uuid.UUID, dict] = {}
    reverse_ip_by_asset: dict[uuid.UUID, dict] = {}
    # planning#182: a LIST per asset, not a single value — `tenancy` is the
    # one claim type read from a SET of observers with no most-recent-wins
    # fold, because every live rung of the ladder is composed together.
    tenancy_claims_by_asset: dict[uuid.UUID, list[tuple[str, dict]]] = {}
    cdn_boundary_by_asset: dict[uuid.UUID, dict] = {}
    third_party_by_asset: dict[uuid.UUID, dict] = {}
    cloud_inventory_by_asset: dict[uuid.UUID, dict] = {}
    _cdn_seen_at: dict[uuid.UUID, datetime] = {}
    _cloud_inventory_seen_at: dict[uuid.UUID, datetime] = {}
    single_claim_rows = (
        db.query(
            AssetClaim.asset_canonical_id,
            AssetClaim.claim_type,
            AssetClaim.claim_value,
            AssetClaim.observer_id,
            AssetClaim.last_observed_at,
        )
        .filter(
            AssetClaim.asset_canonical_id.in_(asset_ids),
            AssetClaim.claim_type.in_(
                list(_OWNED_CLAIMS)
                + ["cdn_boundary", "third_party_dependency", "cloud_inventory", "tenancy"]
            ),
        )
        .all()
    )
    for asset_id, claim_type, claim_value, observer_id, last_observed_at in single_claim_rows:
        if claim_type == "third_party_dependency":
            # Not observer-pinned, same reasoning as cdn_boundary: whichever
            # discovery observer crossed the boundary is entitled to say so.
            third_party_by_asset[asset_id] = claim_value
            continue
        if claim_type == "cdn_boundary":
            previous = _cdn_seen_at.get(asset_id)
            if previous is None or last_observed_at > previous:
                _cdn_seen_at[asset_id] = last_observed_at
                cdn_boundary_by_asset[asset_id] = claim_value
            continue
        if claim_type == "tenancy":
            # planning#182: observer-SCOPED but not observer-PINNED, and
            # deliberately neither of the two existing patterns. Unlike
            # hosting_class/affinity_confirmation/eol_status a single owner
            # would be wrong (the ladder is several rungs by construction);
            # unlike cdn_boundary/cloud_inventory a most-recently-observed
            # fold would be wrong too, because that silently discards every
            # rung but the freshest, and the composition rule's whole job is
            # to read them together. `_TENANCY_OBSERVERS` still gates WHO may
            # vote — an unlisted observer's `tenancy` claim is ignored here,
            # not folded in.
            if observer_name_by_id.get(observer_id) in _TENANCY_OBSERVERS:
                tenancy_claims_by_asset.setdefault(asset_id, []).append(
                    (observer_name_by_id[observer_id], claim_value)
                )
            continue
        if claim_type == "cloud_inventory":
            # planning#145 L4: NOT observer-pinned, unlike hosting_class/
            # affinity_confirmation/eol_status above. cloud_inventory is
            # *defined* as credentialed proof of ownership (planning#142
            # D1), and more than one credentialed producer can legitimately
            # emit it — Wiz, cloudlist, a future cloud connector
            # (planning#141/#118) — so this folds every observer's claim,
            # most-recently-observed winning, same as cdn_boundary just
            # above. Whether a given producer is ENTITLED to emit
            # cloud_inventory at all is enforced at emission time (which
            # observers are seeded/authorised to write it), not
            # re-litigated here at projection time.
            previous = _cloud_inventory_seen_at.get(asset_id)
            if previous is None or last_observed_at > previous:
                _cloud_inventory_seen_at[asset_id] = last_observed_at
                cloud_inventory_by_asset[asset_id] = claim_value
            continue
        if observer_name_by_id.get(observer_id) != _OWNED_CLAIMS[claim_type]:
            continue
        if claim_type == "hosting_class":
            hosting_class_by_asset[asset_id] = claim_value
        elif claim_type == "affinity_confirmation":
            affinity_confirmation_by_asset[asset_id] = claim_value
        elif claim_type == "eol_status":
            eol_status_by_asset[asset_id] = claim_value
        elif claim_type == "reverse_ip":
            reverse_ip_by_asset[asset_id] = claim_value

    # CIDR/IP-scoped ip_address ids, computed once for the whole batch —
    # target_scope._ip_scoped_asset_ids takes the full ip/cidr target list,
    # not a per-asset lookup.
    ip_target_values = [
        v for (v,) in db.query(Target.value)
        .filter(Target.type.in_([TargetType.IP, TargetType.CIDR]))
        .all()
    ]
    cidr_scoped_ids = target_scope._ip_scoped_asset_ids(db, ip_target_values)

    rows_to_upsert: list[dict] = []

    for asset_id in asset_ids:
        canonical = canonical_by_id.get(asset_id)
        asset_claims = claims_by_asset.get(asset_id, [])
        hosting_claim_value = hosting_class_by_asset.get(asset_id)
        affinity_claim_value = affinity_confirmation_by_asset.get(asset_id)
        eol_claim_value = eol_status_by_asset.get(asset_id)
        cdn_claim_value = cdn_boundary_by_asset.get(asset_id)
        third_party_claim_value = third_party_by_asset.get(asset_id)
        cloud_inventory_claim_value = cloud_inventory_by_asset.get(asset_id)
        tenancy_rung_claims = tenancy_claims_by_asset.get(asset_id, [])
        reverse_ip_claim_value = reverse_ip_by_asset.get(asset_id)

        if canonical is None:
            continue  # id doesn't resolve to a row (deleted mid-scan)

        # ── open_ports: fold every observer's claim through _merge_open_ports,
        # restoring the observer identity the emitter stripped, then prune on
        # the naabu observer's last_observed_at (no naabu claim -> keep all).
        merged_ports: list = []
        naabu_last_observed_at: datetime | None = None
        for observer_name, claim_value, last_observed_at, evidence in asset_claims:
            ports = claim_value.get("ports") if isinstance(claim_value, dict) else None
            if not isinstance(ports, list):
                continue
            restored: list[dict] = []
            for entry in ports:
                if not isinstance(entry, dict):
                    continue
                entry = dict(entry)
                entry["sources"] = [observer_name]
                restored.append(entry)
            merged_ports = _merge_open_ports(merged_ports, restored)
            if observer_name == "naabu":
                # planning#169 — only a pass that FINISHED licenses absence.
                # An incomplete sweep's confirmed ports are real and are folded
                # in above; what it may not do is advance the staleness cutoff,
                # which both DELETES here (_prune_stale_ports) and drives the
                # read-time hide via attributes["naabu_last_scan_at"] below.
                # Leaving naabu_last_observed_at None withholds both for this
                # cycle: the previous complete sweep's cutoff is deliberately
                # NOT carried forward, so a genuine phantom is retired one scan
                # later than it could be — and no real port is ever deleted.
                # A claim with no `complete` key predates #169 (or came from a
                # producer with no notion of an unfinished pass) and counts as
                # complete, preserving the previous behaviour exactly.
                if not (isinstance(evidence, dict) and evidence.get("complete") is False):
                    naabu_last_observed_at = last_observed_at

        # planning#172 — must run BEFORE the prune: it exists purely to give the
        # prune's grace branches something to judge.
        merged_ports = _carry_forward_unclaimed_ports(
            merged_ports, prior_ports_by_asset.get(asset_id, [])
        )

        if naabu_last_observed_at is not None:
            cutoff_iso = naabu_last_observed_at.isoformat()
            merged_ports = _prune_stale_ports(merged_ports, cutoff_iso, now)

        # ── hosting_class / affinity_confirmation claims (planning#144 L3a) ──
        hosting = hosting_claim_value if isinstance(hosting_claim_value, dict) else {}

        # ── eol_summary: the eol_enrichment observer's `eol_status` claim
        # (planning#144 L3c-3 — the last path-2 asset_metadata read in this
        # module, now gone). The claim carries a LIST of per-port EOL
        # records under `services`, despite the column being named
        # eol_summary; L3c-2 found the old passthrough guard here checking
        # isinstance(dict) and silently discarding every real list into {}.
        eol_summary = eol_claim_value.get("services") if isinstance(eol_claim_value, dict) else None
        if not isinstance(eol_summary, list):
            eol_summary = []

        verdict = affinity_claim_value.get("verdict") if isinstance(affinity_claim_value, dict) else None
        cloud_inventory_confirmed = (
            isinstance(cloud_inventory_claim_value, dict)
            and cloud_inventory_claim_value.get("confirmed") is True
        )
        if cloud_inventory_confirmed:
            # planning#145 L4: proven_ours — the promotion path the epic was
            # missing. Estate precedence, most-to-least authoritative:
            #   cloud_inventory.confirmed -> proven_ours
            #   else third_party_dependency present -> not_ours
            #   else verdict == confirmed_ours -> claimed_ours
            #   else verdict == rejected_shared_infra -> not_ours
            #   else None (no ownership signal)
            # cloud_inventory outranks EVERYTHING, including
            # third_party_dependency: that claim is a name-scoping
            # INFERENCE (dns_resolve saw the CNAME target fall outside
            # every declared target domain), whereas cloud_inventory is
            # credentialed PROOF of ownership from a connector with API
            # access to the org's own cloud account. An org's own cloud
            # hostname can legitimately sit outside its declared target
            # domains — proof of ownership beats an inference of
            # non-ownership, not the other way round.
            estate = "proven_ours"
        elif third_party_claim_value is not None:
            # planning#147: a captured CNAME boundary target. Not ours by
            # observation — dns_resolve saw it fall outside every declared
            # target domain — and it outranks any affinity verdict, because
            # we never probed it and never will, so an affinity claim on it
            # could only be stale or mistaken.
            estate = "not_ours"
        elif verdict == "confirmed_ours":
            estate = "claimed_ours"
        elif verdict == "rejected_shared_infra":
            estate = "not_ours"
        else:
            # No ownership signal (absent, unverified, ownership_unverifiable,
            # …) -> NULL. Do not invent an estate-unknown default here — per
            # planning#145's settled decision, "unknown" is mapped in the
            # query layer (app.services.claims_query.surface), never stored.
            estate = None

        # ── provider_mx (recomputed from the L3b-1 record_type/content
        # columns, not asset_metadata) ─────────────────────────────────────
        asset_type = canonical.asset_type if canonical is not None else None
        if (
            asset_type == "dns_record"
            and canonical is not None
            and canonical.record_type == "MX"
            and canonical.content
        ):
            provider_mx = is_provider_managed_mx(canonical.content)
        else:
            provider_mx = False

        # ── composed tenancy (planning#182 rung 3) ─────────────────────────
        # Every rung's opinion, folded by the asymmetric rule documented at
        # `_compose_tenancy`. Computed for ip_address assets only: no other
        # asset type has an address for a rung to have an opinion about, and
        # writing `no_rungs_reported` onto every hostname would put a
        # meaningless key on most rows in the table.
        if asset_type == "ip_address":
            tenancy_opinions = [
                o for o in (
                    [_tenancy_opinion_from_claim(obs, cv) for obs, cv in tenancy_rung_claims]
                    + [_tier2_tenancy_opinion(reverse_ip_claim_value)]
                ) if o is not None
            ]
            composed_tenancy = _compose_tenancy(tenancy_opinions)
        else:
            composed_tenancy = {"tenancy": _TENANCY_UNDETERMINED, "rule": "not_an_address", "rungs": []}

        # planning#128: `cloud_inventory.confirmed` now reaches probe_class,
        # closing the seam planning#145 L4 deliberately left open (its comment
        # here said probe eligibility was the authorisation gate's business —
        # this IS that issue, so the seam closes rather than persists).
        #
        # Until it did, the evidence hierarchy was inverted: an address we
        # hold CREDENTIALED INVENTORY PROOF for projected as `name_only`,
        # while an address that merely looked like a datacenter IP with a
        # heuristic affinity verdict earned `direct_addressable`. The weaker
        # evidence licensed more probing than the stronger evidence.
        #
        # Ordering is load-bearing: this sits BELOW the two `no_probe`
        # branches. A third-party boundary still wins, even over proof of
        # ownership — those two are not in tension, they answer different
        # questions. `cloud_inventory` says "this address is in our cloud
        # account"; `third_party_dependency` says "we resolved through here
        # to somebody else's service". An address can be both (our account,
        # fronting a vendor's endpoint), and in that case not probing is the
        # safe reading. Estate precedence runs the other way — see the
        # comment on the estate chain above — because "is this ours" and
        # "may we send it traffic" are genuinely different questions and
        # this codebase answers them separately on purpose.
        #
        # Freshness is handled by the claim, not here: `cloud_inventory`
        # carries `authorisation_ttl = 1 day` (migration 0039), so a missed
        # connector sync lapses probe eligibility back to `name_only` rather
        # than letting a stale proof keep licensing bare-IP probes.
        if third_party_claim_value is not None:
            # Capture is not scan eligibility (planning#147). This is the
            # projected half of that rule; `_extract_scan_targets` enforces
            # the in-batch half.
            probe_class = "no_probe"
        elif provider_mx:
            probe_class = "no_probe"
        elif cloud_inventory_confirmed:
            probe_class = "direct_addressable"
        elif asset_type == "ip_address" and (
            asset_id in cidr_scoped_ids
            # planning#182 rung 3: `hosting.is_datacenter` is GONE from this
            # disjunct, replaced by the composed tenancy verdict.
            #
            # is_datacenter was never the right question. It asked "does this
            # address belong to a hosting provider", which is true of a CDN
            # edge node, an object-storage front end and a managed load
            # balancer alike — none of which is a customer VM we may point a
            # port scanner at. Worse, planning#177: it fails SOFT to False on
            # an unattempted or broken lookup, so a vendor schema change
            # presented for a month as a policy outcome. The composed verdict
            # cannot do that — an absent or unanswerable rung lands on
            # `undetermined` and is recorded as such (see `_compose_tenancy`).
            #
            # The two caps stay SEPARATE and are ANDed, never collapsed
            # (planning#178, restated on #181/#182 as the single most
            # important line): tenancy says "one tenant lives at this
            # address", ownership says "that tenant is us". A recycled
            # address sitting in a pure-VPS range satisfies the first and
            # not the second, and scanning it is scanning a stranger's host.
            or (composed_tenancy["tenancy"] == _SINGLE_TENANT and verdict == "confirmed_ours")
        ):
            probe_class = "direct_addressable"
        else:
            probe_class = "name_only"

        attributes: dict = {"probe_class": probe_class, "provider_mx": provider_mx}
        if asset_type == "ip_address":
            # Carried onto the projection, and from there into
            # `authorisation_decisions.evidence_snapshot` by
            # `probe_authorisation._compose`, so a denial says WHICH of
            # planning#177's three collapsed cases it was. `rule_fired` alone
            # cannot: an IP at `name_only` probed by an ip-addressing
            # connector reports `addressing_not_permitted` whether tenancy was
            # unknown, unanswerable or a genuine negative. planning#182's
            # acceptance criterion allows either a distinguishing `rule_fired`
            # or evidence on the row; this is the evidence route, chosen
            # because it leaves every existing rule string — which the #148
            # log-only rollout is already being read by — untouched.
            attributes["tenancy"] = composed_tenancy

        if naabu_last_observed_at is not None:
            attributes["naabu_last_scan_at"] = naabu_last_observed_at.isoformat()

        # ── cdn / cdn_domain: the discovery observer's `cdn_boundary` claim
        # (planning#144 L3c-3). This replaces the L3b-2 stopgap, which
        # mirrored the keys straight out of the asset_metadata column — a
        # passthrough that would have had no source left once L3c-4 drops
        # that column. Still NOT recomputed here: the boundary judgment
        # belongs to dns_resolve, this only projects it. #147 replaces the
        # whole annotation with a real CNAME -> third-party edge.
        if isinstance(cdn_claim_value, dict):
            for attr_key in ("cdn", "cdn_domain"):
                if attr_key in cdn_claim_value:
                    attributes[attr_key] = cdn_claim_value[attr_key]

        rows_to_upsert.append({
            "asset_canonical_id": asset_id,
            "open_ports": merged_ports,
            "estate": estate,
            "hosting": hosting,
            "eol_summary": eol_summary,
            "attributes": attributes,
            "projected_at": now,
        })

    if not rows_to_upsert:
        return

    stmt = pg_insert(AssetState.__table__).values(rows_to_upsert)
    stmt = stmt.on_conflict_do_update(
        index_elements=["asset_canonical_id"],
        set_={
            "open_ports": stmt.excluded.open_ports,
            "estate": stmt.excluded.estate,
            "hosting": stmt.excluded.hosting,
            "eol_summary": stmt.excluded.eol_summary,
            # Merge rather than overwrite so future keys (this slice only
            # ever writes probe_class) don't clobber each other; same key
            # from this run wins, matching every other merge in this module.
            "attributes": AssetState.__table__.c.attributes.op("||")(stmt.excluded.attributes),
            "projected_at": stmt.excluded.projected_at,
        },
    )
    db.execute(stmt)
