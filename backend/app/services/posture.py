"""Engagement-posture policy (planning#132, planning#196 step 2).

This module is the SHARED policy the two places that enforce engagement
posture must both call, instead of each independently reading
`targets.ma_pre_close` and reimplementing the same decision. Before this
module existed, `app.services.probe_authorisation._posture_cap` (the
asset-shaped gate) and `app.services.scan_executor._run_pipeline` (the
discovery-phase dnsrecon/bruteforce enablement check) each read
`targets.ma_pre_close` directly and each independently decided who counted
as "too noisy" for a pre-close M&A target. That is precisely the kind of
duplication `probe_authorisation`'s own module docstring calls a bug, not a
convenience (see epic#81 and the shared-infra false-attribution history it
cites): two code paths that can each independently decide a security-load-
bearing question will eventually disagree, and planning#196 exists because
they already had — the discovery phase's `is_scan_authorised` check knows
nothing about posture at all, so route (c) (planning#193) had to bolt a
second, ad hoc `posture_passive` flag onto `scan_executor` rather than reuse
the probe gate's own cap.

## Why a shared POLICY, not one shared CALLABLE

planning#196's own hand-off considered routing the discovery phase's check
through `probe_authorisation.authorise_probes` itself, and rejected it: a
domain being enumerated has no canonical identity yet.
`assets_canonical` identity for a `dns_record` is `(asset_type, value,
record_type, content)` — a row per RECORD, not per domain — and
`write_assets(..., target_ids=...)` (`scan_executor.py`, Phase 1) runs
*after* the discovery tools in this same loop, so on a brand-new target's
first-ever scan there is nothing to resolve to a canonical row at all. An
asset-shaped gate consulted before any asset exists would deny ALL
first-run discovery — the exact availability regression that already
forced `probe_authorisation_mode` to default to `log_only` (see that
module's "Gate mode" section). So instead of one callable serving both
shapes, this module exports the DECISION FUNCTION
(`observer_permitted`) and the two PREDICATE renderings
(`passive_only_filter`/`is_passive_only`) that both callers compose for
themselves: `probe_authorisation._posture_cap` (asset-shaped) and
`probe_authorisation.authorise_discovery` (domain-shaped, planning#196 step
2's new entry point).

planning#205 adds a THIRD caller, `probe_authorisation.
authorise_ownership_probe` — the point above ("a third call site is
presumptively either one of these two shapes in disguise") does not hold
for it, and this update exists so that claim does not silently keep reading
as though it still covers every caller. It is asset-shaped, like
`_posture_cap`, but is not just another instance of that shape: it composes
NO scope cap (unlike `_posture_cap`, which is always evaluated alongside
`_scope_cap` inside `authorise_probes`) and is reached from call sites —
`shared_infra_verifier.classify_ip_ownership`,
`dangling_dns_analyzer._evaluate_record`,
`origin_corroboration.corroborate_liveness` — that have no scan run and,
for the manual Re-verify path in particular, no scope dict to compose in
the first place (see `authorise_ownership_probe`'s own docstring, "Why not
`authorise_probes`"). It calls `observer_permitted` the same way
`_posture_cap` does (`passive_only=True` resolved via
`_resolve_ma_pre_close_ids`, real `noise_class` from the seeded `observers`
row), so the policy itself is unchanged — this is a new CALLER of the one
shared decision, not a fourth shape for this module to grow a case for.

## The load-bearing property this module exists to preserve

planning#193 shipped the discovery-phase denial as "deny dnsrecon and
bruteforce outright under `ma_pre_close`". planning#196 replaces that
hardcoded pair with a general noise-class axis (`app.models.observer`,
migration 0055) — but ONLY as a refactor, not a policy change:
`PASSIVE_ONLY_PERMITTED_NOISE`/`PASSIVE_ONLY_DENIED_NOISE` are chosen so
that, applied to the 23 seeded `observers` rows, the resulting denied set is
EXACTLY `{naabu, banner_grab, httpx, tlsx, nuclei, tenancy_tls,
domain_affinity, shared_infra_verifier, dnsrecon, bruteforce}` — the eight
`target_host` observers plus the two `target_infra` observers dnsrecon and
bruteforce, and nothing else. `test_posture_policy.py`'s
`test_seeded_observers_reproduce_planning_193s_shipped_denial_set` pins this
directly against the live seeded table, not against a hand-copied list, so
a future edit to `OBSERVER_NOISE` or to the seed data that changes this set
fails loudly rather than silently drifting.

## Two renderings of one predicate — not two policies

`passive_only_filter()` (a SQLAlchemy expression, for a query that must
compose the predicate into a WHERE clause bounded by a batch of ids — see
`probe_authorisation._resolve_ma_pre_close_ids`) and `is_passive_only()` (a
plain Python function, for a caller that already has one loaded `targets`
row in hand — see `probe_authorisation.authorise_discovery`) exist
separately only because the two call sites have genuinely different
shapes, not because the predicate itself differs. Both must always agree,
by construction, on every `targets` row — `test_posture_policy.py`'s
`test_sql_and_python_renderings_of_the_predicate_agree` asserts exactly
that. When planning#132 eventually turns posture into a real enum (today
it is a single boolean, `ma_pre_close`, standing in for one posture value
out of however many #132 ultimately enumerates), BOTH renderings live in
THIS ONE FILE and must be edited together — that is the whole reason they
are kept side by side here rather than inlined at their respective call
sites.
"""

from __future__ import annotations

from app.models.observer import OBSERVER_NOISE
from app.models.target import Target

# The noise classes a passive-only (pre-close M&A) target still permits.
# Chosen, not derived: `silent` (no attributable network I/O — third-party
# APIs, or claims derived from existing evidence) and `third_party_infra`
# (queries someone else's infrastructure — public recursors — never the
# target's own) are the two classes a counterparty cannot notice at all.
# `target_infra` (queries the target's OWN authoritative nameservers) and
# `target_host` (packets at the target host itself) are both noticeable and
# both denied.
PASSIVE_ONLY_PERMITTED_NOISE: frozenset[str] = frozenset({"silent", "third_party_infra"})

# DERIVED by subtraction from the full vocabulary, not written out as its
# own literal set, so the permitted/denied sets can never drift out of
# partition with each other or with `OBSERVER_NOISE` itself: adding a new
# noise class to `OBSERVER_NOISE` automatically makes it a member of
# EXACTLY one of these two sets (denied, by `observer_permitted`'s
# fail-closed membership test below — see that function's docstring),
# never both and never neither.
PASSIVE_ONLY_DENIED_NOISE: frozenset[str] = OBSERVER_NOISE - PASSIVE_ONLY_PERMITTED_NOISE


def passive_only_filter():
    """SQL rendering of the passive-only posture predicate.

    Returns a fresh SQLAlchemy boolean expression on every call rather than
    a module-level constant, so a caller that composes it into a larger
    `.filter(...)` chain (see
    `probe_authorisation._resolve_ma_pre_close_ids`, which joins it against
    `TargetAssetLink`) can never accidentally share or mutate one
    expression object across queries.

    See `is_passive_only` below for the Python-side rendering of this same
    predicate, and the module docstring's "Two renderings of one predicate"
    section for why both exist and why planning#132 must edit them
    together.
    """
    return Target.ma_pre_close == True  # noqa: E712


def is_passive_only(target_row) -> bool:
    """Python rendering of the same predicate, over one already-loaded
    `targets` row (or `None`, when no target row is in scope at all — a
    domain that was never added as a target still gets a definite `False`
    here rather than raising).

    See `passive_only_filter` above for the SQL rendering of this same
    predicate.
    """
    return bool(target_row is not None and target_row.ma_pre_close)


def observer_permitted(*, passive_only: bool, noise_class: str | None) -> bool:
    """THE decision function: (target posture, observer noise class) ->
    allowed. The single function both `probe_authorisation._posture_cap`
    (asset-shaped) and `probe_authorisation.authorise_discovery`
    (domain-shaped) call to decide whether one observer may act against one
    target — see the module docstring's "Why a shared POLICY, not one
    shared CALLABLE" section for why there are exactly two callers and why
    that is by design.

    Not passive-only: permissive unconditionally — posture has nothing to
    say about an ordinary target, regardless of noise class.

    Passive-only: tests membership of `PASSIVE_ONLY_PERMITTED_NOISE`, NOT
    absence from `PASSIVE_ONLY_DENIED_NOISE` — the two sets partition
    `OBSERVER_NOISE` today (see that constant's derivation above), so this
    distinction is invisible for any currently-seeded observer. It matters
    for everything else: an unknown string, a NULL `noise_class`, or a
    noise class added to `OBSERVER_NOISE` in some future migration before
    anyone has deliberately decided it belongs in the permitted set — all
    of these fail the membership test and are DENIED. That is the fail-
    closed direction on purpose: a tool this function cannot positively
    place in the permitted set does not get to act against a target we
    hold no authorisation to touch, rather than being let through because
    nothing on record says it is forbidden.
    """
    if not passive_only:
        return True
    return noise_class in PASSIVE_ONLY_PERMITTED_NOISE
