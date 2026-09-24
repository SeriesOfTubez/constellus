"""Engagement-posture policy (planning#132, planning#196 step 2, planning#211).

This module is the SHARED policy the two places that enforce engagement
posture must both call, instead of each independently reading a posture
value and reimplementing the same decision. Before this module existed,
`app.services.probe_authorisation._posture_cap` (the asset-shaped gate) and
`app.services.scan_executor._run_pipeline` (the discovery-phase dnsrecon/
bruteforce enablement check) each read a bare posture boolean directly and
each independently decided who counted as "too noisy" for a pre-close M&A
target. That is precisely the kind of duplication `probe_authorisation`'s
own module docstring calls a bug, not a convenience (see epic#81 and the
shared-infra false-attribution history it cites): two code paths that can
each independently decide a security-load-bearing question will eventually
disagree, and planning#196 exists because they already had — the discovery
phase's `is_scan_authorised` check knew nothing about posture at all, so
route (c) (planning#193) had to bolt a second, ad hoc `posture_passive`
flag onto `scan_executor` rather than reuse the probe gate's own cap.

## Why a shared POLICY, not one shared CALLABLE

planning#196's own hand-off considered routing the discovery phase's check
through `probe_authorisation.authorise_probes` itself, and rejected it: a
domain being enumerated has no canonical identity yet. So instead of one
callable serving both shapes, this module exports the DECISION FUNCTION
(`observer_permitted`) and the two PREDICATE renderings
(`passive_only_filter`/`is_passive_only`) that both callers compose for
themselves: `probe_authorisation._posture_cap` (asset-shaped) and
`probe_authorisation.authorise_discovery` (domain-shaped). planning#205
adds a third caller, `probe_authorisation.authorise_ownership_probe` —
asset-shaped like `_posture_cap`, calling `observer_permitted` the same
way.

## The load-bearing property this module exists to preserve

planning#193 shipped the discovery-phase denial as "deny dnsrecon and
bruteforce outright under the pre-close M&A flag". planning#196 replaced that
hardcoded pair with a general noise-class axis (`app.models.observer`,
migration 0055) as a REFACTOR, not a policy change:
`PASSIVE_ONLY_PERMITTED_NOISE`/`PASSIVE_ONLY_DENIED_NOISE` are chosen so
that, applied to the 23 seeded `observers` rows, the resulting denied set is
EXACTLY `{naabu, banner_grab, httpx, tlsx, nuclei, tenancy_tls,
domain_affinity, shared_infra_verifier, dnsrecon, bruteforce}` —
`test_posture_policy.py`'s
`test_seeded_observers_reproduce_planning_193s_shipped_denial_set` pins
this directly against the live seeded table.

## planning#211: from a boolean to a real posture object

The engagement object (`app.models.engagement.Engagement`) replaces
the boolean flag this codebase used before. Posture is now read off
`target_row.engagement.posture` — a real four-value enum (`pre_close`,
`day_0`, `integrated`,
`abandoned`) — rather than a single boolean standing in for one posture
value. `RESTRICTING_POSTURES` is the subset that restricts traffic to
passive-only: `pre_close` (the original planning#193 case) AND `abandoned`
(a fallen-through deal restricts FOREVER — see `Engagement`'s docstring;
purging member targets is a separate, explicit human action, never a side
effect of the posture transition). `day_0` and `integrated` are both fully
permissive here — the boundary this module enforces is "may we touch this
target's infrastructure at all", not "has the deal closed" in general.

`observer_permitted` and the noise-class vocabulary below are UNCHANGED by
this re-key — they already took a bare `passive_only: bool`, and that is
still exactly what they take. The whole re-key is contained to
`RESTRICTING_POSTURES`/`posture_restricts`/`passive_only_filter`/
`is_passive_only` in this one file, which is the entire reason both
renderings of the predicate have always lived side by side here rather
than inlined at their call sites.

## Two renderings of one predicate — not two policies

`passive_only_filter()` (a SQLAlchemy expression, for a query that must
compose the predicate into a WHERE clause bounded by a batch of ids — see
`probe_authorisation._resolve_engagements`) and `is_passive_only()` (a
plain Python function, for a caller that already has one loaded `targets`
row, with its `engagement` relationship loaded, in hand — see
`probe_authorisation.authorise_discovery`) exist separately only because
the two call sites have genuinely different shapes, not because the
predicate itself differs. Both must always agree, by construction, on
every `targets` row — `test_posture_policy.py`'s
`test_sql_and_python_renderings_of_the_predicate_agree` asserts exactly
that, now over all four posture values plus "no engagement".
"""

from __future__ import annotations

from sqlalchemy import select

from app.models.engagement import Engagement
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
# partition with each other or with `OBSERVER_NOISE` itself.
PASSIVE_ONLY_DENIED_NOISE: frozenset[str] = OBSERVER_NOISE - PASSIVE_ONLY_PERMITTED_NOISE

# planning#211 — the posture values that restrict traffic to passive-only.
# `pre_close` is the original planning#193 case: an operator has not yet
# closed on the acquisition and holds no authorisation to probe it.
# `abandoned` is here too, and for a DIFFERENT reason: a fallen-through deal
# is not "back to normal" — there was never any authorisation to begin
# with, closing never happened, and nothing about the deal falling through
# grants one retroactively. `abandoned` is TERMINAL (no transition out, see
# `app/api/engagements.py`'s transition table) specifically so this
# membership can never lapse by accident. `day_0`/`integrated` are the two
# non-restricting (widened) states and are deliberately absent.
RESTRICTING_POSTURES: frozenset[str] = frozenset({"pre_close", "abandoned"})


def posture_restricts(posture: str | None) -> bool:
    """`posture in RESTRICTING_POSTURES`. `None` (no engagement at all, or
    an engagement whose posture somehow failed to load) means "nothing to
    restrict" — `False`, not a fail-closed denial: the no-engagement case is
    the ordinary, overwhelmingly common state (an owned target), and this
    function must cost nothing to answer for it, the same reasoning
    `passive_only_filter`/`is_passive_only` below have always applied.
    """
    return posture in RESTRICTING_POSTURES


def passive_only_filter():
    """SQL rendering of the passive-only posture predicate, over
    `targets.engagement_id` joined through `engagements.posture`.

    Returns a fresh SQLAlchemy boolean expression on every call rather than
    a module-level constant, so a caller that composes it into a larger
    `.filter(...)` chain (see `probe_authorisation._resolve_engagements`,
    which joins it against `TargetAssetLink`) can never accidentally share
    or mutate one expression object across queries.

    See `is_passive_only` below for the Python-side rendering of this same
    predicate, and the module docstring's "Two renderings" section for why
    both exist and why they must be edited together.
    """
    return Target.engagement_id.in_(
        select(Engagement.id).where(Engagement.posture.in_(RESTRICTING_POSTURES))
    )


def is_passive_only(target_row) -> bool:
    """Python rendering of the same predicate, over one already-loaded
    `targets` row (or `None`, when no target row is in scope at all — a
    domain that was never added as a target still gets a definite `False`
    here rather than raising) with its `.engagement` relationship
    resolvable (lazy="select" — one extra query per call if not already
    loaded, matching every other single-row lookup in this codebase).

    See `passive_only_filter` above for the SQL rendering of this same
    predicate.
    """
    if target_row is None or target_row.engagement is None:
        return False
    return posture_restricts(target_row.engagement.posture)


def observer_permitted(*, passive_only: bool, noise_class: str | None) -> bool:
    """THE decision function: (target posture, observer noise class) ->
    allowed. The single function both `probe_authorisation._posture_cap`
    (asset-shaped) and `probe_authorisation.authorise_discovery`
    (domain-shaped) call to decide whether one observer may act against one
    target.

    Not passive-only: permissive unconditionally — posture has nothing to
    say about an ordinary target, regardless of noise class.

    Passive-only: tests membership of `PASSIVE_ONLY_PERMITTED_NOISE`, NOT
    absence from `PASSIVE_ONLY_DENIED_NOISE` — an unknown string, a NULL
    `noise_class`, or a noise class added to `OBSERVER_NOISE` in some future
    migration before anyone has deliberately decided it belongs in the
    permitted set all fail the membership test and are DENIED. That is the
    fail-closed direction on purpose: a tool this function cannot
    positively place in the permitted set does not get to act against a
    target we hold no authorisation to touch.
    """
    if not passive_only:
        return True
    return noise_class in PASSIVE_ONLY_PERMITTED_NOISE
