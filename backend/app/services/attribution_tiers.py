"""What each evidence row on an attribution chain is worth (planning#358).

The tier words are the candidate-signal tiers (`org_discovery.tiers`), reused
so a reader meets one vocabulary. This table covers the links those tiers do
not: an organization relation, a host seen by an observer, and the ownership
verdict on a host. Jason approved it row by row on 2026-11-14 (planning#358
comment 6889949695).

It is an attribution rule, so it is code, not a setting: a change here is a
reviewed change.

Rules:

* A row gets a tier only from this table. A link with no evidence row has no
  tier.
* A link's own tier is the highest tier among its rows (`highest`).
* The affinity check is SUPPORTING, never STRONG: it is what makes a host
  "claimed", and the tier must not outrank the verdict it produced.
"""

from __future__ import annotations

from collections.abc import Iterable

from app.services.org_discovery.tiers import CONTEXT, SIGNALS, STRONG, SUPPORTING, TIERS

# A confirmed `entity_relations` row always has a fetched source and a quote,
# and was confirmed by a person or by a source granted `confirms_relations`.
RELATION_TIER = STRONG

# A claim row that records that an observer saw the name or address is worth
# what the observer's recorded `trust` says (`models.observer.OBSERVER_TRUST`).
OBSERVER_TRUST_TIERS: dict[str, str] = {
    "observed": STRONG,
    "derived": SUPPORTING,
    "inferred": CONTEXT,
}

# The claim types that record a host being seen. `observation` is the
# value-less claim every observer writes; a certificate-log issuance is a CA
# having issued a certificate for the name.
SIGHTING_CLAIM_TYPES: frozenset[str] = frozenset({"observation", "ct_cert_issuance"})

# The claim types the ownership verdict is projected from (`projector`).
OWNERSHIP_CLAIM_TYPES: frozenset[str] = frozenset(
    {"cloud_inventory", "affinity_confirmation", "tenancy", "third_party_dependency"}
)


def signal_tier(signal_type: str) -> str | None:
    """The tier of a candidate signal; None for a type the table does not know."""
    spec = SIGNALS.get(signal_type)
    return spec.tier if spec is not None else None


def sighting_tier(claim_type: str, observer_trust: str | None) -> str | None:
    """The tier of a claim that records a host being seen."""
    if claim_type == "ct_cert_issuance":
        return STRONG
    if claim_type == "observation":
        return OBSERVER_TRUST_TIERS.get(observer_trust or "")
    return None


def ownership_tier(claim_type: str, claim_value) -> str | None:
    """The tier of a claim as evidence that the host is OURS. None when the
    claim does not say so (an unverified affinity check, a shared address, a
    third-party dependency): such a row is still listed, without a tier."""
    value = claim_value if isinstance(claim_value, dict) else {}
    if claim_type == "cloud_inventory" and value.get("confirmed") is True:
        return STRONG
    if claim_type == "affinity_confirmation" and value.get("verdict") == "confirmed_ours":
        return SUPPORTING
    if claim_type == "tenancy" and value.get("tenancy") == "single_tenant":
        return CONTEXT
    return None


def highest(tiers: Iterable[str | None]) -> str | None:
    """The strongest tier present, or None when there is none."""
    present = {t for t in tiers if t is not None}
    for tier in TIERS:  # strongest first
        if tier in present:
            return tier
    return None
