"""The attribution of an asset (planning#358): the chains of records that link
it to an organization, and the ownership verdict on record for it, as typed
data.

Built at read time by `services/attribution_chain.py` and served on the asset
and finding detail routes. A chain reads from the organization down to the
asset: organization, then any entities under it, then the scope (a target),
then the asset itself (with the hostnames between them where the record needs
them).

Every hop uses the exposure path's statuses (`schemas/exposure_path.py`):
`observed` (a record states this hop), `derived` (worked out from other
records, always a list of `candidates`), `unknown` (nothing on record; `reason`
says what is missing). A missing link is a hop with status `unknown`; a chain
is never padded to look complete.

A hop's `evidence` is the rows that support the link between it and the hop
above. `tier` is the strongest tier among them (`services/attribution_tiers`),
and is None when there is no evidence row.

The chain says how the record links the asset to an organization. Whether the
asset is ours is `Attribution.ownership`, which is the projected estate and is
never inferred from the links.
"""

import uuid
from datetime import date, datetime
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.exposure_path import HopCandidate, HopStatus

Tier = Literal["strong", "supporting", "context"]

# `claims_query.SURFACE_VALUES`. `unknown` = no ownership check is on record.
Surface = Literal["proven_ours", "claimed_ours", "not_ours", "unknown"]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ── evidence rows ────────────────────────────────────────────────────────────


class RelationEvidence(_Model):
    """One confirmed `entity_relations` row: one source's assertion."""

    kind: Literal["relation"] = "relation"
    relation_id: uuid.UUID
    relation: Literal["acquired", "subsidiary_of"]
    # The observer that asserted it.
    source: str | None = None
    tier: Tier | None = None
    # When the relation happened, as the source states it (not when we read it).
    event_date: date | None = None
    event_date_precision: Literal["day", "month", "year", "unknown"]
    # The `evidence_fetches` row holding the source document.
    evidence_id: uuid.UUID
    confirmed_by: Literal["person", "source"] | None = None
    confirmed_at: datetime | None = None


class SignalEvidence(_Model):
    """One `scope_signals` row on the claimed candidate behind a target."""

    kind: Literal["signal"] = "signal"
    signal_id: uuid.UUID
    signal_type: str
    label: str | None = None
    source: str | None = None
    tier: Tier | None = None
    # None when the signal has no fetched document (an admin seed).
    evidence_id: uuid.UUID | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None


class ClaimEvidence(_Model):
    """One `asset_claims` row on the asset."""

    kind: Literal["claim"] = "claim"
    claim_id: uuid.UUID
    claim_type: str
    source: str
    # The observer's recorded trust: observed, derived or inferred.
    source_trust: str | None = None
    tier: Tier | None = None
    # What an ownership claim concluded (an affinity verdict, a tenancy
    # value, "confirmed"); None for a claim that only records a sighting.
    outcome: str | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None


Evidence = Annotated[
    Union[RelationEvidence, SignalEvidence, ClaimEvidence],
    Field(discriminator="kind"),
]


# ── hops ─────────────────────────────────────────────────────────────────────


class _Hop(_Model):
    status: HopStatus
    reason: str | None = None
    # The rows that support the link between this hop and the one above it.
    evidence: list[Evidence] = Field(default_factory=list)
    # More rows exist than are listed. `tier` is taken over all of them.
    evidence_truncated: bool = False
    tier: Tier | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None


class OrganizationHop(_Hop):
    """The organization at the top: an entity marked as ours or as an
    acquisition target. It starts the chain, so it has no evidence or tier."""

    kind: Literal["organization"] = "organization"
    entity_id: uuid.UUID | None = None
    name: str | None = None
    relationship: Literal["ours", "ma_target"] | None = None
    # Who marked the entity as ours, and when. None for an acquisition target.
    marked_at: datetime | None = None
    marked_by_id: uuid.UUID | None = None


class EntityHop(_Hop):
    """An entity between the organization and the scope."""

    kind: Literal["entity"] = "entity"
    entity_id: uuid.UUID
    name: str
    # How this entity relates to the hop above; None when no confirmed
    # relation leads up from it (the organization hop is then `unknown`).
    relation: Literal["acquired", "subsidiary_of"] | None = None


class ScopeHop(_Hop):
    """The target the asset falls under."""

    kind: Literal["scope"] = "scope"
    target_id: uuid.UUID | None = None
    target_type: Literal["domain", "ip", "cidr"] | None = None
    value: str | None = None
    # The claimed candidate that became this target, when one is on record.
    candidate_id: uuid.UUID | None = None
    claimed_at: datetime | None = None
    claimed_by_id: uuid.UUID | None = None


class HostHop(_Hop):
    kind: Literal["host"] = "host"
    asset_id: uuid.UUID | None = None
    hostname: str | None = None
    candidates: list[HopCandidate] = Field(default_factory=list)
    candidates_truncated: bool = False


class AddressHop(_Hop):
    kind: Literal["address"] = "address"
    asset_id: uuid.UUID | None = None
    address: str | None = None


AttributionHop = Annotated[
    Union[OrganizationHop, EntityHop, ScopeHop, HostHop, AddressHop],
    Field(discriminator="kind"),
]


class AttributionChain(_Model):
    # The target this chain runs through; None when no target covers the asset.
    target_id: uuid.UUID | None = None
    # organization, entity (zero or more), scope, host (zero or one, the
    # hostnames between the scope and the asset), then the asset itself as a
    # host or an address. Always in that order.
    hops: list[AttributionHop]


class Ownership(_Model):
    """The ownership verdict on record for the asset (the projected estate)."""

    surface: Surface
    # Plain language about the record, set unless the surface is proven_ours.
    reason: str | None = None
    # The ownership claims on the asset. A row has a tier only when it says
    # the asset is ours.
    evidence: list[ClaimEvidence] = Field(default_factory=list)
    # The strongest tier among the rows, only when the surface is ours.
    tier: Tier | None = None


class Attribution(_Model):
    ownership: Ownership
    # One chain per target the asset falls under and per organization that
    # target leads to. None is promoted over another. Never empty: an asset no
    # target covers has one chain whose upper hops are `unknown`.
    chains: list[AttributionChain]
    chains_truncated: bool = False


class AssetDetailResponse(BaseModel):
    """Documents the typed part of `GET /api/assets/{id}`. The rest of that
    response is still an untyped dict, hence `extra="allow"`."""

    model_config = ConfigDict(extra="allow")

    attribution: Attribution
