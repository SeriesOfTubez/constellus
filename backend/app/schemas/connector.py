import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel


class ConnectorInstanceCreate(BaseModel):
    name: str
    bound_entity_id: uuid.UUID | None = None
    config: dict[str, Any] = {}


class ConnectorInstanceUpdate(BaseModel):
    """PATCH body: only the fields present are applied (`bound_entity_id: null`
    is an explicit unbind, which an account type refuses)."""

    name: str | None = None
    bound_entity_id: uuid.UUID | None = None


class ConnectorConfigUpdate(BaseModel):
    config: dict[str, Any]


class ConnectorConfigResponse(BaseModel):
    instance_id: uuid.UUID
    type: str
    enabled: bool
    config: dict[str, Any]


class BindingSuggestionRequest(BaseModel):
    config: dict[str, Any] = {}
    instance_id: uuid.UUID | None = None


class BindingCandidate(BaseModel):
    entity_id: uuid.UUID
    name: str
    matches: int


class BindingSuggestionResponse(BaseModel):
    suggested_entity_id: uuid.UUID | None
    candidates: list[BindingCandidate]
    zone_count: int | None


class ConnectorInstanceSummary(BaseModel):
    """One configured connector. Never carries config (secrets): that is the
    separate, more strictly gated `/config` route."""

    id: uuid.UUID
    type: str
    name: str
    enabled: bool
    configured: bool
    bound_entity_id: uuid.UUID | None
    bound_entity_name: str | None
    # False when the bound organization no longer satisfies the binding rule
    # (e.g. its deal reverted to pre_close); such an instance cannot sync.
    binding_ok: bool
    # Unresolved zone clashes (planning#277 S1b): zones this instance lists that
    # could not be verified/claimed. Rows: GET /instances/{id}/zone-clashes.
    open_zone_clashes: int = 0
    created_at: datetime
    updated_at: datetime


class ZoneClashResponse(BaseModel):
    """One connector zone that could not be acted on. The conflicting ids are
    returned only when the caller can read the referenced row under that row's
    own read scope. Otherwise `reason` is the response-only value
    `conflict_not_visible` (never stored) and both ids are null: the reason
    itself would tell the caller that a deal they cannot see holds the domain."""

    id: uuid.UUID
    zone: str
    reason: str
    conflicting_candidate_id: uuid.UUID | None
    conflicting_target_id: uuid.UUID | None
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None


class ConnectorTypeSummary(BaseModel):
    id: str
    name: str
    description: str
    phase: str
    config_schema: dict[str, Any]
    # True for connectors whose absence visibly degrades core product value
    # (active scanning, service ID, vuln intelligence). Drives the "Core
    # capability" badge and the setup wizard's Core/Optional grouping —
    # not a hard gate, just an expectations-setting signal.
    core: bool = False
    # True when the connector has a tier profile slot whose `enabled` flag
    # is False at the current global aggressiveness setting. Lets the UI
    # explain why an "enabled, configured" connector still isn't running.
    disabled_at_current_tier: bool = False
    # Tier name the above flag was evaluated against — purely informational.
    current_tier: str | None = None
    # Account types (many instances, each bound to an organization). The two
    # flags carry the same value; `multi_instance` is the neutral name.
    account_scoped: bool = False
    multi_instance: bool = False
    # A DNS-discovery type: its instances list zones (Zones tab, sync) and can
    # suggest a binding from them.
    supports_zones: bool = False
    instances: list[ConnectorInstanceSummary] = []


class BindableOrganization(BaseModel):
    """An organization a connector instance may be bound to right now."""

    id: uuid.UUID
    name: str
    relationship: str
    # The deal's engagement posture (day_0 / integrated); None for `ours`.
    posture: str | None
