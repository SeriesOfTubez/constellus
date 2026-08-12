from typing import Any

from pydantic import BaseModel


class ConnectorConfigUpdate(BaseModel):
    config: dict[str, Any]


class ConnectorConfigResponse(BaseModel):
    connector_id: str
    enabled: bool
    config: dict[str, Any]


class ConnectorSummary(BaseModel):
    id: str
    name: str
    description: str
    phase: str
    enabled: bool
    configured: bool
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
