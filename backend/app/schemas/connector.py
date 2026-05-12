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
    schema: dict[str, Any]
