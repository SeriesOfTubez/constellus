import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, HttpUrl


class SamlConfigCreate(BaseModel):
    metadata_url: str
    sp_entity_id: str
    sp_acs_url: str
    jit_provisioning: bool = True
    allow_local_fallback: bool = True


class SamlConfigUpdate(BaseModel):
    metadata_url: Optional[str] = None
    sp_entity_id: Optional[str] = None
    sp_acs_url: Optional[str] = None
    jit_provisioning: Optional[bool] = None
    allow_local_fallback: Optional[bool] = None
    enabled: Optional[bool] = None


class SamlConfigResponse(BaseModel):
    id: uuid.UUID
    enabled: bool
    metadata_url: str
    sp_entity_id: str
    sp_acs_url: str
    jit_provisioning: bool
    allow_local_fallback: bool
    metadata_fetched_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class IdpMetadataPreview(BaseModel):
    """Parsed fields extracted from IdP metadata — shown to admin before saving."""
    entity_id: str
    sso_url: str
    certificate_subject: Optional[str] = None
    valid: bool
    error: Optional[str] = None
