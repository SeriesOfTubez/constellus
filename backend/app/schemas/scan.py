import uuid
from datetime import datetime

from pydantic import BaseModel, field_validator


class ScanOptions(BaseModel):
    cert_transparency: bool = True
    subfinder: bool = True
    dnsrecon: bool = False
    bruteforce: bool = False
    bruteforce_wordlist: str = "small"  # small | medium | large


class ScanScope(BaseModel):
    domains: list[str] = []
    ip_ranges: list[str] = []

    @field_validator("domains")
    @classmethod
    def normalise_domains(cls, v: list[str]) -> list[str]:
        return [d.lower().strip().rstrip(".") for d in v if d.strip()]

    @field_validator("ip_ranges")
    @classmethod
    def normalise_ranges(cls, v: list[str]) -> list[str]:
        return [r.strip() for r in v if r.strip()]


class ScanRequest(BaseModel):
    name: str | None = None
    scope: ScanScope
    options: ScanOptions = ScanOptions()


class ScanResponse(BaseModel):
    id: uuid.UUID
    name: str | None
    status: str
    scope: dict
    options: dict
    connectors_used: list[str] | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    error: str | None
    asset_count: int = 0
    finding_count: int = 0

    model_config = {"from_attributes": True}
