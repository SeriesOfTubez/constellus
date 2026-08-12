import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class TagRule(Base):
    """
    Auto-tagging rule. Evaluated against targets, assets, and findings at ingest
    and on-demand via POST /api/tags/rules/evaluate.

    condition format:
      Simple:   {"field": "asset_type", "op": "eq", "value": "dns_record"}
      Glob:     {"field": "value", "op": "glob", "value": "*.cloudfront.net"}
      Compound: {"all": [cond, ...]}  or  {"any": [cond, ...]}

    Supported fields per entity_type:
      target  — type, value, verified, whois_org, whois_asn
      asset   — asset_type, value, parent_value, metadata.<key>
      finding — severity, category, source, finding_type, cve_id, kev
    """

    __tablename__ = "tag_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    entity_type: Mapped[str] = mapped_column(Text, nullable=False, index=True)  # target | asset | finding
    condition: Mapped[dict] = mapped_column(JSONB, nullable=False)
    tag: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
