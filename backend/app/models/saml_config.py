import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class SamlConfig(Base):
    """
    Single SAML IdP configuration. Only one active config is supported at a time.
    Metadata XML is fetched from metadata_url and cached here so the app
    doesn't depend on the IdP being reachable at runtime.
    """

    __tablename__ = "saml_configs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # IdP metadata URL — app fetches and parses this automatically
    metadata_url: Mapped[str] = mapped_column(String(1024), nullable=False)

    # Cached metadata — refreshed on demand or on a schedule
    metadata_xml: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_fetched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # SP (this app) settings
    sp_entity_id: Mapped[str] = mapped_column(String(512), nullable=False)
    sp_acs_url: Mapped[str] = mapped_column(String(512), nullable=False)

    # Behaviour settings
    jit_provisioning: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    allow_local_fallback: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
