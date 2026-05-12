import secrets
import uuid
from datetime import datetime
from enum import Enum

from sqlalchemy import Boolean, DateTime, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class VerificationMethod(str, Enum):
    CONNECTOR = "connector"
    TXT_RECORD = "txt_record"


class DomainVerification(Base):
    __tablename__ = "domain_verifications"
    __table_args__ = (UniqueConstraint("domain", name="uq_domain_verifications_domain"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    method: Mapped[str | None] = mapped_column(String(20), nullable=True)
    connector_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    token: Mapped[str] = mapped_column(String(64), nullable=False, default=lambda: secrets.token_hex(32))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
