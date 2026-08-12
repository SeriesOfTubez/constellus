import secrets
import uuid
from datetime import datetime
from enum import Enum

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class TargetType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"


class VerificationMethod(str, Enum):
    CONNECTOR = "connector"
    TXT_RECORD = "txt_record"
    ACKNOWLEDGED = "acknowledged"
    PTR_MATCH = "ptr_match"
    MANUAL = "manual"  # added via UI; act of adding implies operator authorisation


class Target(Base):
    __tablename__ = "targets"
    __table_args__ = (UniqueConstraint("value", name="uq_targets_value"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    type: Mapped[str] = mapped_column(String(10), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    verification_method: Mapped[str | None] = mapped_column(String(20), nullable=True)
    connector_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    token: Mapped[str] = mapped_column(String(64), nullable=False, default=lambda: secrets.token_hex(32))
    whois_org: Mapped[str | None] = mapped_column(String(255), nullable=True)
    whois_asn: Mapped[str | None] = mapped_column(String(50), nullable=True)
    verified_by_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default=text("'[]'"))
    # source_type: where the target came from. Auto-managed targets are
    # owned by a connector — deleted on sync removal, not by the user.
    source_type: Mapped[str] = mapped_column(String(32), nullable=False, default="manual", server_default=text("'manual'"))
    auto_managed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=text("false"))
    # Per-target aggressiveness override. NULL = inherit from the
    # template/global default. Resolution order is target > template > global,
    # implemented in app.services.aggressiveness.effective_for_target.
    aggressiveness: Mapped[str | None] = mapped_column(String(20), nullable=True)
