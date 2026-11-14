import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import INET, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# Mirror the CHECK-backed vocabulary in migration 0102 by hand.
ENDPOINT_PROTOCOLS: tuple[str, ...] = ("tcp", "udp")


class FindingEndpoint(Base):
    """One place a finding was observed (planning#347): address, port and
    transport protocol. A finding has no port in its identity, so one finding
    can have several endpoints. Migration 0102's docstring carries the
    invariants: NULL means the source did not record that part (never a
    default), a row has an address or a port, the observer is the finding's own
    `source`, and re-observation only moves `last_seen_at`.

    Written only by `finding_writer`, under the finding's row lock."""

    __tablename__ = "finding_endpoints"
    __table_args__ = (
        UniqueConstraint(
            "finding_id", "address", "port", "protocol",
            name="uq_finding_endpoints_endpoint",
            postgresql_nulls_not_distinct=True,
        ),
        CheckConstraint("address IS NOT NULL OR port IS NOT NULL", name="ck_finding_endpoints_address_or_port"),
        CheckConstraint(
            "address IS NULL OR masklen(address) = CASE family(address) WHEN 4 THEN 32 ELSE 128 END",
            name="ck_finding_endpoints_address_is_host",
        ),
        CheckConstraint("port IS NULL OR (port >= 1 AND port <= 65535)", name="ck_finding_endpoints_port_range"),
        CheckConstraint("protocol IS NULL OR protocol IN ('tcp', 'udp')", name="ck_finding_endpoints_protocol"),
        CheckConstraint("last_seen_at >= first_seen_at", name="ck_finding_endpoints_last_after_first"),
        Index("ix_finding_endpoints_address", "address"),
        Index("ix_finding_endpoints_port", "port"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("findings_canonical.id", ondelete="CASCADE"), nullable=False
    )
    address: Mapped[str | None] = mapped_column(INET, nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("now()"))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("now()"))
