import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Text, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# Mirrors migration 0086's CLASH_REASONS by hand; test_org_discovery_schema.py
# fails if it drifts from the migration or the DB CHECK.
CLASH_REASONS: frozenset[str] = frozenset({
    "claimed_by_other_org", "target_in_other_scope", "target_other_entity", "not_a_claimable_domain",
})


class ConnectorZoneClash(Base):
    """A zone a connector instance listed but did not act on, for a person to
    look at (planning#277 S1b, migration 0086). One unresolved row per
    (instance, zone); `resolved_at` is set when a later sync no longer sees it."""

    __tablename__ = "connector_zone_clashes"
    __table_args__ = (
        Index(
            "uq_connector_zone_clashes_open", "instance_id", "zone",
            unique=True, postgresql_where=text("resolved_at IS NULL"),
        ),
        Index("ix_connector_zone_clashes_instance", "instance_id", "resolved_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    instance_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("connector_instances.id", ondelete="CASCADE"), nullable=False
    )
    zone: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    conflicting_candidate_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scope_candidates.id", ondelete="SET NULL"), nullable=True
    )
    conflicting_target_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="SET NULL"), nullable=True
    )
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
