import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# Mirror the CHECK-backed vocabularies in migration 0079 by hand (the same
# pattern as `finding_ai_writeup.py`).
ALERT_KINDS: frozenset[str] = frozenset({"new", "promotion"})
DELIVERY_OUTCOMES: frozenset[str] = frozenset({"sent", "failed", "raised", "no_channel", "no_recipients", "deferred_to_digest"})


class AlertDispatch(Base):
    """One notification rule's selection in one dispatcher call (planning#233).
    `rule_name` is a snapshot; `rule_id` goes NULL if the rule is deleted."""

    __tablename__ = "alert_dispatches"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    rule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("notification_rules.id", ondelete="SET NULL"), nullable=True
    )
    rule_name: Mapped[str] = mapped_column(Text, nullable=False)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    # The digest that claimed this dispatch (migration 0080); NULL = unclaimed.
    digest_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("digests.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class AlertEvent(Base):
    """One finding in a dispatch's selection, with its severity at the time
    and (for a promotion) the band change in `detail`."""

    __tablename__ = "alert_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    dispatch_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alert_dispatches.id", ondelete="CASCADE"), nullable=False
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("findings_canonical.id", ondelete="CASCADE"), nullable=False
    )
    severity: Mapped[str | None] = mapped_column(Text, nullable=True)
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class AlertDelivery(Base):
    """One outcome per dispatch per connector. `no_channel` / `no_recipients`
    and `deferred_to_digest` carry a NULL `connector_id` (CHECK in 0079/0080)."""

    __tablename__ = "alert_deliveries"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    dispatch_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alert_dispatches.id", ondelete="CASCADE"), nullable=False
    )
    connector_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    outcome: Mapped[str] = mapped_column(Text, nullable=False)
    recipient_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=text("0"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
