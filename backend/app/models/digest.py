import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# Mirror the CHECK-backed vocabularies in migration 0080 by hand.
DIGEST_OUTCOMES: frozenset[str] = frozenset({
    "pending", "empty", "sent", "partial", "failed", "no_channel", "no_recipients", "abandoned",
})
NARRATIVE_STATUSES: frozenset[str] = frozenset({"succeeded", "failed", "skipped"})


class Digest(Base):
    """One rule's digest run (planning#233 slice 2a). Written even for an
    empty period, so a rule's newest row is its watermark. `rule_name` is a
    snapshot; `rule_id` goes NULL if the rule is deleted."""

    __tablename__ = "digests"
    __table_args__ = (
        CheckConstraint("period_end > period_start", name="ck_digests_period"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    rule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("notification_rules.id", ondelete="SET NULL"), nullable=True
    )
    rule_name: Mapped[str] = mapped_column(Text, nullable=False)
    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=text("0"))
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=text("0"))
    body: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb"))
    narrative: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    narrative_status: Mapped[str | None] = mapped_column(Text, nullable=True)
    narrative_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    model: Mapped[str | None] = mapped_column(Text, nullable=True)
    forced_strict: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    ledger_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
    outcome: Mapped[str] = mapped_column(Text, nullable=False, default="pending", server_default=text("'pending'"))
    deliveries: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=text("0"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # planning#319: the kind of rule this digest was built for (mirrors 0099).
    kind: Mapped[str] = mapped_column(Text, nullable=False, default="finding", server_default=text("'finding'"))


class DigestCandidate(Base):
    """An organization discovery candidate a rule's digest listed (planning#319).
    The unique key claims each candidate for a rule exactly once. `rule_id`
    goes NULL if the rule is deleted, so the digest's stored body can still be
    filtered when read back."""

    __tablename__ = "digest_candidates"
    __table_args__ = (
        UniqueConstraint("rule_id", "candidate_id", name="uq_digest_candidates_rule_candidate"),
        Index("ix_digest_candidates_digest_id", "digest_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    digest_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("digests.id", ondelete="CASCADE"), nullable=False
    )
    rule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("notification_rules.id", ondelete="SET NULL"), nullable=True
    )
    candidate_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scope_candidates.id", ondelete="CASCADE"), nullable=False
    )
