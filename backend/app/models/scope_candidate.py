import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# Mirror the CHECK-backed vocabularies in migration 0083 by hand (the same
# pattern as `entity_relation.py`). `test_org_discovery_schema.py` fails if
# any of these drifts from the migration's lists; `SIGNAL_TYPES` is also
# compared with `org_discovery.tiers.SIGNALS`.
CANDIDATE_KINDS: frozenset[str] = frozenset({"domain"})
CANDIDATE_STATUSES: frozenset[str] = frozenset({"open", "claimed", "rejected"})
ACCEPTED_INTO: frozenset[str] = frozenset({"engagement", "estate"})
SIGNAL_TYPES: frozenset[str] = frozenset({
    "admin_seed", "person_evidence", "filer_10k_website", "connector_zone",
    "registrant_email_claimed", "redirect_to_claimed", "shared_vanity_ns",
    "mx_into_claimed", "spf_sender_shared", "dmarc_report_to_claimed",
    "dmarc_exact_vendor", "registrant_org_match", "research_quote",
    "reverse_ip_dedicated", "dmarc_exact_generic", "name_similarity", "ai_mention",
})
ANCHOR_KINDS: frozenset[str] = frozenset({"claimed_candidate", "filer_filing", "person"})
EVENT_KINDS: frozenset[str] = frozenset({"claimed", "rejected", "unlocked"})


class ScopeCandidate(Base):
    """Something (a domain today) that may belong to a root organization
    (planning#277 S1a). Never scan scope by itself: only `claim`, called by
    a person, turns one into a `Target`.

    Migration 0083's docstring carries the invariants: root/kind/value are
    immutable, status moves open -> claimed | rejected and rejected -> open
    only, and every decision column follows `status`. Strength is not stored;
    it is calculated on load from the candidate's `ScopeSignal` rows
    (`org_discovery.strength`).
    """

    __tablename__ = "scope_candidates"
    __table_args__ = (
        UniqueConstraint("root_entity_id", "kind", "value", name="uq_scope_candidates_root_kind_value"),
        Index("ix_scope_candidates_root_status", "root_entity_id", "status"),
        # The post-discovery reverse-IP step finds claimed candidates by target (0084).
        Index("ix_scope_candidates_target_id", "target_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    root_entity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("org_entities.id", ondelete="RESTRICT"), nullable=False
    )
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="open", server_default=text("'open'"))
    affiliated_entity_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("org_entities.id", ondelete="RESTRICT"), nullable=True
    )
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decided_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    rejected_strong_types: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)
    accepted_into: Mapped[str | None] = mapped_column(Text, nullable=True)
    engagement_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("engagements.id", ondelete="RESTRICT"), nullable=True
    )
    target_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class ScopeSignal(Base):
    """One independent reason a candidate may belong to its root. See
    `org_discovery.tiers.SIGNALS` for the tier of each type and migration
    0083 for the anchor rules. Only `last_seen_at` ever changes."""

    __tablename__ = "scope_signals"
    __table_args__ = (
        UniqueConstraint(
            "candidate_id", "signal_type", "anchor_kind", "anchor_candidate_id", "anchor_entity_id", "evidence_id",
            name="uq_scope_signals_route", postgresql_nulls_not_distinct=True,
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    candidate_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scope_candidates.id", ondelete="RESTRICT"), nullable=False
    )
    signal_type: Mapped[str] = mapped_column(Text, nullable=False)
    anchor_kind: Mapped[str] = mapped_column(Text, nullable=False)
    anchor_candidate_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scope_candidates.id", ondelete="RESTRICT"), nullable=True
    )
    anchor_entity_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("org_entities.id", ondelete="RESTRICT"), nullable=True
    )
    anchor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    via_entity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("org_entities.id", ondelete="RESTRICT"), nullable=False
    )
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("evidence_fetches.id", ondelete="RESTRICT"), nullable=True
    )
    quote: Mapped[str | None] = mapped_column(Text, nullable=True)
    observer_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("observers.id"), nullable=True)
    # What two domains were found to share (migration 0084): NS/MX hosts,
    # SPF senders, the folded registrant org, an IP. NULL for document types.
    matched_values: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class ScopeCandidateEvent(Base):
    """Append-only history of a candidate's decisions (migration 0083)."""

    __tablename__ = "scope_candidate_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    candidate_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scope_candidates.id", ondelete="RESTRICT"), nullable=False
    )
    event: Mapped[str] = mapped_column(Text, nullable=False)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    signal_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scope_signals.id", ondelete="RESTRICT"), nullable=True
    )
