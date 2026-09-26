import uuid
from datetime import date, datetime

from sqlalchemy import Date, DateTime, ForeignKey, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# Mirror the CHECK-backed vocabularies in migration 0064 by hand (the same
# pattern as `entity_relation.py`).
CANDIDATE_SOURCES: frozenset[str] = frozenset({"edgar_10k_website", "person"})
CANDIDATE_STATUSES: frozenset[str] = frozenset({"proposed", "accepted", "rejected"})


class CandidateDomain(Base):
    """A domain that evidence says may belong to an entity (planning#216,
    L6). Never scan scope by itself: only `candidate_domains.accept`, called
    by a person, turns one into a `Target`, and that target is created
    already attached to the chosen engagement, so it inherits its posture.

    Migration 0064's docstring carries the invariants: evidence NOT NULL,
    the quote must contain the domain, decided rows are frozen, and what a
    row claims (entity, domain, evidence, quote) is immutable.
    """

    __tablename__ = "candidate_domains"
    __table_args__ = (UniqueConstraint("entity_id", "domain", name="uq_candidate_domains_entity_domain"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    entity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("org_entities.id", ondelete="RESTRICT"), nullable=False
    )
    domain: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    # NULL iff `source = 'person'` (`ck_candidate_domains_source_observer`).
    observer_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("observers.id"), nullable=True)
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("evidence_fetches.id", ondelete="RESTRICT"), nullable=False
    )
    quote: Mapped[str] = mapped_column(Text, nullable=False)
    # Filing dates of the first/latest 10-K that named the domain; NULL for
    # a manual candidate.
    first_cited_on: Mapped[date | None] = mapped_column(Date, nullable=True)
    last_cited_on: Mapped[date | None] = mapped_column(Date, nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="proposed", server_default=text("'proposed'"))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decided_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    engagement_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("engagements.id", ondelete="RESTRICT"), nullable=True
    )
    target_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="SET NULL"), nullable=True
    )
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
