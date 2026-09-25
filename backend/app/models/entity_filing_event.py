import uuid
from datetime import date, datetime

from sqlalchemy import Date, DateTime, ForeignKey, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class EntityFilingEvent(Base):
    """One row per SEC filing event worth attention (planning#213, L4 slice
    1) — an 8-K (or 8-K/A) whose item list intersects `edgar_ingest.
    LINEAGE_ITEMS` (2.01 "Completion of Acquisition or Disposition of
    Assets", 5.01 "Change in Control of Registrant").

    This is deliberately an EVENT, never an `EntityRelation` row: the
    submissions JSON carries no counterparty, and item 2.01 covers BOTH
    directions (acquisition OR disposition), so there is no object entity
    and no direction to assert. `items` is the SEC's own comma-separated
    string, stored byte-identical — never normalised, re-ordered, or
    interpreted further by this schema. A person, or a later slice (#214's
    Wayback corroboration / #215's AI research loop), supplies the
    counterparty if one is ever attached.
    """

    __tablename__ = "entity_filing_events"
    __table_args__ = (
        UniqueConstraint("entity_id", "accession_number", name="uq_entity_filing_events_entity_accession"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    entity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("org_entities.id", ondelete="RESTRICT"), nullable=False
    )
    observer_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("observers.id"), nullable=False)
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("evidence_fetches.id", ondelete="RESTRICT"), nullable=False
    )
    form: Mapped[str] = mapped_column(Text, nullable=False)
    accession_number: Mapped[str] = mapped_column(Text, nullable=False)
    filing_date: Mapped[date] = mapped_column(Date, nullable=False)
    items: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
