import uuid
from datetime import date, datetime

from sqlalchemy import Date, DateTime, ForeignKey, Integer, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class EntitySubsidiaryListing(Base):
    """One row per KEPT row of one 10-K's EX-21 subsidiary-listing exhibit
    (planning#213, L4 slice 2) — stored VERBATIM as data, never a diff.

    This is a snapshot, not a relation: `subsidiary_entity_id` records
    which `OrgEntity` this row's (name, jurisdiction) maps to (set at
    ingest by the scoped-exact-reuse rule in `app.services.edgar_ingest`'s
    module docstring), but the row itself exists independent of whether a
    `subsidiary_of` `EntityRelation` was ever proposed for it. A heading
    row or a row equal to the filer's own current name is NOT stored here
    at all (`app.services.edgar_ingest._is_heading_row`); `row_index` is
    therefore 0-based among STORED rows only, not raw document position.

    The year-over-year "what changed" a person wants is a QUERY over these
    rows grouped by `filer_entity_id` and ordered by `filing_date` — never
    a stored computation (planning#213's 2026-09-25 decisions comment,
    decision 1).
    """

    __tablename__ = "entity_subsidiary_listings"
    __table_args__ = (
        UniqueConstraint(
            "filer_entity_id", "accession_number", "exhibit_type", "row_index",
            name="uq_entity_subsidiary_listings_filer_accession_exhibit_row",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    filer_entity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("org_entities.id", ondelete="RESTRICT"), nullable=False
    )
    observer_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("observers.id"), nullable=False)
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("evidence_fetches.id", ondelete="RESTRICT"), nullable=False
    )
    accession_number: Mapped[str] = mapped_column(Text, nullable=False)
    # Verbatim index `Type` cell, e.g. "EX-21.1".
    exhibit_type: Mapped[str] = mapped_column(Text, nullable=False)
    filing_date: Mapped[date] = mapped_column(Date, nullable=False)
    report_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    row_index: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    jurisdiction: Mapped[str | None] = mapped_column(Text, nullable=True)
    cells: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
    subsidiary_entity_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("org_entities.id", ondelete="RESTRICT"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
