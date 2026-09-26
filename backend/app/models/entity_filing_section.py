import uuid
from datetime import date, datetime

from sqlalchemy import CheckConstraint, Date, DateTime, ForeignKey, Integer, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

SECTION_VALUES: frozenset[str] = frozenset({"business_combinations"})


class EntityFilingSection(Base):
    """One row per located 10-K footnote section (planning#213, L4 slice 2)
    — currently only `business_combinations`, located by preferring a
    `Note N`/`N.`-prefixed heading match, LAST among those; only when NO
    match is so prefixed does it fall back to the LAST bare match
    (planning#220, defect 3, 2026-09-26 — refined from the original "always
    take the LAST heading match" rule, which a live run showed can pick a
    bare table-cell column header — e.g. a goodwill roll-forward table's
    own "Acquisitions" column — over the actual note heading).

    **No relation is ever written from this table.** Naming the deal is
    planning#215's job, over this row's `text` and `heading_match_count`.

    ## Known limitations (carried from the extraction method itself)

    The LAST-numbered (or LAST-bare, when nothing is numbered) rule can
    still land on a LATER, unrelated mention — e.g. a numbered
    subsequent-events note ALSO titled "Acquisitions" still wins over the
    real Business Combinations note by virtue of being LAST among numbered
    matches. Separately, the section-end heuristic's numbered-heading shape
    can match an ordinary enumerated body line (e.g. `2. The Company
    acquired...`), ending a numbered section early. This schema stores
    `heading_match_count` specifically so a reader can see the first
    ambiguity rather than trusting a single extracted section as fact. This
    is extraction for a later reader, not a verified claim.
    """

    __tablename__ = "entity_filing_sections"
    __table_args__ = (
        UniqueConstraint("entity_id", "accession_number", "section", name="uq_entity_filing_sections_entity_accession_section"),
        CheckConstraint("end_line > start_line", name="ck_entity_filing_sections_end_after_start"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    entity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("org_entities.id", ondelete="RESTRICT"), nullable=False
    )
    observer_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("observers.id"), nullable=False)
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("evidence_fetches.id", ondelete="RESTRICT"), nullable=False
    )
    accession_number: Mapped[str] = mapped_column(Text, nullable=False)
    form: Mapped[str] = mapped_column(Text, nullable=False)
    filing_date: Mapped[date] = mapped_column(Date, nullable=False)
    report_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    section: Mapped[str] = mapped_column(Text, nullable=False)
    extraction: Mapped[str] = mapped_column(Text, nullable=False)
    heading: Mapped[str] = mapped_column(Text, nullable=False)
    heading_match_count: Mapped[int] = mapped_column(Integer, nullable=False)
    start_line: Mapped[int] = mapped_column(Integer, nullable=False)
    end_line: Mapped[int] = mapped_column(Integer, nullable=False)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
