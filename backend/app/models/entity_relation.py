import uuid
from datetime import date, datetime

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# Vocabularies — mirror the CHECK-backed tuples in migration 0061 by hand,
# the same established pattern as every other CHECK-backed vocabulary in
# this codebase (e.g. `observer.py`'s OBSERVER_TRUST vs. migration 0039).
RELATION_TYPES: frozenset[str] = frozenset({"acquired", "subsidiary_of", "dba", "formerly_named"})
EVENT_DATE_PRECISIONS: frozenset[str] = frozenset({"day", "month", "year", "unknown"})
DECISION_KINDS: frozenset[str] = frozenset({"person", "source"})
RELATION_STATUSES: frozenset[str] = frozenset({"proposed", "confirmed", "rejected"})
GROUNDING_VALUES: frozenset[str] = frozenset({"verified", "not_applicable"})


class EntityRelation(Base):
    """One row per SOURCE ASSERTION about a relationship between two
    `OrgEntity` rows (planning#212, L3) — never a merged "asset_edges" row.
    Two independent sources reporting the same acquisition are two rows;
    `app.services.entity_graph.project_edges` groups them into one edge with
    multiple sources for display.

    ## Direction convention (planning#213 — #212 never defined one)

    "subject `formerly_named` object" reads "subject was formerly named
    object" — the SUBJECT is the entity under its CURRENT name, the OBJECT
    is the `OrgEntity` row standing in for the retired name.

    ## The decision gate — `ck_entity_relations_decision` (migration 0061)

    Rejection always needs `decision_kind = 'person'`. Auto-confirmation
    needs `decision_kind = 'source'` AND `observer_confirms`.
    `observer_confirms` is a DENORMALISED copy of `observers.
    confirms_relations`, pinned to its source by the composite FK
    `fk_entity_relations_observer_confirms` — `(observer_id,
    observer_confirms)` references `observers(id, confirms_relations)`
    `ON UPDATE CASCADE`, so this column can never disagree with the observer
    it was copied from, and revoking a grant while auto-confirmed rows exist
    is refused by the CHECK (not silently accepted).

    `decided_by_id` is `ON DELETE SET NULL` and deliberately OUTSIDE the
    CHECK, for the same reason `engagements.authorised_by_id` is (migration
    0059's docstring, finding 3 of 0061's): a deleted user must not be able
    to flip a live CHECK and break every future UPDATE of the row.

    ## The trigger — `trg_entity_relations_no_demotion`

    "Never lowers" needs OLD, which a CHECK cannot see, hence a BEFORE
    UPDATE trigger (precedent: `asset_edges_validate_endpoints`, migration
    0016) that raises on any `status` transition FROM a decided state BACK
    to `proposed`. Ingest must use `ON CONFLICT DO NOTHING`, never `DO
    UPDATE SET status = ...`.
    """

    __tablename__ = "entity_relations"
    __table_args__ = (
        UniqueConstraint(
            "subject_id", "object_id", "relation", "observer_id", "evidence_id",
            name="uq_entity_relations_subject_object_relation_observer_evidence",
        ),
        ForeignKeyConstraint(
            ["observer_id", "observer_confirms"],
            ["observers.id", "observers.confirms_relations"],
            onupdate="CASCADE",
            name="fk_entity_relations_observer_confirms",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    subject_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("org_entities.id", ondelete="RESTRICT"), nullable=False
    )
    object_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("org_entities.id", ondelete="RESTRICT"), nullable=False
    )
    relation: Mapped[str] = mapped_column(Text, nullable=False)
    # No default — fact time (when the acquisition happened), never
    # observation time (when we learned about it).
    event_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    event_date_precision: Mapped[str] = mapped_column(Text, nullable=False)
    # Not a ForeignKey("observers.id") alone — the COMPOSITE FK in
    # __table_args__ covers both this and observer_confirms together, and a
    # second, narrower single-column FK on the same column is redundant.
    observer_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    observer_confirms: Mapped[bool] = mapped_column(Boolean, nullable=False)
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("evidence_fetches.id", ondelete="RESTRICT"), nullable=False
    )
    quote: Mapped[str] = mapped_column(Text, nullable=False)
    # Grounding label from `llm_connector.structured()` — 'verified' |
    # 'not_applicable' | NULL. Never read by any confirm path: it is a
    # human-facing signal in the review queue, not a trust input.
    grounding: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="proposed", server_default=text("'proposed'"))
    decision_kind: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decided_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
