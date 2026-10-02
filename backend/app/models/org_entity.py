import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Text, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# Mirrors migration 0068's `ck_org_entities_relationship` by hand (the
# codebase's pattern for CHECK-backed vocabularies).
RELATIONSHIP_OURS = "ours"
RELATIONSHIP_MA_TARGET = "ma_target"
RELATIONSHIPS: frozenset[str] = frozenset({RELATIONSHIP_OURS, RELATIONSHIP_MA_TARGET})


class OrgEntity(Base):
    """A corporate entity node in the entity graph (planning#212, L3).

    `legal_name` carries no uniqueness constraint — the same name never
    implies the same entity, and entities are never auto-merged by name.
    `cik` (SEC filer identifier, zero-padded 10 digits) is the only
    automatic identity key; `lei` (ISO 17442 Legal Entity Identifier) is a
    second optional one. Both are nullable and independently UNIQUE
    (NULLs are distinct under Postgres's default unique-constraint
    semantics, so any number of entities may have no CIK/LEI at once).

    Deliberately NO `aliases` column (a documented deviation from the
    planning#212 issue body — see migration 0061's docstring). A
    `dba`/`formerly_named` name is itself an `OrgEntity` row, joined to this
    one by a SOURCED `EntityRelation` — an unsourced alias array would be
    exactly the undifferentiated blob this schema exists to replace.
    """

    __tablename__ = "org_entities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    legal_name: Mapped[str] = mapped_column(Text, nullable=False)
    cik: Mapped[str | None] = mapped_column(Text, nullable=True)
    lei: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    # planning#240 (migration 0068): what this company is TO US. NULL = unset
    # (browse only, accept blocked, AI reads strict). Written only through
    # `app.services.entity_relationship`, which also keeps the cross-table
    # invariants with `engagements.subject_entity_id`.
    relationship: Mapped[str | None] = mapped_column(Text, nullable=True)
    ours_authorised_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    ours_authorised_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ours_reference: Mapped[str | None] = mapped_column(Text, nullable=True)
