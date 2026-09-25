import uuid
from datetime import datetime
from enum import Enum

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class EngagementPosture(str, Enum):
    """The four posture values (planning#211/#132 §5.2). `RESTRICTING_
    POSTURES` — the subset that restricts traffic to passive-only — lives
    in `app.services.posture`, not here: posture POLICY belongs in the
    service module both gate call sites already import, not on the model.

    ⚠ `(str, Enum)` hazard (bit #203): `str(EngagementPosture.PRE_CLOSE)` is
    `"EngagementPosture.PRE_CLOSE"`, not `"pre_close"`. Always compare with
    `==` against `.value`, and store/serialize `.value` — never format a
    member with `str()` or an f-string.
    """

    PRE_CLOSE = "pre_close"
    DAY_0 = "day_0"
    INTEGRATED = "integrated"
    ABANDONED = "abandoned"


class Engagement(Base):
    __tablename__ = "engagements"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    posture: Mapped[str] = mapped_column(String(20), nullable=False, default=EngagementPosture.PRE_CLOSE.value)
    # FK added by migration 0061 (planning#212, L3) — RESTRICT, not SET
    # NULL: deleting an entity out from under an engagement that attributes
    # its subject must not silently strip that attribution (same rationale
    # as `targets.engagement_id`'s own ON DELETE RESTRICT, migration 0059).
    subject_entity_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("org_entities.id", ondelete="RESTRICT"), nullable=True
    )
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    # Authorisation record — a claim about the CURRENT posture, not a log of
    # past widenings (the audit trail carries history; this row only ever
    # describes "as of right now"). Set iff posture is `day_0`/`integrated`
    # (migration 0059's `ck_engagements_authorisation_matches_posture`);
    # demotion to `pre_close` clears all three immediately.
    authorised_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    authorised_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    authorisation_reference: Mapped[str | None] = mapped_column(Text, nullable=True)
    posture_changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
