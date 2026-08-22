import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class AuthorisationDecision(Base):
    """Decision log for probe authorisation (planning#142, L1).

    Written by the authorisation gate (#148, a cross-epic consumer) — L1
    only defines the table, no writer exists yet. `asset_canonical_id` and
    `observer_id` are nullable because a decision may be evaluated for an
    address before an AssetCanonical row exists for it (e.g. a candidate
    from Phase 1.5 port discovery that hasn't resolved to an asset yet).
    """

    __tablename__ = "authorisation_decisions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    asset_canonical_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets_canonical.id"), nullable=True
    )
    observer_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("observers.id"), nullable=True)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)
    allowed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    probe_modes: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default=text("'[]'"))
    authorised_names: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default=text("'[]'"))
    rule_fired: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_snapshot: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default=text("'{}'"))
