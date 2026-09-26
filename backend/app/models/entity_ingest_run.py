import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# Mirror the CHECK-backed vocabulary in migration 0065 by hand (the same
# pattern as `candidate_domain.py`).
INGEST_RUN_STATUSES: frozenset[str] = frozenset({"queued", "running", "succeeded", "failed"})
INGEST_RUN_ACTIVE: tuple[str, ...] = ("queued", "running")


class EntityIngestRun(Base):
    """One `POST /api/entities/edgar-ingest` request and what became of it
    (planning#219). Migration 0065's docstring carries the invariants: one
    active run per CIK, status ⇔ timestamps, and why there is no
    `entity_id` column (resolved from `cik` at read time)."""

    __tablename__ = "entity_ingest_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    cik: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="queued", server_default=text("'queued'"))
    result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
