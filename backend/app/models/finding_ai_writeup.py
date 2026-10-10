import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# Mirror the CHECK-backed vocabulary in migration 0071 by hand (the same
# pattern as `entity_ingest_run.py`).
WRITEUP_STATUSES: frozenset[str] = frozenset({"queued", "running", "succeeded", "failed"})
WRITEUP_ACTIVE: tuple[str, ...] = ("queued", "running")


class FindingAiWriteup(Base):
    """One AI write-up request for a finding and what became of it
    (planning#226). Migration 0071's docstring carries the invariants: one
    active row per finding, the newest succeeded row is the one shown, and
    why AI output lives here rather than on `findings_canonical`.

    Nothing that scores a finding (risk, SSVC, hygiene, attribution) reads
    this table; `test_finding_writeup.py` asserts it."""

    __tablename__ = "finding_ai_writeups"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("findings_canonical.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(Text, nullable=False, default="queued", server_default=text("'queued'"))
    input_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    model: Mapped[str | None] = mapped_column(Text, nullable=True)
    ledger_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
    payload: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    statements_returned: Mapped[int | None] = mapped_column(Integer, nullable=True)
    statements_dropped: Mapped[int | None] = mapped_column(Integer, nullable=True)
    priority_note_dropped: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    forced_strict: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=text("false"))
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
