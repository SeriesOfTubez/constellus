import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# Mirror the CHECK-backed vocabularies in migration 0073 by hand.
REPORT_KINDS: tuple[str, ...] = ("exec_summary",)
REPORT_STATUSES: frozenset[str] = frozenset({"queued", "running", "done", "failed"})
REPORT_ACTIVE: tuple[str, ...] = ("queued", "running")


class Report(Base):
    """One generated report for an engagement (planning#230). `facts` are
    deterministic numbers from the query language, pinned to `as_of`;
    `payload` is the AI narration over them, kept only where each statement
    cites facts it can be checked against. Migration 0073 carries the invariants."""

    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="queued", server_default=text("'queued'"))
    prompt_version: Mapped[str | None] = mapped_column(String(20), nullable=True)
    as_of: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    facts: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    payload: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    statements_returned: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=text("0"))
    statements_dropped: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=text("0"))
    drop_reasons: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb"))
    model: Mapped[str | None] = mapped_column(String, nullable=True)
    ledger_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
    forced_strict: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=text("false"))
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
