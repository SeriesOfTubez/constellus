import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# Same CHECK-backed vocabulary as `finding_ai_writeup.py` (migration 0081).
CLUSTER_WRITEUP_ACTIVE: tuple[str, ...] = ("queued", "running")


class ClusterAiWriteup(Base):
    """One AI write-up request for a cross-asset finding cluster and what
    became of it (planning#233 slice 2b). Migration 0081's docstring carries
    the invariants: one active row per cluster key, `member_ids` frozen at
    generation and checked by the per-viewer read gate.

    Nothing that scores a finding reads this table."""

    __tablename__ = "cluster_ai_writeups"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    finding_type: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    fingerprint: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="queued", server_default=text("'queued'"))
    member_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
    finding_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    asset_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_severity: Mapped[str | None] = mapped_column(Text, nullable=True)
    input_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    model: Mapped[str | None] = mapped_column(Text, nullable=True)
    ledger_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
    payload: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    statements_returned: Mapped[int | None] = mapped_column(Integer, nullable=True)
    statements_dropped: Mapped[int | None] = mapped_column(Integer, nullable=True)
    summary_dropped: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    priority_note_dropped: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    forced_strict: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=text("false"))
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
