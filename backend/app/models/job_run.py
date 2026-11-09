import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Index, Integer, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# Mirror the CHECK-backed vocabulary in migration 0100 by hand.
JOB_RUN_FINISH_REASONS: frozenset[str] = frozenset(
    {"done", "time_limit", "lookup_failures", "rate_limited", "not_configured", "error"}
)


class JobRun(Base):
    """One finished run of a recorded scheduler job (planning#329). Migration
    0100's docstring carries the invariants: `error` holds the exception type
    only and is set exactly when `finish_reason` is `error`; a skipped run
    writes no row, so gaps are computed at read time."""

    __tablename__ = "job_runs"
    __table_args__ = (
        Index("ix_job_runs_job_started", "job", text("started_at DESC")),
        Index("ix_job_runs_started", "started_at"),
        CheckConstraint("length(job) > 0", name="ck_job_runs_job_nonempty"),
        CheckConstraint("finished_at >= started_at", name="ck_job_runs_finished_after_started"),
        CheckConstraint(
            "finish_reason IN ('done', 'time_limit', 'lookup_failures', 'rate_limited', 'not_configured', 'error')",
            name="ck_job_runs_finish_reason",
        ),
        CheckConstraint("(finish_reason = 'error') = (error IS NOT NULL)", name="ck_job_runs_error_iff_reason"),
        CheckConstraint("items_selected >= 0", name="ck_job_runs_items_selected_nonneg"),
        CheckConstraint("jsonb_typeof(counts) = 'object'", name="ck_job_runs_counts_object"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    job: Mapped[str] = mapped_column(Text, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finish_reason: Mapped[str] = mapped_column(Text, nullable=False)
    items_selected: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=text("0"))
    counts: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb"))
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
