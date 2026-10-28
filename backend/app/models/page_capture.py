import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, SmallInteger, Text, UniqueConstraint, func, text,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# Mirrors migration 0091's `ck_page_captures_status` by hand.
CAPTURE_STATUSES: frozenset[str] = frozenset({"queued", "done", "failed"})
# Mirrors migration 0092's `ck_page_captures_user_agent_mode` by hand.
USER_AGENT_MODES: frozenset[str] = frozenset({"stock", "identifying"})


class PageCapture(Base):
    """One page load of a scope candidate's domain by the capture browser
    (planning#280 S5b-2a). `id` is the `capture_id` the spool, the worker and
    the proxy log are keyed by (`docs/architecture/capture-spool.md`).

    Migration 0091's docstring carries the invariants: `finished_at` follows
    `status`, `failure_reason` is set exactly when `failed`, and the row outlives
    its image file.
    """

    __tablename__ = "page_captures"
    __table_args__ = (
        Index(
            "uq_page_captures_one_queued_per_candidate", "candidate_id",
            unique=True, postgresql_where=text("status = 'queued'"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    candidate_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scope_candidates.id", ondelete="RESTRICT"), nullable=False
    )
    domain: Mapped[str] = mapped_column(Text, nullable=False)
    observer_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("observers.id"), nullable=False)
    requested_url: Mapped[str] = mapped_column(Text, nullable=False)
    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    status: Mapped[str] = mapped_column(Text, nullable=False, default="queued", server_default=text("'queued'"))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    final_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    redirect_chain: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    cert: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    cert_sha256: Mapped[str | None] = mapped_column(Text, nullable=True)
    cert_san_dns: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)
    pinned_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    proxy_log_truncated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    image_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    image_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    image_sha256: Mapped[str | None] = mapped_column(Text, nullable=True)
    image_quality: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    image_omitted_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    # What the job asked for (migration 0092): the ingest enforces this cap, not
    # the current setting.
    user_agent_mode: Mapped[str] = mapped_column(Text, nullable=False)
    image_max_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    # Migration 0093: set when the image FILE was pruned; the row stays (see its docstring).
    image_pruned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PageCaptureRequest(Base):
    """One request the enforcing proxy saw for a capture, from the proxy's own
    log (never from the browser's report)."""

    __tablename__ = "page_capture_requests"
    __table_args__ = (UniqueConstraint("capture_id", "seq", name="uq_page_capture_requests_capture_seq"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    capture_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("page_captures.id", ondelete="RESTRICT"), nullable=False
    )
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    ts: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    method: Mapped[str | None] = mapped_column(Text, nullable=True)
    scheme: Mapped[str | None] = mapped_column(Text, nullable=True)
    host: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    resolved: Mapped[list[str] | None] = mapped_column(ARRAY(INET), nullable=True)
    pinned_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    decision: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    bytes_up: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    bytes_down: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
