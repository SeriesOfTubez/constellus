import uuid
from datetime import datetime
from enum import Enum

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanKind(str, Enum):
    MONITORING = "monitoring"
    INITIAL_DISCOVERY = "initial_discovery"
    RECHECK = "recheck"
    MANUAL = "manual"


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default=ScanStatus.PENDING)
    kind: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=ScanKind.MANUAL,
        server_default=text("'manual'"),
        index=True,
    )
    scope: Mapped[dict] = mapped_column(JSONB, nullable=False)
    options: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    connectors_used: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    template_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_templates.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Per-chunk failures during a batched run. The run still reports COMPLETED
    # if all chunks ran; FAILED is reserved for hard aborts (DB down, etc.).
    partial_failures: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default=text("'[]'"))
    # Aggregate counts populated by the executor at run completion. Used by
    # the Activity feed; populated here rather than derived from observation
    # tables because the legacy `assets` / `findings` hypertables were
    # dropped once readers moved to canonical.
    asset_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=text("0"))
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=text("0"))
    # Resolved aggressiveness tier at run start. Denormalised from app_settings
    # (or the run's per-run override) so audit logs answer "why did this scan
    # generate so many requests" without time-travelling app_settings history.
    aggressiveness: Mapped[str] = mapped_column(
        String(20), nullable=False, default="polite", server_default=text("'polite'")
    )
