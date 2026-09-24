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
    # planning#204 — assets this run evaluated whose probe_class denied `ip`
    # addressing (port scanning), unioned across every authorise_probes()
    # call by the executor (see GateResult.port_scan_unauthorised_ids).
    # probe_class-derived ONLY: scope and posture denials are NOT counted
    # here, a deliberate limitation following the issue's rejection of a
    # decision-log read surface for this count. 0 on a run stamped before
    # this migration means "not recorded", not "nothing was denied" — safe
    # only because the UI never renders a zero count (Activity.tsx).
    port_scan_unauthorised_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    # planning#211 — `[{"target_id", "engagement_id", "posture"}]`, stamped
    # once by `scan_executor._stamp_scope_target_engagements` right after
    # scope is finalised and before any phase runs. Named for honesty, not
    # convenience: this is the engagements of the `Target` rows literally
    # NAMED in `scope["domains"] + scope["ip_ranges"]` — it is NOT the
    # posture of every asset this run touches. A recheck of a child IP of a
    # pre-close target has no Target value in scope (the IP is the asset
    # being rechecked, not a target), so it stamps `[]` here while the gate
    # still denies through `target_asset_links` — per-asset truth lives in
    # `authorisation_decisions`, not this column. `[]` on a run stamped
    # before this migration, or a run whose scope named no engaged target,
    # both read as "nothing recorded" — the same ambiguity `asset_count`/
    # `port_scan_unauthorised_count` already accept for the same reason.
    scope_target_engagements: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'")
    )
    # Resolved aggressiveness tier at run start. Denormalised from app_settings
    # (or the run's per-run override) so audit logs answer "why did this scan
    # generate so many requests" without time-travelling app_settings history.
    aggressiveness: Mapped[str] = mapped_column(
        String(20), nullable=False, default="polite", server_default=text("'polite'")
    )
