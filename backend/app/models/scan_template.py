import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class ScanTemplate(Base):
    """Durable scan configuration. A template is what the user creates and edits;
    each execution against a template produces a ScanRun observation row.

    Two scope models supported:
      static  — `dynamic_scope=False` (default). The executor reads `scope` as-is.
                Used by the legacy one-shot scan path.
      dynamic — `dynamic_scope=True`. The executor resolves scope at run start
                from the `targets` table, optionally filtered by `target_tag_filter`.
                This is how the global continuous-monitoring templates work.

    Batching applies in both modes — the resolved (or static) target list is
    chunked into groups of `batch_size` and processed sequentially within a
    single ScanRun.
    """

    __tablename__ = "scan_templates"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    scope: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default=text("'{}'"))
    options: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default=text("'{}'"))
    schedule_cron: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default=text("true"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    tags: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default=text("'[]'"))
    dynamic_scope: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=text("false"))
    target_tag_filter: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default=text("'[]'"))
    batch_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    batch_delay_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=text("0"))
    # Tag-based cadence priority. NULL = this template isn't a cadence tier
    # (the default monitoring template + any ad-hoc/manual templates fall
    # here). Non-NULL = cadence tier, applies to targets carrying the tag
    # in target_tag_filter. Lower priority wins when a target matches
    # multiple tiers.
    tag_priority: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
