import uuid
from datetime import datetime
from enum import Enum

from sqlalchemy import Boolean, Date, DateTime, Float, ForeignKey, PrimaryKeyConstraint, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingSource(str, Enum):
    NUCLEI = "nuclei"
    CLOUDFLARE = "cloudflare"
    FORTIMANAGER = "fortimanager"
    TENABLE = "tenable"
    MANUAL = "manual"


class FindingState(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    SUPPRESSED = "suppressed"
    RESOLVED = "resolved"


class Finding(Base):
    """
    Risk findings from all sources, captured per scan run.
    TimescaleDB hypertable partitioned on discovered_at — enables
    trending, regression detection, and time-based reporting.
    """

    __tablename__ = "findings"
    __table_args__ = (PrimaryKeyConstraint("id", "discovered_at"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), default=uuid.uuid4)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)
    scan_run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scan_runs.id"), nullable=False, index=True)
    asset_value: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    finding_type: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    source: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    severity: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    detail: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    state: Mapped[str] = mapped_column(Text, nullable=False, default=FindingState.OPEN, index=True)
    acknowledged_by_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    suppressed_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Category and enrichment — populated at ingest / post-scan enrichment pipeline
    category: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    cve_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    kev: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    kev_date_added: Mapped[datetime | None] = mapped_column(Date, nullable=True)
    cwe: Mapped[str | None] = mapped_column(Text, nullable=True)
