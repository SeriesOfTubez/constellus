import uuid
from datetime import datetime
from enum import Enum

from sqlalchemy import Boolean, DateTime, ForeignKey, PrimaryKeyConstraint, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class AssetType(str, Enum):
    DNS_RECORD = "dns_record"
    IP_ADDRESS = "ip_address"
    OPEN_PORT = "open_port"
    SERVICE = "service"
    CLOUD_RESOURCE = "cloud_resource"
    INTERNAL_HOST = "internal_host"


class Asset(Base):
    """
    Discovered assets captured per scan run.
    TimescaleDB hypertable partitioned on discovered_at — enables
    change tracking over time (new exposures, remediated ports, etc).

    parent_value links child assets to parents:
      dns_record  → (none)
      ip_address  → dns_record value
      open_port   → ip_address value
      service     → open_port value  (e.g. "1.2.3.4:443")
      cloud_resource → ip_address value
      internal_host  → ip_address value (via FortiManager VIP mapping)
    """

    __tablename__ = "assets"
    __table_args__ = (PrimaryKeyConstraint("id", "discovered_at"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), default=uuid.uuid4)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)
    scan_run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scan_runs.id"), nullable=False, index=True)
    asset_type: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    parent_value: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    asset_metadata: Mapped[dict | None] = mapped_column("metadata", JSONB, nullable=True)
    ignored: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
