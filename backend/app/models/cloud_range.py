"""Local mirror of constellus-binaries' `cloud-ranges` dataset (planning#179).

`CloudRange` rows are the mirrored prefixes themselves; `CloudRangeMeta` is a
single-row freshness/provenance marker for the whole mirror (dataset digest,
when it was generated upstream, when this mirror last refreshed). Both are
written only by `app.services.cloud_ranges.refresh` and read only by
`app.services.cloud_ranges.lookup` / `dataset_state` — see migration
0050_cloud_ranges_and_tenancy.py for the schema rationale (why Postgres
over memory, why no unique constraint on prefix/service_raw).
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, SmallInteger, Text, text
from sqlalchemy.dialects.postgresql import CIDR, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class CloudRange(Base):
    __tablename__ = "cloud_ranges"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    prefix: Mapped[str] = mapped_column(CIDR, nullable=False)
    ip_version: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    provider: Mapped[str] = mapped_column(Text, nullable=False)
    service_raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    service_class: Mapped[str] = mapped_column(Text, nullable=False)
    region: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(Text, nullable=False)


class CloudRangeMeta(Base):
    """Single-row table: `CHECK (id)` + boolean PK means only `id = true` is
    insertable, so there is exactly one row by construction."""

    __tablename__ = "cloud_ranges_meta"

    id: Mapped[bool] = mapped_column(Boolean, primary_key=True, default=True)
    dataset_sha256: Mapped[str] = mapped_column(Text, nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    record_count: Mapped[int] = mapped_column(Integer, nullable=False)
    refreshed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    manifest: Mapped[dict] = mapped_column(JSONB, nullable=False)
