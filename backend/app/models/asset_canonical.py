import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class AssetCanonical(Base):
    """Durable identity for an asset.

    Uniqueness is enforced by partial unique indexes:
      - dns_record rows: (asset_type, value, record_type, content) so each
        distinct DNS record gets its own canonical identity — originally
        migration 0026 keyed this off `metadata->>'record_type'`/
        `metadata->>'content'`; migration 0040 (planning#144 L3b-1)
        promoted `record_type`/`content` to real columns (below) and
        repointed the index at them, so identity/dedup no longer depends
        on the JSONB blob.
      - All other asset types: (asset_type, value).

    `record_type`/`content` are the dedup/identity AUTHORITY for
    dns_record rows. `asset_metadata` still carries copies of both (kept
    in sync by asset_writer) — that's what the API serializes for the
    frontend; dropping them from metadata is a later slice (L3c).
    """

    __tablename__ = "assets_canonical"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_type: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    parent_value: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)
    ignored: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=text("false"))
    tags: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default=text("'[]'"))
    asset_metadata: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, default=dict, server_default=text("'{}'"))
    # dns_record identity — see class docstring. Nullable because every
    # other asset_type leaves these NULL (no per-column index of their
    # own; membership is via the partial unique index above).
    record_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    content: Mapped[str | None] = mapped_column(Text, nullable=True)
