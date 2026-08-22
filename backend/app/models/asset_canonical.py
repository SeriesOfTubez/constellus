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

    `record_type`/`content` are the dedup/identity authority for dns_record
    rows, and since planning#144 L3c-4 they are its only source: the
    `metadata` JSONB column that used to carry copies of them (and of every
    other observed attribute) is DROPPED — migration 0043.

    Current-state attributes live in `asset_state` (projected) and
    `asset_claims` (per-observer grounding) instead. Nothing here mirrors
    them. The API still serves an `asset_metadata` key, but it is
    RECONSTRUCTED per request by `app.services.metadata_bridge` from those
    two tables plus the columns on this one — the frontend contract
    outlived the column, which is the whole point of the bridge.
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
    # dns_record identity — see class docstring. Nullable because every
    # other asset_type leaves these NULL (no per-column index of their
    # own; membership is via the partial unique index above).
    record_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    content: Mapped[str | None] = mapped_column(Text, nullable=True)
