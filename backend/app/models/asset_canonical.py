import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class AssetCanonical(Base):
    """Durable identity for an asset.

    Uniqueness is enforced by partial unique indexes (migration 0026):
      - dns_record rows: (asset_type, value, record_type, content) so each
        distinct DNS record gets its own canonical identity.
      - All other asset types: (asset_type, value).
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
