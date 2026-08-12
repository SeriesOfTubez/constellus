import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, PrimaryKeyConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class TargetAssetLink(Base):
    """N-to-N link between targets and canonical assets. An asset is kept alive
    as long as at least one target references it (reference counting handled in
    app code on target deletion). last_observed_at is touched every time a scan
    against the linked target re-observes the asset."""

    __tablename__ = "target_asset_links"
    __table_args__ = (PrimaryKeyConstraint("target_id", "asset_canonical_id"),)

    target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    asset_canonical_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("assets_canonical.id", ondelete="CASCADE"), nullable=False, index=True)
    first_linked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
