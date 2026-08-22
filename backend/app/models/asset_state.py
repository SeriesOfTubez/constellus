import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# Estate vocabulary — the ownership confidence tier a projected asset sits
# in. Adding a new value means editing the CHECK constraint in a follow-up
# migration AND this frozenset.
ESTATE_VALUES: frozenset[str] = frozenset({
    "proven_ours",
    "claimed_ours",
    "not_ours",
})


class AssetState(Base):
    """Projected current-state row per asset (planning#142, L1).

    One row per asset, meant to be written only by the L2 projector that
    folds `asset_claims` down into a promoted, gate-aware view. That
    projector does not exist yet — L1 only creates the structure so it has
    somewhere to land. `attributes` is a compat catch-all for anything not
    yet promoted to its own column (Decision 1 = Option A). Nothing reads or
    writes this table in this slice; `asset_metadata` on AssetCanonical
    stays authoritative.
    """

    __tablename__ = "asset_state"

    asset_canonical_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets_canonical.id", ondelete="CASCADE"), primary_key=True
    )
    open_ports: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default=text("'[]'"))
    estate: Mapped[str | None] = mapped_column(Text, nullable=True)
    hosting: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default=text("'{}'"))
    eol_summary: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default=text("'{}'"))
    attributes: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default=text("'{}'"))
    projected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
