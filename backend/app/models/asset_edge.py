import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


# Edge type vocabulary. Adding a new edge type means editing the CHECK
# constraint in a follow-up migration AND adding it here.
EDGE_TYPES: frozenset[str] = frozenset({
    "resolves_to",
    "runs_service",
    "has_finding",
    "registered_to",
    "discovered_in_target",
    "belongs_to_apex",
})

# Polymorphic endpoint types. App-level integrity is enforced by the
# asset_edges_validate_endpoints_trg trigger (migration 0016).
NODE_TYPES: frozenset[str] = frozenset({
    "target",
    "asset_canonical",
    "finding_canonical",
    "whois_org",
})


class AssetEdge(Base):
    """Typed directed edge between graph nodes. Polymorphic FK pattern —
    (source_type, source_id) and (target_type, target_id) reference rows in
    the table named by *_type. A Postgres trigger validates the referenced
    row exists (see migration 0016).

    weight is nullable and populated only on edges relevant to attack-path
    scoring (Phase 5). Descriptive edges (registered_to, tagged_as, etc.)
    leave it null. The edge_type itself is what distinguishes traversable
    from descriptive — there's no separate flag column.
    """

    __tablename__ = "asset_edges"
    __table_args__ = (
        UniqueConstraint(
            "source_type", "source_id", "target_type", "target_id", "edge_type",
            name="uq_asset_edges_unique",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_type: Mapped[str] = mapped_column(Text, nullable=False)
    source_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    target_type: Mapped[str] = mapped_column(Text, nullable=False)
    target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    edge_type: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    weight: Mapped[float | None] = mapped_column(Float, nullable=True)
    edge_metadata: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, default=dict, server_default=text("'{}'"))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
