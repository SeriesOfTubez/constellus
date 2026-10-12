import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# Mirror the CHECK-backed vocabulary in migrations 0075/0076 by hand (the
# same pattern as `finding_ai_writeup.py`).
KINDS: frozenset[str] = frozenset({
    "login_portal", "admin_panel", "default_install", "parked", "marketing_site", "api", "application", "unknown",
})
ENVIRONMENTS: frozenset[str] = frozenset({"production", "non_production", "unknown"})
STATUSES: frozenset[str] = frozenset({"queued", "running", "succeeded", "failed"})
ACTIVE: tuple[str, ...] = ("queued", "running")


class WebClassification(Base):
    """One AI web-app classification request for an endpoint (asset, port)
    and what became of it (planning#231): the immutable AI log. The newest
    succeeded row is the endpoint's AI value, applied unless a person's
    `WebEndpointOverride` corrects it (migration 0076). A succeeded row is
    frozen by a trigger.

    Nothing that scores, attributes or hosts an asset reads this table, and
    nothing here writes tags; `test_web_classifier.py` asserts it.

    `example_override_ids` (migration 0078, slice 3) holds the ids of the
    corrections sent to the model as examples with this request."""

    __tablename__ = "web_classifications"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    asset_canonical_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets_canonical.id", ondelete="CASCADE"), nullable=False
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="queued", server_default=text("'queued'"))
    kind: Mapped[str | None] = mapped_column(Text, nullable=True)
    environment: Mapped[str | None] = mapped_column(Text, nullable=True)
    product: Mapped[str | None] = mapped_column(Text, nullable=True)
    product_source_field: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
    citations_returned: Mapped[int | None] = mapped_column(Integer, nullable=True)
    citations_dropped: Mapped[int | None] = mapped_column(Integer, nullable=True)
    product_dropped: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    downgraded: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    input_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    model: Mapped[str | None] = mapped_column(Text, nullable=True)
    ledger_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
    forced_strict: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=text("false"))
    example_override_ids: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


REASON_CAP = 500  # mirrors ck_web_endpoint_overrides_reason_len


class WebEndpointOverride(Base):
    """A person's correction of one endpoint's web classification
    (planning#231, migration 0076). At most one per (asset, port); it wins
    over the AI value and AI code never writes it. `input_snapshot` is the
    bounded input the AI saw when the correction was made, and `input_hash`
    lets the UI flag a correction whose endpoint changed since."""

    __tablename__ = "web_endpoint_overrides"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    asset_canonical_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets_canonical.id", ondelete="CASCADE"), nullable=False
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    environment: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    input_snapshot: Mapped[dict] = mapped_column(JSONB, nullable=False)
    input_hash: Mapped[str] = mapped_column(Text, nullable=False)
    ai_classification_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("web_classifications.id", ondelete="SET NULL"), nullable=True
    )
    set_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    set_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
