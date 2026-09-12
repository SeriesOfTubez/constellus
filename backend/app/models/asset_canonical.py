import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Text, and_, func, or_, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.ext.hybrid import hybrid_property
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
    # RAW STORED FLAG — do NOT filter the read path on this directly. An
    # ignore can carry an expiry (`ignore_expires_at`), so `ignored is True`
    # and "suppressed right now" are different questions. Use the
    # `suppressed` hybrid below; see migration 0047.
    ignored: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=text("false"))
    # planning#148-adjacent suppression discipline, borrowed from Wiz's
    # `DiscoveredResource` (Obsidian `Constellus — Wiz API Reference` §9.1):
    # an ignore carries a reason, the detail behind it, an author, and a
    # review date. NULL `ignore_expires_at` means indefinite — an explicit
    # choice the API forces the caller to make, not a silent default.
    ignore_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    ignore_reason_details: Mapped[str | None] = mapped_column(Text, nullable=True)
    ignore_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ignored_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ignored_by_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    tags: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default=text("'[]'"))
    # dns_record identity — see class docstring. Nullable because every
    # other asset_type leaves these NULL (no per-column index of their
    # own; membership is via the partial unique index above).
    record_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    content: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── effective suppression ───────────────────────────────────────────────

    @hybrid_property
    def suppressed(self) -> bool:
        """Is this asset suppressed **right now**?

        `ignored` is the stored intent; this is the effective state. They
        diverge the moment an ignore carries an expiry — which is the whole
        point of migration 0047. Every read site that used to filter
        `ignored == False` filters `~AssetCanonical.suppressed` instead, so
        an expired ignore stops suppressing *on read*, with no sweeper job
        to schedule, no row to rewrite, and therefore no window in which a
        lapsed suppression is still silently hiding an asset because the
        sweeper hasn't run yet.

        Deliberately evaluated against `now()` at query time rather than
        materialised into a column: a materialised flag is a cache, and a
        cache of "has this moment passed" is a bug waiting for the job that
        refreshes it to fail.
        """
        if not self.ignored:
            return False
        if self.ignore_expires_at is None:
            return True
        return self.ignore_expires_at > datetime.now(timezone.utc)

    @suppressed.expression
    def suppressed(cls):  # noqa: N805 - SQLAlchemy hybrid expression form
        return and_(
            cls.ignored.is_(True),
            or_(cls.ignore_expires_at.is_(None), cls.ignore_expires_at > func.now()),
        )
