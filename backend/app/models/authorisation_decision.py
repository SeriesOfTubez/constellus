import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class AuthorisationDecision(Base):
    """Decision log for probe authorisation (planning#142, L1).

    Written by the authorisation gate (#148, a cross-epic consumer) — L1
    only defines the table, no writer exists yet. `asset_canonical_id` and
    `observer_id` are nullable because a decision may be evaluated for an
    address before an AssetCanonical row exists for it (e.g. a candidate
    from Phase 1.5 port discovery that hasn't resolved to an asset yet).

    ## `asset_canonical_id` is `ON DELETE SET NULL` (planning#195)

    The row outlives the asset it was about, on purpose. This table is
    read to decide the planning#148 `enforce` flip (planning#189
    established it as the audit trail that decision is measured from), and
    a user deleting an asset through the admin UI must not silently shrink
    that evidence — the FK was `NO ACTION` until planning#195, which meant
    deleting any asset the gate had evaluated raised an unhandled
    `ForeignKeyViolation` (measured on dev: 4 of 4 assets undeletable).

    The flip itself is decided by a `GROUP BY` over `rule_fired` /
    `evidence_snapshot->>'gate_mode'`, neither of which needs
    `asset_canonical_id` — so an orphaned row still counts fully for the
    purpose this table exists for. And an orphaned row is not silently
    unreadable evidence: `evidence_snapshot` carries the asset's own
    identity (`asset_type`/`asset_value`), so a row that has lost its FK
    reference is still human-readable.

    ## That identity claim was only two-thirds true until planning#209

    The paragraph above named `probe_authorisation._compose` as the writer.
    It is now written by all three entry points, which it was not before:

      - `_compose` read it off `canonical` alone, so it was NULL on exactly
        the `unresolved_asset` denial — the one branch where
        `asset_canonical_id` is also NULL. Measured on dev before the fix:
        39 of 155 rows on one run, a third of all denials, unattributable
        in both directions at once. It now falls back to the in-batch
        asset, which always carries both.
      - The connector-declaration-failure path had the same guard inline,
        and denies an entire batch at once.
      - `authorise_ownership_probe` (planning#205) wrote no identity keys
        at all — it does not go through `_compose`, so the claim above was
        simply false for `decision_scope = "ownership_probe"`.

    ⚠ Rows written BEFORE planning#209 keep whatever they had. Any query
    treating `asset_value` as reliably present must be bounded by
    `decided_at`, or tolerate NULL — on dev that is 92 pre-planning#196
    rows carrying no `decision_scope` either, plus every historical
    `unresolved_asset` row.
    """

    __tablename__ = "authorisation_decisions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    asset_canonical_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets_canonical.id", ondelete="SET NULL"), nullable=True
    )
    observer_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("observers.id"), nullable=True)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)
    allowed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    probe_modes: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default=text("'[]'"))
    authorised_names: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default=text("'[]'"))
    rule_fired: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_snapshot: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default=text("'{}'"))
