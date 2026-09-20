import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# Claim type vocabulary — the L0 grounding ontology (planning#142). Mirrors
# the seeded claim_types reference table. Adding a new claim type means
# editing the CHECK constraint in a follow-up migration AND the claim_types
# seed data AND this frozenset (see EDGE_TYPES in asset_edge.py for the
# established pattern).
CLAIM_TYPES: frozenset[str] = frozenset({
    "port_observation",
    "proxy_state",
    "dns_ttl",
    "cloudflare_zone",
    "host_tarpit",
    "hosting_class",
    "reverse_ip",
    "spf_policy",
    "mx_preference",
    "ct_cert_issuance",
    "shodan_host",
    "reverse_hostname",
    "affinity_confirmation",
    "eol_status",
    "cloud_inventory",
    "observation",
    "cdn_boundary",
    "third_party_dependency",
    "tenancy",
})


class AssetClaim(Base):
    """Current-value claims layer (planning#142, L1 — green slice).

    One row per (asset, observer, claim_type): the current grounding claim
    an observer holds about an asset. Per Decision D1, probe-authorisation
    claims (affinity_confirmation, cloud_inventory) carry their authorised
    names directly in `claim_value` — `{"confirmed": bool,
    "authorised_names": [...], "evidence_ref": ...}` — rather than on a
    separate edge, so a future gate's read path stays a single lookup keyed
    by (asset, observer, claim_type).

    This table is NOT yet read by anything and nothing writes to it yet;
    `asset_metadata` on AssetCanonical stays authoritative until the L2
    projector and the authorisation gate land.
    """

    __tablename__ = "asset_claims"
    __table_args__ = (
        UniqueConstraint(
            "asset_canonical_id", "observer_id", "claim_type",
            name="uq_asset_claims_asset_observer_type",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    asset_canonical_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets_canonical.id", ondelete="CASCADE"), nullable=False
    )
    observer_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("observers.id"), nullable=False)
    claim_type: Mapped[str] = mapped_column(Text, ForeignKey("claim_types.claim_type"), nullable=False)
    claim_value: Mapped[dict] = mapped_column("claim_value", JSONB, nullable=False)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default=text("'{}'"))
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)


class ClaimHistory(Base):
    """Append-only history of claim changes (planning#142, L1).

    Natively range-partitioned on `changed_at`, composite PK
    (changed_at, id). SQLAlchemy/Alembic cannot emit `PARTITION BY`
    declaratively via op.create_table, so the actual table + partition DDL
    lives as raw SQL in migration 0039_claims_layer.py — this class exists
    only so the ORM has a mapped target to query/insert against. Seeded
    partitions are current-month, next-month, and a DEFAULT catch-all; the
    monthly rollover job is an L2 concern, not built here.

    `asset_canonical_id` carries `ON DELETE CASCADE` (planning#191): if the
    asset is deleted, its history goes with it. A history row is per-asset
    provenance — "observer X claimed value Y about asset Z at time T" — and
    it is meaningless once Z is gone; re-discovery mints a NEW canonical id,
    so old rows could never re-link to the returning asset even if kept. An
    asset going offline does NOT delete it (absence is modelled, planning#145),
    so this rule never costs a real asset its history.

    Do not copy this rule to `ScoreHistory`/`HygieneHistory`. They look
    identical and the answer is the opposite: they feed org-level trend
    aggregates, so cascading them would rewrite last month's numbers when you
    clean up an asset today. See their docstrings.

    This docstring used to say "No FKs — kept lean as an append-only log",
    and `ScoreHistory` retroactively attributed a stronger rationale to this
    class ("history must outlive the entity it describes") that was never
    stated here. It also said "nothing writes to this table yet", which has
    been stale since `claim_emitter` started appending on value change.
    """

    __tablename__ = "claim_history"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    asset_canonical_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets_canonical.id", ondelete="CASCADE"),
        nullable=False,
    )
    # observer_id / claim_type deliberately stay FK-free here: observers and
    # claim_types are seeded lookup rows that are never deleted, and
    # planning#191's decision was about the ASSET lifecycle only.
    observer_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    claim_type: Mapped[str] = mapped_column(Text, nullable=False)
    claim_value: Mapped[dict] = mapped_column(JSONB, nullable=False)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default=text("'{}'"))
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True, nullable=False)
