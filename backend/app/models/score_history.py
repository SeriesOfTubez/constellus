import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class ScoreHistory(Base):
    """Append-only per-finding risk-score change log (planning#131, temporal
    layer slice 1).

    Written by exactly one service, `app.services.score_history.capture`,
    called from two places: `scan_executor.py` right after
    `risk_scorer.score_scan_findings` for the findings a scan just touched,
    and `nightly_rescore.py` for the full open-finding scope every night.
    Nothing else writes to this table.

    CHANGE-ONLY APPEND, not one row per (finding, night): a row is inserted
    only when `(risk_score, risk_band, building_velocity)` differs from the
    finding's own most recent prior row, or there is no prior row at all
    (the baseline). This is a deliberate deviation from planning#131's
    literal "one row per (finding, scored_at)" — see
    `app.services.score_history`'s module docstring for the full reasoning
    (it mirrors `ClaimHistory`'s change-log semantics). A future editor
    must not "simplify" this back into one-row-per-night without reading
    why it's built this way.

    Natively range-partitioned on `scored_at`, composite PK
    `(scored_at, id)` — same idiom as `ClaimHistory`. SQLAlchemy/Alembic
    cannot emit `PARTITION BY` declaratively via `op.create_table`, so the
    actual table + partition DDL is raw SQL in migration
    0046_temporal_layer.py; this class exists only so the ORM has a mapped
    target to query/insert against.

    No FKs, on purpose, and the reason is TREND AGGREGATES — not the two
    reasons this docstring used to give. History must outlive the entity it
    describes here because `score_history` feeds org-level trend queries
    (planning#121/#131): a finding can be deleted, and if its score rows went
    with it, last month's estate-wide number would silently change when you
    clean up today. That argument is real and specific to this table and
    `HygieneHistory`.

    The two corrected claims (planning#191):
      * it does NOT "mirror `ClaimHistory`" — that table now cascades on the
        asset, because per-asset provenance is meaningless once the asset is
        gone and nothing aggregates it. Same shape, opposite answer;
      * "an FK would make a future partition DROP/DETACH more expensive" is
        false on this stack, measured on PostgreSQL 18.6: an OUTGOING FK on a
        range-partitioned table is accepted, cascades across partitions, and
        blocks neither DETACH nor a subsequent DROP. The restriction being
        remembered applies to FKs *referencing* a partitioned table.

    So if these tables ever should cascade, it is a deliberate decision about
    rewriting trend history — not a technical constraint. `asset_canonical_id` is
    denormalised here rather than requiring a join through
    `findings_canonical` for the same reason — asset-grain trend queries
    must not depend on a `findings_canonical` row that may since have been
    deleted.

    `id` is server-generated (`uuidv7()`) — do NOT add a Python-side
    `default=uuid.uuid4`; keep Postgres as the sole generator, same
    convention as `ClaimHistory`/`AssetClaim`.
    """

    __tablename__ = "score_history"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    finding_canonical_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    asset_canonical_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    scored_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_band: Mapped[str] = mapped_column(Text, nullable=False)
    building_velocity: Mapped[bool] = mapped_column(Boolean, nullable=False)
    inputs: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default=text("'{}'"))
