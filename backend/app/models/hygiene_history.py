import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class HygieneHistory(Base):
    """Append-only per-asset hygiene-score change log (planning#131,
    temporal layer slice 1).

    Written by exactly one service — a private helper inside
    `app.services.hygiene_scorer.run`, called right after that run's
    per-chunk upsert into `asset_hygiene_score`. Nothing else writes to
    this table, and it carries NO notifications in this slice (only
    `score_history`/finding promotions notify — see
    `app.services.score_history`'s module docstring).

    CHANGE-ONLY APPEND, same rule and reasoning as `ScoreHistory`: a row is
    inserted only when `(score, band, dimensions)` differs from the asset's
    own most recent prior row, or there is no prior row (the baseline).
    `dimensions` is part of that key deliberately — two dimensions moving in
    compensating directions leave the composite `score`/`band` identical, so
    keying on those alone would drop the row and lose the change; see
    `hygiene_scorer._append_hygiene_history`'s docstring. ASSET GRAIN
    ONLY — no roll-up grain here. The epic mentions "asset and roll-up
    grain", but roll-up is blocked on planning#120 (no org/business-unit
    graph exists yet), the same reason planning#130 L1 excluded roll-up
    from `asset_hygiene_score` itself. Do not add a roll-up dimension here
    without that graph existing first.

    Natively range-partitioned on `computed_at`, composite PK
    `(computed_at, id)` — same idiom as `ScoreHistory`/`ClaimHistory`. The
    actual table + partition DDL is raw SQL in migration
    0046_temporal_layer.py; this class exists only so the ORM has a mapped
    target to query/insert against.

    No FKs, on purpose — mirrors `ScoreHistory`/`ClaimHistory`: history
    must outlive the entity it describes.

    `id` is server-generated (`uuidv7()`) — do NOT add a Python-side
    `default=uuid.uuid4`; keep Postgres as the sole generator.
    """

    __tablename__ = "hygiene_history"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    asset_canonical_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True, nullable=False)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    band: Mapped[str] = mapped_column(Text, nullable=False)
    dimensions: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default=text("'{}'"))
