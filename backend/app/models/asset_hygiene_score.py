import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# Sub-score grade vocabulary (planning#130, L1) — what each of the five
# hygiene dimensions grades to, worst -> best. `unknown` sorts BELOW `bad`;
# see `app.services.hygiene_scorer`'s module docstring for why that
# inversion is the entire point of this feature, not a bug to "fix" here.
#
# This is NOT backed by a DB CHECK constraint the way ESTATE_VALUES /
# CLAIM_TYPES are — `dimensions` below is JSONB, and constraining grade
# strings inside it would need a `jsonb_path_exists` CHECK heavier than any
# other JSONB column in this codebase carries (see the 0045 migration
# docstring). The one place this vocabulary is actually enforced is
# `hygiene_scorer.GRADE_SCORES`, whose keys must equal this set — editing
# one without the other is an application bug the tests would catch, not a
# state the DB can reject on its own.
GRADE_VALUES: frozenset[str] = frozenset({"unknown", "bad", "fair", "good", "excellent"})

# Composite band vocabulary. Unlike GRADE_VALUES above, this DOES map to a
# real DB CHECK constraint (`ck_asset_hygiene_score_band`, migration 0045)
# because `band` is a real column real queries predicate on
# (`app/api/hygiene.py`'s `band` filter). Adding a value means editing that
# CHECK in a follow-up migration AND this frozenset — the established
# ESTATE_VALUES / CLAIM_TYPES discipline.
BAND_VALUES: frozenset[str] = frozenset({"critical", "poor", "fair", "good", "excellent"})


class AssetHygieneScore(Base):
    """Pre-computed per-asset hygiene score (planning#130, L1).

    One row per scored asset, written only by `app.services.hygiene_scorer`
    (nightly, via the scheduler) and read by `app/api/hygiene.py`. Never
    written from a request path — this is deliberately not a read-time
    computation; see the 0045 migration docstring for the query-performance
    and LLM-over-database-question-answering reasons.

    `dimensions` carries all five sub-scores (`coverage`, `health`,
    `currency`, `exposure`, `ownership`), each
    `{"grade", "score", "reason_codes", "detail"}` — see
    `hygiene_scorer.score_asset` for the shape. `score`/`band` are the
    composite (mean of all five sub-scores, including any `unknown` ones —
    the denominator is always 5, never fewer; that is the settled rule
    `hygiene_scorer`'s docstring explains at length) and its banded label,
    both promoted to real columns because `app/api/hygiene.py` sorts and
    filters on them directly.

    A row here implies the asset was, at last compute, in scope for
    scoring: `ignored == False` and
    `app.services.claims_query.surface(asset) != "not_ours"`. `run()`
    deletes the row for an asset that drops out of scope rather than
    leaving a stale score behind — see `hygiene_scorer.run`'s docstring.
    """

    __tablename__ = "asset_hygiene_score"

    asset_canonical_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets_canonical.id", ondelete="CASCADE"), primary_key=True
    )
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    band: Mapped[str] = mapped_column(Text, nullable=False)
    dimensions: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default=text("'{}'"))
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
