"""app.models.llm_call — the LLM inference ledger (planning#140 slice 1).

One row per HTTP attempt to OpenRouter — never per logical `complete()`/
`structured()` call. A call that escalates across three bound models and
retries once on a 429 along the way writes several rows; see
`app.services.llm_connector`'s module docstring for the full escalation
ladder that determines how many.

R4 (the reviewer will check this): this table NEVER stores prompt or
response content — not the messages, not the output, not a hash of either.
`error_detail` is the upstream error MESSAGE only (never the request that
produced it), truncated to 2000 chars by the writer in
`app.services.llm_connector._write_ledger`. It is high-volume telemetry
with long retention (`app_settings` key `llm_ledger_retention_days`,
default 400 days — see `app.services.llm_connector.prune_ledger`), not an
audit trail of what was asked: a pre-close M&A query leaking through this
table would defeat the entire point of R1/R3's data-policy enforcement,
which exists precisely so a counterparty never learns we were asking.

`ROLES`/`DATA_POLICIES`/`STATUSES` below are plain tuples, deliberately
NOT imported by the migration that creates this table's CHECK constraints
(`0058_llm_call_ledger.py`) — a migration is frozen history and must not
depend on importable app code that can change under it. The migration
carries its own literal copies; keep the two in sync by hand, same
established pattern as every other CHECK-backed vocabulary in this
codebase (e.g. `app/models/claim.py`'s `CLAIM_TYPES` vs.
`0050_cloud_ranges_and_tenancy.py`'s `_PRIOR_CLAIM_TYPES`).
"""

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    SmallInteger,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# Mirrors the CHECK constraint text in 0058_llm_call_ledger.py.
ROLES: tuple[str, ...] = ("research", "extract", "classify", "judge", "narrate")

# Mirrors the CHECK constraint text in 0058_llm_call_ledger.py.
DATA_POLICIES: tuple[str, ...] = ("strict", "dev_permissive")

# Mirrors the CHECK constraint text in 0058_llm_call_ledger.py. `ok` is a
# genuine end-to-end success; `invalid_output`/`ungrounded` are structured-
# output failures on an otherwise-successful HTTP response (R2: the
# structurer is a transformer, never a source — an ungrounded result is a
# failed attempt, never partially accepted); the rest are HTTP/transport
# outcomes, including the two refusals that never sent a request at all
# (`budget_refused`, `not_configured`).
STATUSES: tuple[str, ...] = (
    "ok",
    "invalid_output",
    "ungrounded",
    "no_eligible_endpoint",
    "rate_limited",
    "budget_refused",
    "upstream_error",
    "transport_error",
    "not_configured",
)


class LlmCall(Base):
    __tablename__ = "llm_calls"

    id: Mapped[int] = mapped_column(BigInteger, autoincrement=True, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    # Caller-supplied label of the triggering task — free text, never the
    # prompt itself (R4). Used to scope test cleanup (a uuid suffix in the
    # task label) and to group spend in `spend_summary`'s `by_task`.
    task: Mapped[str] = mapped_column(String(100), nullable=False)
    target_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # SNAPSHOT at call time — the target's posture can change after the
    # fact, and this column must keep recording what was true when the
    # call was actually made, not what is true now.
    passive_only: Mapped[bool] = mapped_column(Boolean, nullable=False)
    # The EFFECTIVE policy (app.services.llm_connector.effective_data_policy),
    # not the raw settings.llm_data_policy env value — the two can diverge
    # for a pre-close target under dev_permissive (R1/R3).
    data_policy: Mapped[str] = mapped_column(String(20), nullable=False)
    requested_model: Mapped[str] = mapped_column(String(200), nullable=False)
    served_model: Mapped[str | None] = mapped_column(String(200), nullable=True)
    provider: Mapped[str | None] = mapped_column(String(100), nullable=True)
    generation_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    # 1..3 — see app.services.llm_connector's module docstring for exactly
    # what each tier means for complete() vs. structured().
    tier: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    # 1-based, within this call's WHOLE ladder (every model, every tier,
    # every inline retry shares one counter) — not reset per model or tier.
    attempt: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False)
    prompt_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    completion_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cached_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # RAW, as OpenRouter's `usage.cost` reports it — not grossed up by the
    # card-credit-purchase fee. `llm_connector.spend_summary`/the budget
    # check gross this up themselves; the stored value stays the vendor's
    # own number so it can be reconciled against an OpenRouter statement.
    cost_usd: Mapped[Decimal | None] = mapped_column(Numeric(12, 6), nullable=True)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Upstream error MESSAGE only, truncated to 2000 chars — never the
    # request body that produced it (R4).
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Dotted field paths (app.services.llm_grounding.check_grounding's
    # return value) that failed grounding — only set when status ==
    # "ungrounded". Field PATHS only, never the field VALUES or quotes.
    ungrounded_fields: Mapped[list | None] = mapped_column(JSONB, nullable=True)
