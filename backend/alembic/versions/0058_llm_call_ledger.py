"""LLM inference ledger (planning#140 slice 1).

One row per HTTP attempt to OpenRouter — never per logical call. See
`app/models/llm_call.py`'s module docstring for what this table
deliberately never stores (R4: no prompt/response content, ever, ever —
`error_detail` is the upstream error MESSAGE only) and
`app/services/llm_connector.py`'s module docstring for the escalation
ladder that determines how many rows one `complete()`/`structured()` call
writes.

CHECK constraints are built with the same `" OR ".join(...)` idiom as
`0050_cloud_ranges_and_tenancy.py`'s `service_class` check — a literal
TUPLE here, not an import from `app.models.llm_call`, because a migration
is frozen history and must not depend on importable app code that can
change under it. `app.models.llm_call.ROLES`/`DATA_POLICIES`/`STATUSES`
mirror these three tuples for the ORM/app side; keep them in sync by hand,
the same established pattern as every other CHECK-backed vocabulary in
this codebase (e.g. `claim.py`'s `CLAIM_TYPES` vs. this same migration's
own sibling, `0050`'s `_PRIOR_CLAIM_TYPES`).

No seed data, no companion observer/claim-type row — this is a plain
telemetry table, not part of the claims layer.

Revision ID: 0058
Revises: 0057
Create Date: 2026-09-23
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0058"
down_revision = "0057"
branch_labels = None
depends_on = None


_ROLES = ("research", "extract", "classify", "judge", "narrate")
_DATA_POLICIES = ("strict", "dev_permissive")
_STATUSES = (
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


def upgrade() -> None:
    role_check = " OR ".join(f"role = '{v}'" for v in _ROLES)
    data_policy_check = " OR ".join(f"data_policy = '{v}'" for v in _DATA_POLICIES)
    status_check = " OR ".join(f"status = '{v}'" for v in _STATUSES)

    op.create_table(
        "llm_calls",
        sa.Column("id", sa.BigInteger(), autoincrement=True, primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("task", sa.String(100), nullable=False),
        sa.Column("target_id", UUID(as_uuid=True), sa.ForeignKey("targets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("passive_only", sa.Boolean(), nullable=False),
        sa.Column("data_policy", sa.String(20), nullable=False),
        sa.Column("requested_model", sa.String(200), nullable=False),
        sa.Column("served_model", sa.String(200), nullable=True),
        sa.Column("provider", sa.String(100), nullable=True),
        sa.Column("generation_id", sa.String(100), nullable=True),
        sa.Column("tier", sa.SmallInteger(), nullable=False),
        sa.Column("attempt", sa.SmallInteger(), nullable=False),
        sa.Column("status", sa.String(40), nullable=False),
        sa.Column("prompt_tokens", sa.Integer(), nullable=True),
        sa.Column("completion_tokens", sa.Integer(), nullable=True),
        sa.Column("cached_tokens", sa.Integer(), nullable=True),
        sa.Column("cost_usd", sa.Numeric(12, 6), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("error_detail", sa.Text(), nullable=True),
        sa.Column("ungrounded_fields", JSONB(), nullable=True),
        sa.CheckConstraint(role_check, name="ck_llm_calls_role"),
        sa.CheckConstraint(data_policy_check, name="ck_llm_calls_data_policy"),
        sa.CheckConstraint(status_check, name="ck_llm_calls_status"),
        sa.CheckConstraint("tier BETWEEN 1 AND 3", name="ck_llm_calls_tier"),
    )
    op.create_index("ix_llm_calls_created_at", "llm_calls", ["created_at"])
    op.create_index("ix_llm_calls_target_id", "llm_calls", ["target_id"])


def downgrade() -> None:
    op.drop_index("ix_llm_calls_target_id", table_name="llm_calls")
    op.drop_index("ix_llm_calls_created_at", table_name="llm_calls")
    op.drop_table("llm_calls")
