"""Add the `guardrail_blocked` llm_calls status (planning#224 item 4)

The call path now SKIPS a bound model that is not on the OpenRouter key's
guardrail allow-list (cached from `/models/user`), writing a ledger row
with status `guardrail_blocked` instead of sending a request that would
404. That value has to pass `ck_llm_calls_status`, so this migration drops
and re-creates the CHECK with the extended list.

Constraint-only: no existing row changes. The new list is a superset of the
old, so the upgrade's re-validation of existing rows cannot fail; downgrade
re-validates against the old list, which only fails if a `guardrail_blocked`
row already exists (expected — you cannot downgrade past data that uses the
value).
"""

from alembic import op

revision = "0070"
down_revision = "0069"
branch_labels = None
depends_on = None

_OLD_STATUSES = (
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
_NEW_STATUSES = _OLD_STATUSES + ("guardrail_blocked",)


def _recreate(statuses: tuple[str, ...]) -> None:
    op.drop_constraint("ck_llm_calls_status", "llm_calls", type_="check")
    check = " OR ".join(f"status = '{v}'" for v in statuses)
    op.create_check_constraint("ck_llm_calls_status", "llm_calls", check)


def upgrade() -> None:
    _recreate(_NEW_STATUSES)


def downgrade() -> None:
    _recreate(_OLD_STATUSES)
