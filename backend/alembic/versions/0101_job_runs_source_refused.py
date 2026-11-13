"""Add the `source_refused` finish reason to `job_runs` (planning#369).

`source_refused` means a data source answered a request with a refusal; the run
kept what it had finished, and the real status is in the logs. Constraint-only:
no table or column changes.
"""

from alembic import op

revision = "0101"
down_revision = "0100"
branch_labels = None
depends_on = None

_OLD_REASONS = ("done", "time_limit", "lookup_failures", "rate_limited", "not_configured", "error")
_NEW_REASONS = (
    "done", "time_limit", "lookup_failures", "rate_limited", "not_configured", "source_refused", "error",
)


def _check(reasons: tuple[str, ...]) -> str:
    return "finish_reason IN (" + ", ".join(f"'{r}'" for r in reasons) + ")"


def _recreate(reasons: tuple[str, ...]) -> None:
    op.drop_constraint("ck_job_runs_finish_reason", "job_runs", type_="check")
    op.create_check_constraint("ck_job_runs_finish_reason", "job_runs", _check(reasons))


def upgrade() -> None:
    _recreate(_NEW_REASONS)


def downgrade() -> None:
    # Run history is disposable; rows with the new reason cannot satisfy the old constraint.
    op.execute("DELETE FROM job_runs WHERE finish_reason = 'source_refused'")
    _recreate(_OLD_REASONS)
