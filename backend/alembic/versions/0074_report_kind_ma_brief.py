"""Widen `reports.kind` to admit `ma_brief` (planning#230 slice 2)

The M&A due-diligence brief is a second report kind over the same table: same
columns, same one-active-per-(engagement, kind) index. Only the CHECK changes.

Downgrade deletes the `ma_brief` rows first (pre-MVP data is disposable), then
narrows the CHECK back, so the narrower constraint can be created.
"""

import sqlalchemy as sa
from alembic import op

revision = "0074"
down_revision = "0073"
branch_labels = None
depends_on = None

_OLD = ("exec_summary",)
_NEW = ("exec_summary", "ma_brief")


def _check(kinds: tuple[str, ...]) -> str:
    return " OR ".join(f"kind = '{v}'" for v in kinds)


def upgrade() -> None:
    op.drop_constraint("ck_reports_kind", "reports", type_="check")
    op.create_check_constraint("ck_reports_kind", "reports", _check(_NEW))


def downgrade() -> None:
    op.execute(sa.text("DELETE FROM reports WHERE kind = 'ma_brief'"))
    op.drop_constraint("ck_reports_kind", "reports", type_="check")
    op.create_check_constraint("ck_reports_kind", "reports", _check(_OLD))
