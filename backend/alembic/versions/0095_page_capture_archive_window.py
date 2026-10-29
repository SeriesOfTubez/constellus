"""Page capture: record the freshness window an archive capture was judged by (planning#280 S5c-b2b).

`archive_freshness_days` is the `capture.archive_freshness_days` setting at the
time an archive capture was requested: the window the snapshot was chosen from,
and the one ingest judges the rendered snapshot time against. Recording it keeps
a stale capture's explanation true after an admin changes the setting. NULL for
a live capture.

Data change: none. Existing live rows stay NULL, which the CHECK requires. An
existing archive row would fail the CHECK; none existed outside throwaway test
databases when this was written (dev held 0 page_captures rows), and pre-MVP
such a row is re-captured rather than given an invented window.
"""

import sqlalchemy as sa
from alembic import op

revision = "0095"
down_revision = "0094"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("page_captures", sa.Column("archive_freshness_days", sa.SmallInteger(), nullable=True))
    op.create_check_constraint(
        "ck_page_captures_archive_window",
        "page_captures",
        "(source = 'live' AND archive_freshness_days IS NULL) "
        "OR (source = 'archive' AND archive_freshness_days IS NOT NULL AND archive_freshness_days BETWEEN 1 AND 90)",
    )


def downgrade() -> None:
    op.drop_constraint("ck_page_captures_archive_window", "page_captures", type_="check")
    op.drop_column("page_captures", "archive_freshness_days")
