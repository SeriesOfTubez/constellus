"""Page captures: record a missing proxy log (planning#325).

`proxy_log_missing` is set by ingest wherever it reads the proxy log: true when
the store held no log for the capture at that moment, false when it did. NULL
means the log was never looked for: rows from before this migration, and
failures that never reach the read (an invalid result, an ingest error, a
timed-out queued row). A log that is missing cannot also be truncated, so a
CHECK refuses both.

Data change: none; a new nullable column, existing rows stay NULL.
"""

import sqlalchemy as sa
from alembic import op

revision = "0098"
down_revision = "0097"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("page_captures", sa.Column("proxy_log_missing", sa.Boolean(), nullable=True))
    op.create_check_constraint(
        "ck_page_captures_proxy_log_missing_not_truncated", "page_captures",
        "NOT (proxy_log_missing AND proxy_log_truncated)",
    )


def downgrade() -> None:
    op.drop_constraint("ck_page_captures_proxy_log_missing_not_truncated", "page_captures", type_="check")
    op.drop_column("page_captures", "proxy_log_missing")
