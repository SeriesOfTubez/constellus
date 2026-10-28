"""Page capture: record whether a capture was live or from the web archive (planning#280 S5c-b2a).

Under a restricting posture a capture is taken from a Wayback snapshot instead
of a live visit. `source` says which: 'live' or 'archive'. For an archive
capture `archive_snapshot_at` is the snapshot's own capture time and
`archive_host` the archive host it was read from; both are NULL for a live one.

Data change: every existing row becomes 'live' (the server default fills the
new NOT NULL column), which is true: no archive capture existed before this.
"""

import sqlalchemy as sa
from alembic import op

revision = "0094"
down_revision = "0093"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("page_captures", sa.Column("source", sa.Text(), nullable=False, server_default=sa.text("'live'")))
    op.add_column("page_captures", sa.Column("archive_snapshot_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("page_captures", sa.Column("archive_host", sa.Text(), nullable=True))
    op.create_check_constraint("ck_page_captures_source", "page_captures", "source IN ('live','archive')")
    op.create_check_constraint(
        "ck_page_captures_archive_fields",
        "page_captures",
        "(source = 'live' AND archive_snapshot_at IS NULL AND archive_host IS NULL) "
        "OR (source = 'archive' AND archive_snapshot_at IS NOT NULL AND archive_host IS NOT NULL)",
    )


def downgrade() -> None:
    op.drop_constraint("ck_page_captures_archive_fields", "page_captures", type_="check")
    op.drop_constraint("ck_page_captures_source", "page_captures", type_="check")
    op.drop_column("page_captures", "archive_host")
    op.drop_column("page_captures", "archive_snapshot_at")
    op.drop_column("page_captures", "source")
