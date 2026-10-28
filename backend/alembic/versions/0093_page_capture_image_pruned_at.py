"""Page capture: record when a stored image file was pruned (planning#280 S5b-2b slice b).

Pruning keeps the latest N image FILES per domain and removes the rest. It
removes files, never rows. A pruned row has `image_path IS NULL` and
`image_pruned_at` set. `image_omitted_reason` keeps meaning "never stored", so a
pruned row has it NULL. `image_bytes`, `image_sha256` and `image_quality` are
KEPT as the record of what was stored.

No data change: no existing row has the new column set.
"""

import sqlalchemy as sa
from alembic import op

revision = "0093"
down_revision = "0092"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("page_captures", sa.Column("image_pruned_at", sa.DateTime(timezone=True), nullable=True))
    op.create_check_constraint(
        "ck_page_captures_pruned_has_no_image",
        "page_captures",
        "image_pruned_at IS NULL OR (image_path IS NULL AND image_omitted_reason IS NULL)",
    )


def downgrade() -> None:
    op.drop_constraint("ck_page_captures_pruned_has_no_image", "page_captures", type_="check")
    op.drop_column("page_captures", "image_pruned_at")
