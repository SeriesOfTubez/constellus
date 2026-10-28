"""Page capture: record the per-capture job parameters on the row
(planning#280 S5b-2b slice a).

The capture limits became admin settings, so a setting can change between the
request and the ingest. Each row now records what its job asked for:

- `user_agent_mode`: `stock` or `identifying` (job contract v2). The UA string
  actually sent is still `user_agent`, from the worker's result.
- `image_max_bytes`: the image cap sent in the job. The ingest enforces THIS
  cap, not the current setting, so lowering the setting does not reject an
  in-flight capture and raising it does not admit a larger file than was asked.

Existing rows were all written by the v1 contract, which always used the stock
UA and a 2 MiB cap, so the backfill is exact, not a guess.
"""

import sqlalchemy as sa
from alembic import op

revision = "0092"
down_revision = "0091"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "page_captures",
        sa.Column("user_agent_mode", sa.Text(), nullable=False, server_default=sa.text("'stock'")),
    )
    op.add_column(
        "page_captures",
        sa.Column("image_max_bytes", sa.Integer(), nullable=False, server_default=sa.text("2097152")),
    )
    # The defaults only backfilled v1 rows; new rows must say what they asked for.
    op.alter_column("page_captures", "user_agent_mode", server_default=None)
    op.alter_column("page_captures", "image_max_bytes", server_default=None)
    op.create_check_constraint(
        "ck_page_captures_user_agent_mode", "page_captures", "user_agent_mode IN ('stock', 'identifying')"
    )
    op.create_check_constraint("ck_page_captures_image_max_bytes", "page_captures", "image_max_bytes > 0")


def downgrade() -> None:
    op.drop_constraint("ck_page_captures_image_max_bytes", "page_captures", type_="check")
    op.drop_constraint("ck_page_captures_user_agent_mode", "page_captures", type_="check")
    op.drop_column("page_captures", "image_max_bytes")
    op.drop_column("page_captures", "user_agent_mode")
