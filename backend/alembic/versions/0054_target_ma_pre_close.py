"""Add `targets.ma_pre_close` (planning#193, route (c)).

Adds a single boolean column that marks a target as **pre-close M&A**: an
operator has told this system it holds no authorisation to probe the target
yet, and this system must do nothing an in-progress counterparty could
notice. Enforced in two places — the composed probe gate's `_posture_cap`
and the discovery phase's dnsrecon/bruteforce enablement in
`scan_executor.py` — see planning#193's routing decision for why it is two
enforcement points rather than one.

Deliberately NOT named `is_ma`, though that is what the issue and the
hand-off both call it. `is_ma` reads as a claim about what the target *is*
(an M&A entity), which is an entity-graph statement deferred to
planning#192. What is actually stored here is narrower: a posture that
applies only pre-close — "treat this target as passive-only because we have
not closed on it yet." Naming it `ma_pre_close` also leaves `posture` free
for planning#132's eventual enum without a collision or a rename.

Not nullable, unlike `targets.aggressiveness`. `aggressiveness` is
tri-state because NULL means "inherit from template/global"; there is no
inherit tier for this flag — a target is pre-close or it is not — and a
nullable boolean would create a third state with no meaning that every
reader would have to coerce.

No data migration: every existing target correctly defaults to `false`
(nothing already in the database was pre-close M&A under this feature,
because the feature did not exist before it).

Revision ID: 0054
Revises: 0053
Create Date: 2026-09-20
"""

from alembic import op
import sqlalchemy as sa

revision = "0054"
down_revision = "0053"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "targets",
        sa.Column("ma_pre_close", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )


def downgrade() -> None:
    op.drop_column("targets", "ma_pre_close")
