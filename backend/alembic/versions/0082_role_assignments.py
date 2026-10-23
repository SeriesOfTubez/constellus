"""Add `role_assignments` and give every user a global one (planning#261 slice 1)

A role held at a scope: global (`engagement_id` NULL) or one engagement.
"Membership" of an engagement is an assignment on it; there is no members
table (Jason, 2026-10-22, planning#261 comment 6350747062).

The principal is a user or an API key, exactly one of the two
(`ck_role_assignments_one_principal`). No API-key table exists yet, so
`api_key_id` carries no foreign key; planning#243 slice 2 adds only that
constraint, not a reshaping.

Backfill: every existing user gets a global assignment of their current
`users.role`, so `has_permission` (which now reads assignments) grants
exactly what it granted before. From here on the ORM's `before_flush` hook
(models/role_assignment.py) keeps the global assignment equal to
`users.role`.

Downgrade drops the table; `users.role` was never touched, so nothing is lost
that the previous revision needs.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0082"
down_revision = "0081"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "role_assignments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column("user_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=True),
        sa.Column("api_key_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("role", sa.String(50), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("num_nonnulls(user_id, api_key_id) = 1", name="ck_role_assignments_one_principal"),
    )
    op.create_index("ix_role_assignments_user_id", "role_assignments", ["user_id"])
    op.create_index("ix_role_assignments_api_key_id", "role_assignments", ["api_key_id"])
    op.create_index("ix_role_assignments_engagement_id", "role_assignments", ["engagement_id"])
    op.create_index("uq_role_assignments_user_global", "role_assignments", ["user_id"], unique=True,
                    postgresql_where=sa.text("user_id IS NOT NULL AND engagement_id IS NULL"))
    op.create_index("uq_role_assignments_user_engagement", "role_assignments", ["user_id", "engagement_id"],
                    unique=True, postgresql_where=sa.text("user_id IS NOT NULL AND engagement_id IS NOT NULL"))
    op.create_index("uq_role_assignments_api_key_global", "role_assignments", ["api_key_id"], unique=True,
                    postgresql_where=sa.text("api_key_id IS NOT NULL AND engagement_id IS NULL"))
    op.create_index("uq_role_assignments_api_key_engagement", "role_assignments", ["api_key_id", "engagement_id"],
                    unique=True, postgresql_where=sa.text("api_key_id IS NOT NULL AND engagement_id IS NOT NULL"))

    op.execute(
        "INSERT INTO role_assignments (user_id, role, engagement_id) "
        "SELECT id, role, NULL FROM users"
    )


def downgrade() -> None:
    op.drop_table("role_assignments")
