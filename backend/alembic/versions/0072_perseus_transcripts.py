"""Perseus transcripts + the `chat` llm_calls role (planning#228)

Two new tables hold Perseus chat history, per user:

- `perseus_conversations`: one row per conversation, owned by one user
  (ON DELETE CASCADE from `users`). `updated_at` drives retention:
  `app_settings['perseus.transcript_retention_days']` (default 30) and the
  daily purge job delete conversations idle for longer than that.
- `perseus_messages`: the questions and answers, in order (`seq`, unique per
  conversation). `meta` on an assistant message holds the tool trace (the
  query objects run and their counts) and the ledger ids behind the answer.

Transcripts are content (questions reveal interest, answers contain data), so
unlike the `llm_calls` ledger (R4: never content) they are short-lived,
per-user and user-deletable, and nothing copies them into the ledger.

`ck_llm_calls_role` is re-created with `chat` added so Perseus's calls can be
recorded. The new list is a superset of the old, so the upgrade cannot fail;
downgrade fails only if a `chat` row exists, the same as 0070.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0072"
down_revision = "0071"
branch_labels = None
depends_on = None

_OLD_ROLES = ("research", "extract", "classify", "judge", "narrate")
_NEW_ROLES = _OLD_ROLES + ("chat",)
_MESSAGE_ROLES = ("user", "assistant")


def _recreate_role_check(roles: tuple[str, ...]) -> None:
    op.drop_constraint("ck_llm_calls_role", "llm_calls", type_="check")
    op.create_check_constraint("ck_llm_calls_role", "llm_calls", " OR ".join(f"role = '{v}'" for v in roles))


def upgrade() -> None:
    _recreate_role_check(_NEW_ROLES)

    op.create_table(
        "perseus_conversations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column(
            "user_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_perseus_conversations_user_updated", "perseus_conversations", ["user_id", "updated_at"])
    op.create_index("ix_perseus_conversations_updated_at", "perseus_conversations", ["updated_at"])

    op.create_table(
        "perseus_messages",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column(
            "conversation_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("perseus_conversations.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("meta", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(" OR ".join(f"role = '{v}'" for v in _MESSAGE_ROLES), name="ck_perseus_messages_role"),
        sa.UniqueConstraint("conversation_id", "seq", name="uq_perseus_messages_seq"),
    )


def downgrade() -> None:
    op.drop_table("perseus_messages")
    op.drop_index("ix_perseus_conversations_updated_at", table_name="perseus_conversations")
    op.drop_index("ix_perseus_conversations_user_updated", table_name="perseus_conversations")
    op.drop_table("perseus_conversations")
    _recreate_role_check(_OLD_ROLES)
