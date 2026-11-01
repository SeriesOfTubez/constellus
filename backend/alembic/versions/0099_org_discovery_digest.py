"""Organization discovery digests (planning#319)

A notification rule can now be about new organization discovery candidates
instead of findings. Jason, 2026-10-31 (#319 6551740956).

- `notification_rules.kind`: `finding | org_discovery`, default `finding`, so
  every existing rule keeps its meaning. An `org_discovery` rule is digest
  only and has no categories (a CHECK); its severity threshold is unused.
- `digests.kind`: the kind of rule the digest was built for. Kept on the row
  because a deleted rule leaves `rule_id` NULL, and reading an org digest back
  must still re-apply the engagement filter to its stored body.
- `digest_candidates`: the candidates a rule's digest listed. The unique key
  `(rule_id, candidate_id)` claims each candidate for a rule exactly once:
  `created_at` is the inserting transaction's start, so a pure time window
  would lose or repeat a candidate whose transaction committed late. A
  deleted rule leaves `rule_id` NULL (several NULLs never collide).

New column defaults and a new table only: no existing row changes.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0099"
down_revision = "0098"
branch_labels = None
depends_on = None

_KINDS = "kind = 'finding' OR kind = 'org_discovery'"


def upgrade() -> None:
    op.add_column(
        "notification_rules",
        sa.Column("kind", sa.Text(), nullable=False, server_default=sa.text("'finding'")),
    )
    op.create_check_constraint("ck_notification_rules_kind", "notification_rules", _KINDS)
    op.create_check_constraint(
        "ck_notification_rules_org_discovery_shape", "notification_rules",
        "kind = 'finding' OR (mode = 'digest' AND categories = '[]'::jsonb)",
    )

    op.add_column("digests", sa.Column("kind", sa.Text(), nullable=False, server_default=sa.text("'finding'")))
    op.create_check_constraint("ck_digests_kind", "digests", _KINDS)

    op.create_table(
        "digest_candidates",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column(
            "digest_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("digests.id", ondelete="CASCADE"), nullable=False,
        ),
        # SET NULL, like digests.rule_id: a deleted rule's digests keep their
        # rows, so their stored bodies can still be filtered when read back.
        sa.Column(
            "rule_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("notification_rules.id", ondelete="SET NULL"), nullable=True,
        ),
        sa.Column(
            "candidate_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scope_candidates.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.UniqueConstraint("rule_id", "candidate_id", name="uq_digest_candidates_rule_candidate"),
    )
    op.create_index("ix_digest_candidates_digest_id", "digest_candidates", ["digest_id"])


def downgrade() -> None:
    op.drop_index("ix_digest_candidates_digest_id", table_name="digest_candidates")
    op.drop_table("digest_candidates")
    op.drop_constraint("ck_digests_kind", "digests", type_="check")
    op.drop_column("digests", "kind")
    op.drop_constraint("ck_notification_rules_org_discovery_shape", "notification_rules", type_="check")
    op.drop_constraint("ck_notification_rules_kind", "notification_rules", type_="check")
    op.drop_column("notification_rules", "kind")
