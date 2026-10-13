"""Per-rule alert digests (planning#233 slice 2a)

A notification rule can now deliver as it always has, as a daily digest, or
both (`notification_rules.mode`, default `immediate`, so every existing rule
behaves exactly as before). Jason, 2026-10-12 (#233 6137620127, 6138164774,
6138214483).

- `notification_rules.mode`: `immediate | digest | both`. Events are recorded
  in every mode. A `digest` rule's immediate send is skipped and recorded as
  the new delivery outcome `deferred_to_digest`, which carries no connector
  (both 0079 CHECKs are replaced to admit it).
- `digests`: one row per rule per digest run, including an empty period
  (`outcome = 'empty'`, nothing sent). It keeps the deterministic body that
  was built from the events, the AI narrative and how it was grounded, and
  the delivery outcome. A rule's newest row is its watermark.
- `alert_dispatches.digest_id`: the digest that claimed the dispatch. Each
  dispatch is claimed by exactly one digest, so a dispatch whose transaction
  committed after a digest's cut-off still lands in the next one (a pure time
  window would lose it).

New column defaults and new tables only: no existing row changes. Downgrade
deletes `deferred_to_digest` deliveries, which the restored CHECK would
otherwise reject.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0080"
down_revision = "0079"
branch_labels = None
depends_on = None

_MODES = ("immediate", "digest", "both")
_OLD_OUTCOMES = ("sent", "failed", "raised", "no_channel", "no_recipients")
_NEW_OUTCOMES = _OLD_OUTCOMES + ("deferred_to_digest",)
_DIGEST_OUTCOMES = (
    "pending", "empty", "sent", "partial", "failed", "no_channel", "no_recipients", "abandoned",
)
_NARRATIVE_STATUSES = ("succeeded", "failed", "skipped")


def _in(column: str, values: tuple[str, ...]) -> str:
    return " OR ".join(f"{column} = '{v}'" for v in values)


def upgrade() -> None:
    op.add_column(
        "notification_rules",
        sa.Column("mode", sa.Text(), nullable=False, server_default=sa.text("'immediate'")),
    )
    op.create_check_constraint("ck_notification_rules_mode", "notification_rules", _in("mode", _MODES))

    op.drop_constraint("ck_alert_deliveries_outcome", "alert_deliveries", type_="check")
    op.create_check_constraint("ck_alert_deliveries_outcome", "alert_deliveries", _in("outcome", _NEW_OUTCOMES))
    op.drop_constraint("ck_alert_deliveries_connector", "alert_deliveries", type_="check")
    op.create_check_constraint(
        "ck_alert_deliveries_connector", "alert_deliveries",
        "(outcome IN ('no_channel', 'no_recipients', 'deferred_to_digest')) = (connector_id IS NULL)",
    )

    op.create_table(
        "digests",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column(
            "rule_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("notification_rules.id", ondelete="SET NULL"), nullable=True,
        ),
        sa.Column("rule_name", sa.Text(), nullable=False),
        # The floor the claim used (exclusive, before the grace window) and
        # the cut-off (inclusive). The next digest's floor is this cut-off.
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("finding_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("body", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("narrative", postgresql.JSONB(), nullable=True),
        sa.Column("narrative_status", sa.Text(), nullable=True),
        sa.Column("narrative_reason", sa.Text(), nullable=True),
        sa.Column("model", sa.Text(), nullable=True),
        sa.Column("forced_strict", sa.Boolean(), nullable=True),
        sa.Column("ledger_ids", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("outcome", sa.Text(), nullable=False, server_default=sa.text("'pending'")),
        sa.Column("deliveries", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(_in("outcome", _DIGEST_OUTCOMES), name="ck_digests_outcome"),
        sa.CheckConstraint(
            "narrative_status IS NULL OR " + _in("narrative_status", _NARRATIVE_STATUSES),
            name="ck_digests_narrative_status",
        ),
        sa.CheckConstraint("period_end > period_start", name="ck_digests_period"),
    )
    op.create_index("ix_digests_rule_end", "digests", ["rule_id", "period_end"])
    op.create_index("ix_digests_created", "digests", ["created_at"])

    op.add_column(
        "alert_dispatches",
        sa.Column(
            "digest_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("digests.id", ondelete="SET NULL"), nullable=True,
        ),
    )
    op.create_index(
        "ix_alert_dispatches_unclaimed", "alert_dispatches", ["rule_id", "created_at"],
        postgresql_where=sa.text("digest_id IS NULL"),
    )
    op.create_index("ix_alert_dispatches_digest", "alert_dispatches", ["digest_id"])


def downgrade() -> None:
    op.drop_index("ix_alert_dispatches_digest", table_name="alert_dispatches")
    op.drop_index("ix_alert_dispatches_unclaimed", table_name="alert_dispatches")
    op.drop_column("alert_dispatches", "digest_id")
    op.drop_index("ix_digests_created", table_name="digests")
    op.drop_index("ix_digests_rule_end", table_name="digests")
    op.drop_table("digests")

    op.execute("DELETE FROM alert_deliveries WHERE outcome = 'deferred_to_digest'")
    op.drop_constraint("ck_alert_deliveries_connector", "alert_deliveries", type_="check")
    op.create_check_constraint(
        "ck_alert_deliveries_connector", "alert_deliveries",
        "(outcome IN ('no_channel', 'no_recipients')) = (connector_id IS NULL)",
    )
    op.drop_constraint("ck_alert_deliveries_outcome", "alert_deliveries", type_="check")
    op.create_check_constraint("ck_alert_deliveries_outcome", "alert_deliveries", _in("outcome", _OLD_OUTCOMES))

    op.drop_constraint("ck_notification_rules_mode", "notification_rules", type_="check")
    op.drop_column("notification_rules", "mode")
