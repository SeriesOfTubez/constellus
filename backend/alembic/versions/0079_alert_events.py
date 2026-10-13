"""Record what the notification rules selected and what was delivered (planning#233 slice 1)

Until now `notification_dispatcher` selected findings deterministically and
recorded nothing but a log line. #233's digest has to be exactly the set the
rules selected (the AI adds no alerts), so the selection has to be on record
first. Jason, 2026-10-12 (#233 6137620127).

Three tables:

- `alert_dispatches`: one rule's selection in one dispatcher call (`kind`
  `new` = first-insert findings after a scan; `promotion` = a risk-band
  escalation). `rule_name` is a snapshot, and `rule_id` goes NULL if the rule
  is deleted, so history still says what fired.
- `alert_events`: one finding in that selection, with its severity at the
  time and, for a promotion, the band change (`detail`). A finding's purge
  cascades here; nothing else deletes events.
- `alert_deliveries`: one outcome per dispatch per connector. `no_channel`
  (no notification connector enabled) and `no_recipients` carry a NULL
  `connector_id`. They are recorded because the selection happened even
  though nothing went out, which is the case on a fresh install.

New tables only: no existing row changes.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0079"
down_revision = "0078"
branch_labels = None
depends_on = None

_KINDS = ("new", "promotion")
_OUTCOMES = ("sent", "failed", "raised", "no_channel", "no_recipients")


def _in(column: str, values: tuple[str, ...]) -> str:
    return " OR ".join(f"{column} = '{v}'" for v in values)


def upgrade() -> None:
    op.create_table(
        "alert_dispatches",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column(
            "rule_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("notification_rules.id", ondelete="SET NULL"), nullable=True,
        ),
        sa.Column("rule_name", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(_in("kind", _KINDS), name="ck_alert_dispatches_kind"),
    )
    op.create_index("ix_alert_dispatches_created", "alert_dispatches", ["created_at"])
    op.create_index("ix_alert_dispatches_rule_created", "alert_dispatches", ["rule_id", "created_at"])

    op.create_table(
        "alert_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column(
            "dispatch_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("alert_dispatches.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "finding_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("findings_canonical.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("severity", sa.Text(), nullable=True),
        sa.Column("detail", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("dispatch_id", "finding_id", name="uq_alert_events_dispatch_finding"),
    )
    op.create_index("ix_alert_events_finding", "alert_events", ["finding_id"])

    op.create_table(
        "alert_deliveries",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column(
            "dispatch_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("alert_dispatches.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("connector_id", sa.Text(), nullable=True),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("recipient_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(_in("outcome", _OUTCOMES), name="ck_alert_deliveries_outcome"),
        # A connector outcome names its connector; the two "nothing went
        # out" outcomes name none.
        sa.CheckConstraint(
            "(outcome IN ('no_channel', 'no_recipients')) = (connector_id IS NULL)",
            name="ck_alert_deliveries_connector",
        ),
    )
    op.create_index("ix_alert_deliveries_dispatch", "alert_deliveries", ["dispatch_id"])


def downgrade() -> None:
    op.drop_index("ix_alert_deliveries_dispatch", table_name="alert_deliveries")
    op.drop_table("alert_deliveries")
    op.drop_index("ix_alert_events_finding", table_name="alert_events")
    op.drop_table("alert_events")
    op.drop_index("ix_alert_dispatches_rule_created", table_name="alert_dispatches")
    op.drop_index("ix_alert_dispatches_created", table_name="alert_dispatches")
    op.drop_table("alert_dispatches")
