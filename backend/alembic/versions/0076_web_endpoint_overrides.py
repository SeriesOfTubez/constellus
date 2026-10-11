"""Web classification: AI value applied, a person corrects it (planning#231)

Jason, 2026-10-11 (#231 6112788736): web classification is low-impact, so the
AI's value is applied directly and shown as inferred; an ADMIN corrects it.
The proposal / accept / reject flow from 0075 goes away:

- `web_classifications` stays the immutable AI log. `decision`,
  `decided_by_id` and `decided_at` are dropped, along with their CHECKs, the
  proposals index and the trigger's decision clause. A succeeded row's
  content is still frozen, and asset/port are still immutable.
- `web_endpoint_overrides` holds a person's correction, at most one per
  endpoint (asset, port). Upsert re-corrects; delete reverts to the AI value.
  `input_snapshot` is the exact bounded input the AI saw when the correction
  was made (the feedback record), and `input_hash` lets the UI flag a
  correction whose endpoint has changed since.

No tags are written from either table: `hygiene_scorer` counts any asset tag
as an ownership signal, so an auto-applied tag would move hygiene grades.

Dev held 0 `web_classifications` rows when this was written; the downgrade
marks every succeeded row 'proposed' so 0075's CHECKs hold again.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0076"
down_revision = "0075"
branch_labels = None
depends_on = None

_DECISIONS = ("proposed", "accepted", "rejected", "superseded")
_KINDS = (
    "login_portal", "admin_panel", "default_install", "parked", "marketing_site", "api", "application", "unknown",
)
_ENVIRONMENTS = ("production", "non_production", "unknown")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


_GUARD_V2_SQL = """
CREATE OR REPLACE FUNCTION web_classifications_guard()
RETURNS trigger AS $$
BEGIN
    IF NEW.asset_canonical_id IS DISTINCT FROM OLD.asset_canonical_id
        OR NEW.port IS DISTINCT FROM OLD.port THEN
        RAISE EXCEPTION
            'web_classifications: asset and port are immutable (row %)', OLD.id;
    END IF;
    IF OLD.status = 'succeeded' AND (
        NEW.status IS DISTINCT FROM OLD.status
        OR NEW.kind IS DISTINCT FROM OLD.kind
        OR NEW.environment IS DISTINCT FROM OLD.environment
        OR NEW.product IS DISTINCT FROM OLD.product
        OR NEW.product_source_field IS DISTINCT FROM OLD.product_source_field
        OR NEW.evidence IS DISTINCT FROM OLD.evidence
        OR NEW.input_hash IS DISTINCT FROM OLD.input_hash
        OR NEW.model IS DISTINCT FROM OLD.model) THEN
        RAISE EXCEPTION
            'web_classifications: a succeeded row''s status/kind/environment/product/evidence/input/model are immutable (row %)',
            OLD.id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""

# 0075's function, verbatim, for the downgrade.
_GUARD_V1_SQL = """
CREATE OR REPLACE FUNCTION web_classifications_guard()
RETURNS trigger AS $$
BEGIN
    IF NEW.asset_canonical_id IS DISTINCT FROM OLD.asset_canonical_id
        OR NEW.port IS DISTINCT FROM OLD.port THEN
        RAISE EXCEPTION
            'web_classifications: asset and port are immutable (row %)', OLD.id;
    END IF;
    IF OLD.decision IN ('accepted', 'rejected', 'superseded')
        AND NEW.decision IS DISTINCT FROM OLD.decision THEN
        RAISE EXCEPTION
            'web_classifications.decision cannot change once decided (% -> %, row %)',
            OLD.decision, NEW.decision, OLD.id;
    END IF;
    IF OLD.status = 'succeeded' AND (
        NEW.kind IS DISTINCT FROM OLD.kind
        OR NEW.environment IS DISTINCT FROM OLD.environment
        OR NEW.product IS DISTINCT FROM OLD.product
        OR NEW.product_source_field IS DISTINCT FROM OLD.product_source_field
        OR NEW.evidence IS DISTINCT FROM OLD.evidence
        OR NEW.input_hash IS DISTINCT FROM OLD.input_hash
        OR NEW.model IS DISTINCT FROM OLD.model) THEN
        RAISE EXCEPTION
            'web_classifications: a succeeded row''s kind/environment/product/evidence/input/model are immutable (row %)',
            OLD.id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""


def upgrade() -> None:
    op.drop_index("ix_web_classifications_proposed", table_name="web_classifications")
    op.drop_constraint("ck_web_classifications_decided_at", "web_classifications", type_="check")
    op.drop_constraint("ck_web_classifications_decision_on_succeeded", "web_classifications", type_="check")
    op.drop_constraint("ck_web_classifications_decision", "web_classifications", type_="check")
    op.execute(sa.text(_GUARD_V2_SQL))
    op.drop_column("web_classifications", "decided_at")
    op.drop_column("web_classifications", "decided_by_id")
    op.drop_column("web_classifications", "decision")

    op.create_table(
        "web_endpoint_overrides",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column(
            "asset_canonical_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets_canonical.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("environment", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("input_snapshot", postgresql.JSONB(), nullable=False),
        sa.Column("input_hash", sa.Text(), nullable=False),
        sa.Column(
            "ai_classification_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("web_classifications.id", ondelete="SET NULL"), nullable=True,
        ),
        sa.Column(
            "set_by_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
        ),
        sa.Column("set_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("port BETWEEN 1 AND 65535", name="ck_web_endpoint_overrides_port"),
        sa.CheckConstraint(_in("kind", _KINDS), name="ck_web_endpoint_overrides_kind"),
        sa.CheckConstraint(_in("environment", _ENVIRONMENTS), name="ck_web_endpoint_overrides_environment"),
        sa.CheckConstraint(
            "reason IS NULL OR char_length(reason) <= 500", name="ck_web_endpoint_overrides_reason_len",
        ),
        sa.UniqueConstraint("asset_canonical_id", "port", name="uq_web_endpoint_overrides_endpoint"),
    )


def downgrade() -> None:
    op.drop_table("web_endpoint_overrides")

    op.add_column("web_classifications", sa.Column("decision", sa.Text(), nullable=True))
    op.add_column(
        "web_classifications",
        sa.Column(
            "decided_by_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
        ),
    )
    op.add_column("web_classifications", sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True))
    # The v2 guard forbids nothing on `decision` (the column did not exist), so
    # this backfill passes it; v1 is restored after.
    op.execute(sa.text("UPDATE web_classifications SET decision = 'proposed' WHERE status = 'succeeded'"))
    op.execute(sa.text(_GUARD_V1_SQL))
    op.create_check_constraint(
        "ck_web_classifications_decision", "web_classifications", "decision IS NULL OR " + _in("decision", _DECISIONS),
    )
    op.create_check_constraint(
        "ck_web_classifications_decision_on_succeeded", "web_classifications",
        "(status = 'succeeded') = (decision IS NOT NULL)",
    )
    op.create_check_constraint(
        "ck_web_classifications_decided_at", "web_classifications",
        "(decision IN ('accepted', 'rejected')) = (decided_at IS NOT NULL)",
    )
    op.create_index(
        "ix_web_classifications_proposed", "web_classifications", ["created_at"],
        postgresql_where=sa.text("decision = 'proposed'"),
    )
