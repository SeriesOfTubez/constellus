"""Add `web_classifications` (planning#231)

One row per AI web-app classification request for an endpoint (asset, port):
queued -> running -> succeeded | failed. A succeeded row is a PROPOSAL
(`decision = 'proposed'`): the kind of web app (enum), the environment
(enum), an optional product name that literally appears in a cited leaf, and
the `evidence` citations behind it. Only an ADMIN decision (accepted |
rejected) promotes or discards it; accepting adds an asset tag and nothing
else. A newer success supersedes an older still-proposed row.

A separate table on purpose: AI output never lives on `assets_canonical`
columns that scoring, attribution or hosting read, and never in
`asset_state`.

Invariants enforced here, not only in the service:
- `uq_web_classifications_active`: one queued/running row per endpoint.
- a decision exists exactly on succeeded rows; accepted/rejected carry
  `decided_at`; succeeded rows carry kind and environment.
- `web_classifications_guard` (modelled on `candidate_domains_guard`, 0064):
  a decided row's decision never changes; a decision only moves from
  'proposed' (or from NULL on the succeeded transition); asset and port are
  always immutable; a succeeded row's content is frozen.

New table only: no existing row changes.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0075"
down_revision = "0074"
branch_labels = None
depends_on = None

_STATUSES = ("queued", "running", "succeeded", "failed")
_DECISIONS = ("proposed", "accepted", "rejected", "superseded")
_KINDS = (
    "login_portal", "admin_panel", "default_install", "parked", "marketing_site", "api", "application", "unknown",
)
_ENVIRONMENTS = ("production", "non_production", "unknown")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


_GUARD_FUNCTION_SQL = """
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

_GUARD_TRIGGER_SQL = """
CREATE TRIGGER trg_web_classifications_guard
BEFORE UPDATE ON web_classifications
FOR EACH ROW EXECUTE FUNCTION web_classifications_guard();
"""


def upgrade() -> None:
    op.create_table(
        "web_classifications",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column(
            "asset_canonical_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets_canonical.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default=sa.text("'queued'")),
        sa.Column("decision", sa.Text(), nullable=True),
        sa.Column("kind", sa.Text(), nullable=True),
        sa.Column("environment", sa.Text(), nullable=True),
        sa.Column("product", sa.Text(), nullable=True),
        sa.Column("product_source_field", sa.Text(), nullable=True),
        sa.Column("evidence", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("citations_returned", sa.Integer(), nullable=True),
        sa.Column("citations_dropped", sa.Integer(), nullable=True),
        sa.Column("product_dropped", sa.Boolean(), nullable=True),
        sa.Column("downgraded", sa.Boolean(), nullable=True),
        sa.Column("input_hash", sa.Text(), nullable=True),
        sa.Column("model", sa.Text(), nullable=True),
        sa.Column("ledger_ids", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("forced_strict", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "requested_by_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
        ),
        sa.Column(
            "decided_by_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
        ),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("port BETWEEN 1 AND 65535", name="ck_web_classifications_port"),
        sa.CheckConstraint(_in("status", _STATUSES), name="ck_web_classifications_status"),
        sa.CheckConstraint("decision IS NULL OR " + _in("decision", _DECISIONS), name="ck_web_classifications_decision"),
        sa.CheckConstraint("kind IS NULL OR " + _in("kind", _KINDS), name="ck_web_classifications_kind"),
        sa.CheckConstraint(
            "environment IS NULL OR " + _in("environment", _ENVIRONMENTS), name="ck_web_classifications_environment",
        ),
        sa.CheckConstraint(
            "(status = 'succeeded') = (decision IS NOT NULL)", name="ck_web_classifications_decision_on_succeeded",
        ),
        sa.CheckConstraint(
            "status <> 'succeeded' OR (kind IS NOT NULL AND environment IS NOT NULL)",
            name="ck_web_classifications_succeeded_complete",
        ),
        sa.CheckConstraint(
            "(decision IN ('accepted', 'rejected')) = (decided_at IS NOT NULL)",
            name="ck_web_classifications_decided_at",
        ),
    )
    op.create_index(
        "uq_web_classifications_active", "web_classifications", ["asset_canonical_id", "port"], unique=True,
        postgresql_where=sa.text("status IN ('queued', 'running')"),
    )
    op.create_index(
        "ix_web_classifications_endpoint_created", "web_classifications",
        ["asset_canonical_id", "port", sa.text("created_at DESC")],
    )
    op.create_index(
        "ix_web_classifications_proposed", "web_classifications", ["created_at"],
        postgresql_where=sa.text("decision = 'proposed'"),
    )
    op.execute(sa.text(_GUARD_FUNCTION_SQL))
    op.execute(sa.text(_GUARD_TRIGGER_SQL))


def downgrade() -> None:
    op.execute(sa.text("DROP TRIGGER IF EXISTS trg_web_classifications_guard ON web_classifications"))
    op.execute(sa.text("DROP FUNCTION IF EXISTS web_classifications_guard()"))
    op.drop_table("web_classifications")
