"""Reassigned-away records on claimed CIDR candidates (planning#278 S3c3a).

A claimed CIDR candidate became a CIDR Target on the evidence that its holder
handle held it. A later Re-check reads the prefix back from its registry; if
part of it is now registered to another holder, or to no one, that is recorded
here. The record is not a finding (a claimed CIDR has no asset to hang one on)
and it never changes the claim: the candidate stays `claimed` and its Target
stays (planning#278 comment 6405308164 #2, 6391512254 #4).

## `scope_candidate_reassignments`

- One row per (candidate, prefix, new holder kind, new holder handle):
  `uq_scope_candidate_reassignments_route` is UNIQUE NULLS NOT DISTINCT, so the
  same reassignment seen again is one row whose `last_seen_at` moves, and a
  different new holder is a new row (history across repeated reassignment).
- `prefix` is the reassigned part of the candidate's prefix (equal to it or
  inside it), canonical CIDR text: `ck_..._prefix_canonical`.
- `new_holder_kind` in ('org', 'customer', 'unknown', 'unregistered');
  `new_holder_handle` is set exactly for 'org' / 'customer'. 'unknown' is a
  registration whose holder could not be read; 'unregistered' is space no
  registration covers any more.
- `evidence_id` is NOT NULL (the registry answer the detection rests on).
- `trg_scope_candidate_reassignments_insert` (BEFORE INSERT): the candidate is
  a `cidr` candidate that is `claimed`, and the prefix lies inside its value.
- `trg_scope_candidate_reassignments_guard` (BEFORE UPDATE): only
  `last_seen_at` may change.

Downgrade drops the table and its functions.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0089"
down_revision = "0088"
branch_labels = None
depends_on = None

# Mirrored by hand in `app/models/scope_candidate.py` (REASSIGNED_HOLDER_KINDS);
# `test_org_discovery_schema.py` fails if the two drift.
HOLDER_KINDS = ("org", "customer", "unknown", "unregistered")

_INSERT_FUNCTION = """
CREATE OR REPLACE FUNCTION scope_candidate_reassignments_insert_check()
RETURNS trigger AS $$
BEGIN
    PERFORM 1
    FROM scope_candidates c
    WHERE c.id = NEW.candidate_id
      AND c.kind = 'cidr'
      AND c.status = 'claimed'
      AND NEW.prefix::cidr <<= c.value::cidr;
    IF NOT FOUND THEN
        RAISE EXCEPTION
            'scope_candidate_reassignments: the candidate must be a claimed cidr containing the prefix (candidate %)',
            NEW.candidate_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""

_INSERT_TRIGGER = """
CREATE TRIGGER trg_scope_candidate_reassignments_insert
BEFORE INSERT ON scope_candidate_reassignments
FOR EACH ROW EXECUTE FUNCTION scope_candidate_reassignments_insert_check();
"""

_GUARD_FUNCTION = """
CREATE OR REPLACE FUNCTION scope_candidate_reassignments_guard()
RETURNS trigger AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.candidate_id IS DISTINCT FROM OLD.candidate_id
        OR NEW.prefix IS DISTINCT FROM OLD.prefix
        OR NEW.new_holder_kind IS DISTINCT FROM OLD.new_holder_kind
        OR NEW.new_holder_handle IS DISTINCT FROM OLD.new_holder_handle
        OR NEW.evidence_id IS DISTINCT FROM OLD.evidence_id
        OR NEW.first_detected_at IS DISTINCT FROM OLD.first_detected_at
        OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION
            'scope_candidate_reassignments: only last_seen_at may change (row %)', OLD.id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""

_GUARD_TRIGGER = """
CREATE TRIGGER trg_scope_candidate_reassignments_guard
BEFORE UPDATE ON scope_candidate_reassignments
FOR EACH ROW EXECUTE FUNCTION scope_candidate_reassignments_guard();
"""


def upgrade() -> None:
    op.create_table(
        "scope_candidate_reassignments",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column(
            "candidate_id", UUID(as_uuid=True), sa.ForeignKey("scope_candidates.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("prefix", sa.Text(), nullable=False),
        sa.Column("new_holder_kind", sa.Text(), nullable=False),
        sa.Column("new_holder_handle", sa.Text(), nullable=True),
        sa.Column(
            "evidence_id", UUID(as_uuid=True), sa.ForeignKey("evidence_fetches.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("first_detected_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "new_holder_kind IN ('org', 'customer', 'unknown', 'unregistered')", name="ck_scope_candidate_reassignments_holder_kind"
        ),
        sa.CheckConstraint(
            "(new_holder_handle IS NOT NULL) = (new_holder_kind IN ('org', 'customer'))",
            name="ck_scope_candidate_reassignments_handle_iff_holder",
        ),
        sa.CheckConstraint(
            "new_holder_handle IS NULL OR btrim(new_holder_handle) <> ''",
            name="ck_scope_candidate_reassignments_handle_nonblank",
        ),
        sa.CheckConstraint(
            "prefix ~ '^[0-9a-f.:]+/[0-9]+$' AND (prefix::cidr)::text = prefix",
            name="ck_scope_candidate_reassignments_prefix_canonical",
        ),
        sa.CheckConstraint("last_seen_at >= first_detected_at", name="ck_scope_candidate_reassignments_seen_order"),
    )
    op.execute(
        "ALTER TABLE scope_candidate_reassignments ADD CONSTRAINT uq_scope_candidate_reassignments_route "
        "UNIQUE NULLS NOT DISTINCT (candidate_id, prefix, new_holder_kind, new_holder_handle)"
    )
    op.execute(_INSERT_FUNCTION)
    op.execute(_INSERT_TRIGGER)
    op.execute(_GUARD_FUNCTION)
    op.execute(_GUARD_TRIGGER)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_scope_candidate_reassignments_guard ON scope_candidate_reassignments")
    op.execute("DROP TRIGGER IF EXISTS trg_scope_candidate_reassignments_insert ON scope_candidate_reassignments")
    op.drop_table("scope_candidate_reassignments")
    op.execute("DROP FUNCTION IF EXISTS scope_candidate_reassignments_guard()")
    op.execute("DROP FUNCTION IF EXISTS scope_candidate_reassignments_insert_check()")
