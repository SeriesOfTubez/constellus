"""Which corrections steered a web classification (planning#231 slice 3)

Jason, 2026-10-12 (#231 6118442650): up to 3 similar admin corrections from
the same engagement go into the prompt as labelled examples, inside `<data>`.
`example_override_ids` records which `web_endpoint_overrides` rows were sent,
so a classification an example steered can be traced to it. Ids only, no
foreign key: a correction that is later reverted deletes its row, and the log
must still say what was sent at the time.

Additive. Existing rows get `[]` (no examples were ever sent). The guard
freezes the column with the rest of a succeeded row's content.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0078"
down_revision = "0077"
branch_labels = None
depends_on = None


_GUARD_V3_SQL = """
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
        OR NEW.model IS DISTINCT FROM OLD.model
        OR NEW.example_override_ids IS DISTINCT FROM OLD.example_override_ids) THEN
        RAISE EXCEPTION
            'web_classifications: a succeeded row''s status/kind/environment/product/evidence/input/model/examples are immutable (row %)',
            OLD.id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""

# 0076's function, verbatim, for the downgrade.
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


def upgrade() -> None:
    op.add_column(
        "web_classifications",
        sa.Column("example_override_ids", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
    )
    op.create_check_constraint(
        "ck_web_classifications_example_ids_array", "web_classifications",
        "jsonb_typeof(example_override_ids) = 'array' AND jsonb_array_length(example_override_ids) <= 3",
    )
    op.execute(sa.text(_GUARD_V3_SQL))


def downgrade() -> None:
    op.execute(sa.text(_GUARD_V2_SQL))
    op.drop_constraint("ck_web_classifications_example_ids_array", "web_classifications", type_="check")
    op.drop_column("web_classifications", "example_override_ids")
