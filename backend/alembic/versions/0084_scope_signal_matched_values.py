"""Scope signals: the shared value a verifier matched on (planning#277 S1b).

`scope_signals.matched_values` holds what two domains were found to share:
the nameserver host(s) for `shared_vanity_ns`, the MX host(s) for
`mx_into_claimed`, the SPF sender(s) for `spf_sender_shared`, the folded
registrant organization for `registrant_org_match`, the IP address for
`reverse_ip_dedicated`. Without a column that value would exist only inside
the quote, and every data point must be queryable. NULL for the S1a types,
which match on a document, not on a shared value.

The column is immutable like every other column but `last_seen_at`, so the
0083 guard function is replaced with one that also compares it.

`ix_scope_candidates_target_id`: the post-discovery reverse-IP step looks up
claimed candidates by the target a scan just discovered.

`domain_whois_cache` is emptied: `registrant_org` stops falling back to the
registrant NAME (a person, never an organization) and the cached rows were
written under the old meaning. It is a cache; the next lookup refills it.

Revision ID: 0084
Revises: 0083
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import ARRAY

revision = "0084"
down_revision = "0083"
branch_labels = None
depends_on = None


def _guard_function(with_matched_values: bool) -> str:
    extra = "        OR NEW.matched_values IS DISTINCT FROM OLD.matched_values\n" if with_matched_values else ""
    return f"""
CREATE OR REPLACE FUNCTION scope_signals_guard()
RETURNS trigger AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.candidate_id IS DISTINCT FROM OLD.candidate_id
        OR NEW.signal_type IS DISTINCT FROM OLD.signal_type
        OR NEW.anchor_kind IS DISTINCT FROM OLD.anchor_kind
        OR NEW.anchor_candidate_id IS DISTINCT FROM OLD.anchor_candidate_id
        OR NEW.anchor_entity_id IS DISTINCT FROM OLD.anchor_entity_id
        OR (NEW.anchor_user_id IS DISTINCT FROM OLD.anchor_user_id AND NEW.anchor_user_id IS NOT NULL)
        OR NEW.via_entity_id IS DISTINCT FROM OLD.via_entity_id
        OR NEW.evidence_id IS DISTINCT FROM OLD.evidence_id
        OR NEW.quote IS DISTINCT FROM OLD.quote
        OR NEW.observer_id IS DISTINCT FROM OLD.observer_id
{extra}        OR NEW.first_seen_at IS DISTINCT FROM OLD.first_seen_at
        OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION
            'scope_signals: only last_seen_at may change (row %)', OLD.id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""


def upgrade() -> None:
    op.add_column("scope_signals", sa.Column("matched_values", ARRAY(sa.Text()), nullable=True))
    op.create_check_constraint(
        "ck_scope_signals_matched_values_nonempty",
        "scope_signals",
        "matched_values IS NULL OR cardinality(matched_values) > 0",
    )
    op.execute(_guard_function(True))
    op.create_index("ix_scope_candidates_target_id", "scope_candidates", ["target_id"])
    op.execute("DELETE FROM domain_whois_cache")


def downgrade() -> None:
    op.drop_index("ix_scope_candidates_target_id", table_name="scope_candidates")
    op.execute(_guard_function(False))
    op.drop_constraint("ck_scope_signals_matched_values_nonempty", "scope_signals", type_="check")
    op.drop_column("scope_signals", "matched_values")
