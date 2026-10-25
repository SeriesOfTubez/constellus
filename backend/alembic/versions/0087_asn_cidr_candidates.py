"""ASN and CIDR scope candidates (planning#278 S3a): schema only.

Org discovery's `scope_candidates` held domains. S3 adds the two number
resources an RIR hands out. Claiming an ASN claims the RIR handle's
ALLOCATIONS (the CIDR candidates with the same `rir` + `rir_handle`), never
its BGP announcements; each claimed CIDR becomes a CIDR `targets` row and an
ASN has no target. Generators arrive in S3b; this migration only widens the
vocabularies and adds the columns.

## `scope_candidates`

- `ck_scope_candidates_kind`: ('domain', 'asn', 'cidr').
- `ck_scope_candidates_asn_shape`: an ASN is stored as `AS<digits>`. The range
  rules (private / reserved ASNs) live in the service (`normalise_asn`).
- `ck_scope_candidates_cidr_shape`: a CIDR is stored in Postgres's own
  canonical text form (`value::cidr::text = value`): host bits clear,
  lower-case, `::` compressed. A malformed value makes the cast raise, which
  fails the insert as well. The CASE keeps the cast away from domain rows
  (Postgres does not promise AND/OR short-circuit order).
- `rir`, `rir_handle`: which registry and which holder handle the resource
  belongs to. NOT NULL exactly when the kind is not 'domain'
  (`ck_scope_candidates_rir_iff_number_resource`,
  `ck_scope_candidates_rir_handle_iff_number_resource`), `rir` in a closed
  list (`ck_scope_candidates_rir`), the handle non-blank
  (`ck_scope_candidates_rir_handle_nonblank`). The handle is kept as written.
- `trg_scope_candidates_guard`: `rir` and `rir_handle` are immutable like
  root / kind / value (a prefix never silently moves between holders). Every
  other rule of the function is 0083's.
- `ck_scope_signals_signal_type` gains the six S3 types (none has a
  generator yet; `built=False` in `org_discovery.tiers`).

## Downgrade

Pre-MVP data is disposable: the downgrade DELETES every ASN / CIDR candidate
with its signals and events (and any signal of an S3 type, or anchored to a
non-domain candidate), then restores 0086's function, list and kind check and
drops the new columns. The append-only trigger on `scope_candidate_events` is
disabled for the delete and re-enabled. Targets created by CIDR claims are NOT
deleted.

Revision ID: 0087
Revises: 0086
"""

import sqlalchemy as sa
from alembic import op

revision = "0087"
down_revision = "0086"
branch_labels = None
depends_on = None

# Mirrored in app.models.scope_candidate (and checked by test_org_discovery_schema).
KINDS = ("domain", "asn", "cidr")
OLD_KINDS = ("domain",)
RIRS = ("arin", "ripe", "apnic", "lacnic", "afrinic")
NEW_SIGNAL_TYPES = (
    "rir_contact_email_claimed", "rir_allocation_dedicated_ip", "peeringdb_website_claimed",
    "rir_reassigned_elsewhere", "bgp_announced_not_allocated", "rir_contact_email_unvalidated",
)
OLD_SIGNAL_TYPES = (
    "admin_seed", "person_evidence", "filer_10k_website", "connector_zone",
    "registrant_email_claimed", "redirect_to_claimed", "shared_vanity_ns",
    "mx_into_claimed", "spf_sender_shared", "dmarc_report_to_claimed",
    "dmarc_exact_vendor", "registrant_org_match", "research_quote",
    "reverse_ip_dedicated", "dmarc_exact_generic", "name_similarity", "ai_mention",
)
SIGNAL_TYPES = OLD_SIGNAL_TYPES + NEW_SIGNAL_TYPES

_ASN_REGEX = r"^AS[1-9][0-9]{0,9}$"
_CIDR_REGEX = r"^[0-9a-f.:]+/[0-9]{1,3}$"


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


def _guard_function(with_rir: bool) -> str:
    extra = (
        "        OR NEW.rir IS DISTINCT FROM OLD.rir\n"
        "        OR NEW.rir_handle IS DISTINCT FROM OLD.rir_handle\n"
        if with_rir else ""
    )
    what = "root/kind/value/rir/rir_handle" if with_rir else "root/kind/value"
    return f"""
CREATE OR REPLACE FUNCTION scope_candidates_guard()
RETURNS trigger AS $$
BEGIN
    IF NEW.root_entity_id IS DISTINCT FROM OLD.root_entity_id
        OR NEW.kind IS DISTINCT FROM OLD.kind
{extra}        OR NEW.value IS DISTINCT FROM OLD.value THEN
        RAISE EXCEPTION
            'scope_candidates: {what} are immutable (row %)', OLD.id;
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
        (OLD.status = 'open' AND NEW.status IN ('claimed', 'rejected'))
        OR (OLD.status = 'rejected' AND NEW.status = 'open')
    ) THEN
        RAISE EXCEPTION
            'scope_candidates.status cannot change % -> % (row %)',
            OLD.status, NEW.status, OLD.id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""


def upgrade() -> None:
    op.drop_constraint("ck_scope_candidates_kind", "scope_candidates", type_="check")
    op.create_check_constraint("ck_scope_candidates_kind", "scope_candidates", _in("kind", KINDS))

    op.add_column("scope_candidates", sa.Column("rir", sa.Text(), nullable=True))
    op.add_column("scope_candidates", sa.Column("rir_handle", sa.Text(), nullable=True))
    op.create_check_constraint(
        "ck_scope_candidates_asn_shape", "scope_candidates", f"kind <> 'asn' OR value ~ '{_ASN_REGEX}'"
    )
    op.create_check_constraint(
        "ck_scope_candidates_cidr_shape", "scope_candidates",
        f"CASE WHEN kind = 'cidr' THEN (value ~ '{_CIDR_REGEX}' AND value::cidr::text = value) ELSE true END",
    )
    op.create_check_constraint(
        "ck_scope_candidates_rir", "scope_candidates", f"rir IS NULL OR {_in('rir', RIRS)}"
    )
    op.create_check_constraint(
        "ck_scope_candidates_rir_iff_number_resource", "scope_candidates", "(kind = 'domain') = (rir IS NULL)"
    )
    op.create_check_constraint(
        "ck_scope_candidates_rir_handle_iff_number_resource", "scope_candidates",
        "(kind = 'domain') = (rir_handle IS NULL)",
    )
    op.create_check_constraint(
        "ck_scope_candidates_rir_handle_nonblank", "scope_candidates",
        "rir_handle IS NULL OR length(btrim(rir_handle)) > 0",
    )
    op.create_index(
        "ix_scope_candidates_root_rir_handle", "scope_candidates", ["root_entity_id", "rir", "rir_handle"]
    )
    op.execute(_guard_function(True))

    op.drop_constraint("ck_scope_signals_signal_type", "scope_signals", type_="check")
    op.create_check_constraint("ck_scope_signals_signal_type", "scope_signals", _in("signal_type", SIGNAL_TYPES))


def downgrade() -> None:
    # Pre-MVP data is disposable (see the docstring). Signals first: they
    # reference candidates (and events reference signals).
    doomed_signals = (
        "SELECT s.id FROM scope_signals s"
        " JOIN scope_candidates c ON c.id = s.candidate_id"
        " LEFT JOIN scope_candidates a ON a.id = s.anchor_candidate_id"
        f" WHERE c.kind <> 'domain' OR a.kind <> 'domain' OR {_in('s.signal_type', NEW_SIGNAL_TYPES)}"
    )
    op.execute("ALTER TABLE scope_candidate_events DISABLE TRIGGER trg_scope_candidate_events_append_only")
    op.execute(
        "DELETE FROM scope_candidate_events WHERE "
        "candidate_id IN (SELECT id FROM scope_candidates WHERE kind <> 'domain') "
        f"OR signal_id IN ({doomed_signals})"
    )
    op.execute("ALTER TABLE scope_candidate_events ENABLE TRIGGER trg_scope_candidate_events_append_only")
    op.execute(f"DELETE FROM scope_signals WHERE id IN ({doomed_signals})")
    op.execute("DELETE FROM scope_candidates WHERE kind <> 'domain'")

    op.drop_constraint("ck_scope_signals_signal_type", "scope_signals", type_="check")
    op.create_check_constraint("ck_scope_signals_signal_type", "scope_signals", _in("signal_type", OLD_SIGNAL_TYPES))

    op.execute(_guard_function(False))
    op.drop_index("ix_scope_candidates_root_rir_handle", table_name="scope_candidates")
    for name in (
        "ck_scope_candidates_rir_handle_nonblank", "ck_scope_candidates_rir_handle_iff_number_resource",
        "ck_scope_candidates_rir_iff_number_resource", "ck_scope_candidates_rir",
        "ck_scope_candidates_cidr_shape", "ck_scope_candidates_asn_shape",
    ):
        op.drop_constraint(name, "scope_candidates", type_="check")
    op.drop_column("scope_candidates", "rir_handle")
    op.drop_column("scope_candidates", "rir")
    op.drop_constraint("ck_scope_candidates_kind", "scope_candidates", type_="check")
    op.create_check_constraint("ck_scope_candidates_kind", "scope_candidates", _in("kind", OLD_KINDS))
