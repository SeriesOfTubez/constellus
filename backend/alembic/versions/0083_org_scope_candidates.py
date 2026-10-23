"""Organizations: scope candidates, their signals, and their history
(planning#277 S1a). Replaces `candidate_domains`.

A candidate (a domain today; an ASN in S3) belongs to a ROOT organization, an
`org_entities` row that has a `relationship` (a `resolve()` stop). What makes
it worth a person's attention is not one row's `source` but its SIGNALS: each
`scope_signals` row is one independent reason, with an anchor (what the
signal runs through) and a tier. Strength is calculated on load in SQL
(`app.services.org_discovery.strength`); nothing here stores it.

Data is disposable pre-MVP: `candidate_domains` is dropped, with no data
migration.

## `scope_candidates`

- `uq_scope_candidates_root_kind_value`: one row per (root, kind, value).
- `ck_scope_candidates_domain_shape`: for kind 'domain', `value` matches the
  same hostname regex as 0064 (the service canonicalises first; this is the
  backstop a raw insert cannot bypass).
- Decision columns follow `status`: `affiliated_entity_id`,
  `accepted_into` iff claimed; `decided_at` iff claimed or rejected;
  `rejection_reason` and `rejected_strong_types` iff rejected.
  `engagement_id` iff `accepted_into = 'engagement'`. `decided_by_id` and
  `target_id` are ON DELETE SET NULL and outside every CHECK (0064's
  reasoning: a deleted user must not flip a live CHECK).
- `trg_scope_candidates_guard`: `root_entity_id`, `kind`, `value` are
  immutable; status moves open -> claimed, open -> rejected, rejected ->
  open only (`claimed` is terminal). On rejected -> open the service clears
  the rejection columns (the CHECKs force it); the history lives in
  `scope_candidate_events`.

## `scope_signals`

- `uq_scope_signals_route` is UNIQUE NULLS NOT DISTINCT: the same route
  seen again is one row whose `last_seen_at` moves. Every other column is
  immutable (`trg_scope_signals_guard`), except that `anchor_user_id` may be
  set to NULL (its FK is ON DELETE SET NULL, which Postgres performs as an
  UPDATE this trigger also sees).
- Evidence is NOT NULL for every type except `admin_seed`, and `quote` is
  set iff evidence is.
- `trg_scope_signals_anchor` (BEFORE INSERT): a `claimed_candidate` anchor
  must point at a candidate that is already `claimed`, under the SAME root,
  and not at the signal's own candidate. This is the DB half of the
  anchor-chain rule: a signal can only be borne by something a person has
  already decided is ours.

## `scope_candidate_events`

Append-only (`trg_scope_candidate_events_append_only` refuses UPDATE and
DELETE), except that `user_id` may be set to NULL by its own FK action.

## Downgrade

Drops the three tables and recreates `candidate_domains` EMPTY with its
0064 + 0068 constraints and guard (copied, not imported), so upgrade /
downgrade / upgrade works. The old rows are not restored.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import ARRAY, UUID

revision = "0083"
down_revision = "0082"
branch_labels = None
depends_on = None

# Same shape as 0064's `_DOMAIN_REGEX` (copied: a migration must not change
# meaning when an earlier one is edited).
_DOMAIN_REGEX = r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,63}|xn--[a-z0-9-]{1,59})$"

# The CHECK vocabularies. `app/tests/test_org_discovery_schema.py` asserts
# the model frozensets and `org_discovery.tiers.SIGNALS` equal these.
KINDS = ("domain",)
CANDIDATE_STATUSES = ("open", "claimed", "rejected")
ACCEPTED_INTO = ("engagement", "estate")
SIGNAL_TYPES = (
    "admin_seed", "person_evidence", "filer_10k_website", "connector_zone",
    "registrant_email_claimed", "redirect_to_claimed", "shared_vanity_ns",
    "mx_into_claimed", "spf_sender_shared", "dmarc_report_to_claimed",
    "dmarc_exact_vendor", "registrant_org_match", "research_quote",
    "reverse_ip_dedicated", "dmarc_exact_generic", "name_similarity", "ai_mention",
)
ANCHOR_KINDS = ("claimed_candidate", "filer_filing", "person")
EVENT_KINDS = ("claimed", "rejected", "unlocked")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


_CANDIDATE_GUARD_FUNCTION = """
CREATE OR REPLACE FUNCTION scope_candidates_guard()
RETURNS trigger AS $$
BEGIN
    IF NEW.root_entity_id IS DISTINCT FROM OLD.root_entity_id
        OR NEW.kind IS DISTINCT FROM OLD.kind
        OR NEW.value IS DISTINCT FROM OLD.value THEN
        RAISE EXCEPTION
            'scope_candidates: root/kind/value are immutable (row %)', OLD.id;
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

_CANDIDATE_GUARD_TRIGGER = """
CREATE TRIGGER trg_scope_candidates_guard
BEFORE UPDATE ON scope_candidates
FOR EACH ROW EXECUTE FUNCTION scope_candidates_guard();
"""

_SIGNAL_GUARD_FUNCTION = """
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
        OR NEW.first_seen_at IS DISTINCT FROM OLD.first_seen_at
        OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION
            'scope_signals: only last_seen_at may change (row %)', OLD.id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""

_SIGNAL_GUARD_TRIGGER = """
CREATE TRIGGER trg_scope_signals_guard
BEFORE UPDATE ON scope_signals
FOR EACH ROW EXECUTE FUNCTION scope_signals_guard();
"""

_SIGNAL_ANCHOR_FUNCTION = """
CREATE OR REPLACE FUNCTION scope_signals_anchor_check()
RETURNS trigger AS $$
BEGIN
    IF NEW.anchor_kind = 'claimed_candidate' THEN
        IF NEW.anchor_candidate_id = NEW.candidate_id THEN
            RAISE EXCEPTION
                'scope_signals: a candidate cannot anchor its own signal (candidate %)', NEW.candidate_id;
        END IF;
        PERFORM 1
        FROM scope_candidates a
        JOIN scope_candidates c ON c.id = NEW.candidate_id
        WHERE a.id = NEW.anchor_candidate_id
          AND a.status = 'claimed'
          AND a.root_entity_id = c.root_entity_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION
                'scope_signals: a claimed_candidate anchor must be a claimed candidate under the same root (anchor %, candidate %)',
                NEW.anchor_candidate_id, NEW.candidate_id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""

_SIGNAL_ANCHOR_TRIGGER = """
CREATE TRIGGER trg_scope_signals_anchor
BEFORE INSERT ON scope_signals
FOR EACH ROW EXECUTE FUNCTION scope_signals_anchor_check();
"""

_EVENT_GUARD_FUNCTION = """
CREATE OR REPLACE FUNCTION scope_candidate_events_append_only()
RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'UPDATE'
        AND NEW.user_id IS NULL
        AND NEW.id IS NOT DISTINCT FROM OLD.id
        AND NEW.candidate_id IS NOT DISTINCT FROM OLD.candidate_id
        AND NEW.event IS NOT DISTINCT FROM OLD.event
        AND NEW.at IS NOT DISTINCT FROM OLD.at
        AND NEW.reason IS NOT DISTINCT FROM OLD.reason
        AND NEW.signal_id IS NOT DISTINCT FROM OLD.signal_id THEN
        RETURN NEW;  -- users.id ON DELETE SET NULL, performed as an UPDATE
    END IF;
    RAISE EXCEPTION 'scope_candidate_events is append-only (% on row %)', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;
"""

_EVENT_GUARD_TRIGGER = """
CREATE TRIGGER trg_scope_candidate_events_append_only
BEFORE UPDATE OR DELETE ON scope_candidate_events
FOR EACH ROW EXECUTE FUNCTION scope_candidate_events_append_only();
"""

# ── downgrade: the old table, exactly as 0064 + 0068 left it ───────────────

_OLD_GUARD_FUNCTION = """
CREATE OR REPLACE FUNCTION candidate_domains_guard()
RETURNS trigger AS $$
BEGIN
    IF OLD.status <> 'proposed' AND NEW.status IS DISTINCT FROM OLD.status THEN
        RAISE EXCEPTION
            'candidate_domains.status cannot change once decided (% -> %, row %)',
            OLD.status, NEW.status, OLD.id;
    END IF;
    IF OLD.status <> 'proposed' AND (
        NEW.accepted_into IS DISTINCT FROM OLD.accepted_into
        OR NEW.engagement_id IS DISTINCT FROM OLD.engagement_id
    ) THEN
        RAISE EXCEPTION
            'candidate_domains: accepted_into/engagement_id cannot change once decided (row %)',
            OLD.id;
    END IF;
    IF NEW.entity_id IS DISTINCT FROM OLD.entity_id
        OR NEW.domain IS DISTINCT FROM OLD.domain
        OR NEW.source IS DISTINCT FROM OLD.source
        OR NEW.observer_id IS DISTINCT FROM OLD.observer_id
        OR NEW.evidence_id IS DISTINCT FROM OLD.evidence_id
        OR NEW.quote IS DISTINCT FROM OLD.quote THEN
        RAISE EXCEPTION
            'candidate_domains: entity/domain/source/evidence/quote are immutable (row %)',
            OLD.id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""

_OLD_GUARD_TRIGGER = """
CREATE TRIGGER trg_candidate_domains_guard
BEFORE UPDATE ON candidate_domains
FOR EACH ROW EXECUTE FUNCTION candidate_domains_guard();
"""


def upgrade() -> None:
    # The old table, its guard trigger and function. Nothing else references
    # it (0065 and 0075 only mention it in prose).
    op.execute("DROP TRIGGER IF EXISTS trg_candidate_domains_guard ON candidate_domains")
    op.execute("DROP FUNCTION IF EXISTS candidate_domains_guard()")
    op.drop_index("ix_candidate_domains_status", table_name="candidate_domains")
    op.drop_table("candidate_domains")

    op.create_table(
        "scope_candidates",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column("root_entity_id", UUID(as_uuid=True), sa.ForeignKey("org_entities.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default=sa.text("'open'")),
        sa.Column("affiliated_entity_id", UUID(as_uuid=True), sa.ForeignKey("org_entities.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decided_by_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column("rejected_strong_types", ARRAY(sa.Text()), nullable=True),
        sa.Column("accepted_into", sa.Text(), nullable=True),
        sa.Column("engagement_id", UUID(as_uuid=True), sa.ForeignKey("engagements.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("target_id", UUID(as_uuid=True), sa.ForeignKey("targets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(_in("kind", KINDS), name="ck_scope_candidates_kind"),
        sa.CheckConstraint(f"kind <> 'domain' OR value ~ '{_DOMAIN_REGEX}'", name="ck_scope_candidates_domain_shape"),
        sa.CheckConstraint(_in("status", CANDIDATE_STATUSES), name="ck_scope_candidates_status"),
        sa.CheckConstraint(
            "(status = 'claimed') = (affiliated_entity_id IS NOT NULL)", name="ck_scope_candidates_affiliated"
        ),
        sa.CheckConstraint(
            "(status IN ('claimed', 'rejected')) = (decided_at IS NOT NULL)", name="ck_scope_candidates_decided_at"
        ),
        sa.CheckConstraint(
            "(status = 'rejected') = (rejection_reason IS NOT NULL)", name="ck_scope_candidates_rejection_reason"
        ),
        sa.CheckConstraint(
            "rejection_reason IS NULL OR length(btrim(rejection_reason)) > 0",
            name="ck_scope_candidates_rejection_reason_nonblank",
        ),
        sa.CheckConstraint(
            "(status = 'rejected') = (rejected_strong_types IS NOT NULL)", name="ck_scope_candidates_rejected_types"
        ),
        sa.CheckConstraint(
            f"accepted_into IS NULL OR {_in('accepted_into', ACCEPTED_INTO)}", name="ck_scope_candidates_accepted_into"
        ),
        sa.CheckConstraint(
            "(status = 'claimed') = (accepted_into IS NOT NULL)", name="ck_scope_candidates_claimed_destination"
        ),
        sa.CheckConstraint(
            "(accepted_into IS NOT DISTINCT FROM 'engagement') = (engagement_id IS NOT NULL)",
            name="ck_scope_candidates_engagement_destination",
        ),
        sa.UniqueConstraint("root_entity_id", "kind", "value", name="uq_scope_candidates_root_kind_value"),
    )
    op.create_index("ix_scope_candidates_root_status", "scope_candidates", ["root_entity_id", "status"])
    op.execute(_CANDIDATE_GUARD_FUNCTION)
    op.execute(_CANDIDATE_GUARD_TRIGGER)

    op.create_table(
        "scope_signals",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column("candidate_id", UUID(as_uuid=True), sa.ForeignKey("scope_candidates.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("signal_type", sa.Text(), nullable=False),
        sa.Column("anchor_kind", sa.Text(), nullable=False),
        sa.Column("anchor_candidate_id", UUID(as_uuid=True), sa.ForeignKey("scope_candidates.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("anchor_entity_id", UUID(as_uuid=True), sa.ForeignKey("org_entities.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("anchor_user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("via_entity_id", UUID(as_uuid=True), sa.ForeignKey("org_entities.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("evidence_id", UUID(as_uuid=True), sa.ForeignKey("evidence_fetches.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("quote", sa.Text(), nullable=True),
        sa.Column("observer_id", UUID(as_uuid=True), sa.ForeignKey("observers.id"), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(_in("signal_type", SIGNAL_TYPES), name="ck_scope_signals_signal_type"),
        sa.CheckConstraint(_in("anchor_kind", ANCHOR_KINDS), name="ck_scope_signals_anchor_kind"),
        sa.CheckConstraint(
            "(anchor_kind = 'claimed_candidate') = (anchor_candidate_id IS NOT NULL)",
            name="ck_scope_signals_anchor_candidate",
        ),
        sa.CheckConstraint(
            "(anchor_kind = 'filer_filing') = (anchor_entity_id IS NOT NULL)", name="ck_scope_signals_anchor_entity"
        ),
        sa.CheckConstraint(
            "signal_type = 'admin_seed' OR evidence_id IS NOT NULL", name="ck_scope_signals_evidence_required"
        ),
        sa.CheckConstraint("(quote IS NOT NULL) = (evidence_id IS NOT NULL)", name="ck_scope_signals_quote_iff_evidence"),
        sa.CheckConstraint("quote IS NULL OR length(btrim(quote)) > 0", name="ck_scope_signals_quote_nonblank"),
    )
    op.execute(
        "ALTER TABLE scope_signals ADD CONSTRAINT uq_scope_signals_route UNIQUE NULLS NOT DISTINCT "
        "(candidate_id, signal_type, anchor_kind, anchor_candidate_id, anchor_entity_id, evidence_id)"
    )
    op.execute(_SIGNAL_GUARD_FUNCTION)
    op.execute(_SIGNAL_GUARD_TRIGGER)
    op.execute(_SIGNAL_ANCHOR_FUNCTION)
    op.execute(_SIGNAL_ANCHOR_TRIGGER)

    op.create_table(
        "scope_candidate_events",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column("candidate_id", UUID(as_uuid=True), sa.ForeignKey("scope_candidates.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("event", sa.Text(), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("signal_id", UUID(as_uuid=True), sa.ForeignKey("scope_signals.id", ondelete="RESTRICT"), nullable=True),
        sa.CheckConstraint(_in("event", EVENT_KINDS), name="ck_scope_candidate_events_event"),
    )
    op.create_index("ix_scope_candidate_events_candidate", "scope_candidate_events", ["candidate_id", "at"])
    op.execute(_EVENT_GUARD_FUNCTION)
    op.execute(_EVENT_GUARD_TRIGGER)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_scope_candidate_events_append_only ON scope_candidate_events")
    op.execute("DROP FUNCTION IF EXISTS scope_candidate_events_append_only()")
    op.drop_index("ix_scope_candidate_events_candidate", table_name="scope_candidate_events")
    op.drop_table("scope_candidate_events")
    op.execute("DROP TRIGGER IF EXISTS trg_scope_signals_anchor ON scope_signals")
    op.execute("DROP FUNCTION IF EXISTS scope_signals_anchor_check()")
    op.execute("DROP TRIGGER IF EXISTS trg_scope_signals_guard ON scope_signals")
    op.execute("DROP FUNCTION IF EXISTS scope_signals_guard()")
    op.drop_table("scope_signals")
    op.execute("DROP TRIGGER IF EXISTS trg_scope_candidates_guard ON scope_candidates")
    op.execute("DROP FUNCTION IF EXISTS scope_candidates_guard()")
    op.drop_index("ix_scope_candidates_root_status", table_name="scope_candidates")
    op.drop_table("scope_candidates")

    op.create_table(
        "candidate_domains",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column("entity_id", UUID(as_uuid=True), sa.ForeignKey("org_entities.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("domain", sa.Text(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("observer_id", UUID(as_uuid=True), sa.ForeignKey("observers.id"), nullable=True),
        sa.Column("evidence_id", UUID(as_uuid=True), sa.ForeignKey("evidence_fetches.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("quote", sa.Text(), nullable=False),
        sa.Column("first_cited_on", sa.Date(), nullable=True),
        sa.Column("last_cited_on", sa.Date(), nullable=True),
        sa.Column("status", sa.Text(), nullable=False, server_default=sa.text("'proposed'")),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decided_by_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("engagement_id", UUID(as_uuid=True), sa.ForeignKey("engagements.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("accepted_into", sa.Text(), nullable=True),
        sa.Column("target_id", UUID(as_uuid=True), sa.ForeignKey("targets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_by_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(f"domain ~ '{_DOMAIN_REGEX}'", name="ck_candidate_domains_domain_shape"),
        sa.CheckConstraint("domain NOT LIKE 'www.%'", name="ck_candidate_domains_no_www"),
        sa.CheckConstraint("length(btrim(quote)) > 0", name="ck_candidate_domains_quote_nonempty"),
        sa.CheckConstraint("position(domain in lower(quote)) > 0", name="ck_candidate_domains_quote_contains_domain"),
        sa.CheckConstraint("source IN ('edgar_10k_website', 'person')", name="ck_candidate_domains_source"),
        sa.CheckConstraint("(source = 'person') = (observer_id IS NULL)", name="ck_candidate_domains_source_observer"),
        sa.CheckConstraint("status IN ('proposed', 'accepted', 'rejected')", name="ck_candidate_domains_status"),
        sa.CheckConstraint("(status = 'proposed') = (decided_at IS NULL)", name="ck_candidate_domains_decided_at"),
        sa.CheckConstraint("target_id IS NULL OR status = 'accepted'", name="ck_candidate_domains_target"),
        sa.CheckConstraint(
            "first_cited_on IS NULL OR last_cited_on >= first_cited_on", name="ck_candidate_domains_cited_order"
        ),
        sa.CheckConstraint(
            "(status = 'accepted') = (accepted_into IS NOT NULL) "
            "AND (accepted_into IS NULL OR accepted_into IN ('engagement', 'estate'))",
            name="ck_candidate_domains_accepted_into",
        ),
        sa.CheckConstraint(
            "(accepted_into IS NOT DISTINCT FROM 'engagement') = (engagement_id IS NOT NULL)",
            name="ck_candidate_domains_engagement_destination",
        ),
        sa.UniqueConstraint("entity_id", "domain", name="uq_candidate_domains_entity_domain"),
    )
    op.create_index("ix_candidate_domains_status", "candidate_domains", ["status"])
    op.execute(_OLD_GUARD_FUNCTION)
    op.execute(_OLD_GUARD_TRIGGER)
