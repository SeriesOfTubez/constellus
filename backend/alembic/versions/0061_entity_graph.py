"""Corporate entity graph (L3, planning#212).

Constellus can flag that two targets share a name, an SSL cert, or a WHOIS
org, but it has no notion of the CORPORATE entities behind them — the fact
that "Example Holdings A" acquired "Widgetco Corp" on a given date, sourced
from an SEC filing or a Wayback-captured press release. This migration lays
the entity graph L3 needs: named entities (`org_entities`), the raw bytes
and fetch metadata that back every claim about them (`evidence_blobs` +
`evidence_fetches`), and one row per SOURCE ASSERTION about a relationship
between two entities (`entity_relations`) — never a merged "asset_edges"
row, because two independent sources for the same acquisition are two
different pieces of evidence, not one fact to overwrite.

## Rule 0 (Jason, decided, do not re-litigate): AI raises attention, never
scope, never lowers

An `inferred`-trust observer (an LLM extractor, a heuristic classifier) may
PROPOSE a relation. It may never CONFIRM one, and it may never REJECT one —
confirmation and rejection are both "a human or a sufficiently-trusted
source decided this", and `inferred` is neither. A `derived`/`observed`
SEC-filing observer may be granted auto-confirmation; a Wayback-sourced
observer, though also `observed`, may not (§2.1) — trust alone cannot
express that distinction (both are `observed`), so the grant is per-observer,
not per-trust-tier (finding 1 below).

## Why this can't just key off `observers.trust`

1. `trust = 'inferred'` is not "AI" — `shodan`, `hosting_classifier`,
   `tenancy_enricher`, `tenancy_ptr`, `tenancy_tls` are all `inferred` too,
   and keying the gate on trust is conservative-safe but too coarse:
   trust cannot express "SEC filing yes, Wayback capture no" when both are
   `observed`. A per-observer boolean grant (`confirms_relations`) is
   needed, guarded so it can never land on an `inferred` observer
   (`ck_observers_inferred_never_confirms`).
2. A CHECK constraint cannot read another table. Whether an observer may
   auto-confirm lives on `observers`; the decision lives on
   `entity_relations`. The grant is therefore DENORMALISED onto the
   relation row (`entity_relations.observer_confirms`) and pinned to its
   source of truth with a COMPOSITE FK — `(observer_id, observer_confirms)`
   references `observers(id, confirms_relations)` — so the copy cannot
   disagree with the observer it was copied from. `ON UPDATE CASCADE` means
   revoking an observer's grant cascades `false` into every row that copied
   `true`; any of those rows with `decision_kind = 'source'` then fails
   `ck_entity_relations_decision` and the UPDATE is refused. That is
   intended: an admin who revokes a source's trust must re-decide its
   already-auto-confirmed rows by hand, not have them silently keep
   standing on a source this system no longer trusts.
3. `decided_by_id` cannot carry the invariant, for the same reason
   `engagements.authorised_by_id` (migration 0059) is deliberately outside
   ITS CHECK: it is `ON DELETE SET NULL` against `users`, so a deleted
   user's row disappearing must not flip a live CHECK and brick every
   future UPDATE of the relation. The gate keys on `decision_kind` +
   `decided_at`, which are never `SET NULL`; `decided_by_id` is
   informational only.
4. Postgres 18.6 (this stack's version) ships `sha256(bytea)` as a built-in
   IMMUTABLE function, so `evidence_blobs`'s integrity CHECK
   (`sha256 = sha256(content)`) can be enforced by the database itself, not
   trusted to whatever inserted the row.

## The gate: `ck_entity_relations_decision`

    (status = 'proposed'  AND decision_kind IS NULL AND decided_at IS NULL)
    OR (status = 'rejected'  AND decision_kind = 'person' AND decided_at IS NOT NULL)
    OR (status = 'confirmed' AND decided_at IS NOT NULL
        AND (decision_kind = 'person' OR (decision_kind = 'source')))

Rejection always needs a person (finding: AI never lowers, and rejecting a
proposed relation IS a form of lowering what's on record). Auto-confirmation
needs a granted observer. An `inferred` observer can never hold that grant
(`ck_observers_inferred_never_confirms`), so an AI-sourced claim can never
confirm a relation without a person — by construction, not by a code path
that could be bypassed by calling the service function differently.

## The trigger: `trg_entity_relations_no_demotion`

"Never lowers" needs OLD, which a row-local CHECK cannot see — hence a
BEFORE UPDATE trigger (same precedent as `asset_edges_validate_endpoints`,
migration 0016), raising whenever `OLD.status <> 'proposed' AND NEW.status
= 'proposed'`. Its practical target is the ingest upsert: re-running an
extractor over the same source must not use `ON CONFLICT DO UPDATE SET
status = ...`, because that would silently re-propose an already-decided
row and erase a person's decision. Ingest (L4/L5, not built here) must use
`ON CONFLICT DO NOTHING` — the unique constraint on `(subject_id, object_id,
relation, observer_id, evidence_id)` already makes a re-ingest of the same
source assertion a no-op.

## `org_entities` has no `aliases` column (deviation from the issue body)

A `dba` / `formerly_named` name is itself an `org_entities` row, joined to
the canonical entity by a SOURCED `entity_relations` row. An unsourced
alias array on the entity itself would be exactly the "undifferentiated
blob" this schema exists to replace — nothing would record WHO asserted the
alias or WHEN. Entities are never auto-merged by name for the same reason:
`legal_name` carries no uniqueness constraint at all, and `cik` (zero-padded
10-digit SEC identifier) is the only automatic identity key.

## Why `evidence_blobs` and `evidence_fetches` are two tables, not one

Deduplicating content by its sha256 hash is correct — two fetches of
byte-identical bytes should not store the bytes twice — but a single table
keyed by hash would then lose the SECOND (url, time) observation of those
same bytes. That is not hypothetical: Wayback's raw (`id_`) capture mode
returns byte-identical content for every capture of an unchanged page, and
for planning#214 the capture TIMESTAMP is itself the evidence (it is what
lets a later reader tell that a fact was already public as of that date).
`evidence_fetches` therefore carries the (url, time) axis and points at the
shared blob; `UNIQUE (source_url, sha256)` makes re-fetching identical bytes
from the same URL idempotent without losing a distinct URL or a distinct
time.

## FKs onto existing tables

`targets.entity_id` and `engagements.subject_entity_id` (the latter added as
a bare, FK-less uuid column by migration 0059 in anticipation of this one)
both point at `org_entities` `ON DELETE RESTRICT`, matching 0059's own
rationale for `targets.engagement_id`: deleting an entity out from under
attributed targets/engagements must not silently strip that attribution.

## No observer rows seeded here

The SEC-filing, Wayback and LLM-extractor observers are seeded by
planning#213/#214/#215 alongside the code that IS them. Seeding them here,
by analogy, before their real behaviour exists risks exactly the
mis-classification planning#198 already burned this codebase once for.
Tests in this slice create and delete their own throwaway observers by id.

Revision ID: 0061
Revises: 0060
Create Date: 2026-09-24
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0061"
down_revision = "0060"
branch_labels = None
depends_on = None


# ── Vocabularies (mirrors the frozensets in app/models/entity_relation.py) ──
RELATION_TYPES = ("acquired", "subsidiary_of", "dba", "formerly_named")
EVENT_DATE_PRECISIONS = ("day", "month", "year", "unknown")
DECISION_KINDS = ("person", "source")
RELATION_STATUSES = ("proposed", "confirmed", "rejected")
GROUNDING_VALUES = ("verified", "not_applicable")

# The decision gate is a fixed boolean formula, not a vocabulary-membership
# check, so it is one static literal (matching 0059's
# `ck_engagements_authorisation_matches_posture`) rather than built from a
# tuple loop.
_DECISION_CHECK = (
    "(status = 'proposed' AND decision_kind IS NULL AND decided_at IS NULL) "
    "OR (status = 'rejected' AND decision_kind = 'person' AND decided_at IS NOT NULL) "
    "OR (status = 'confirmed' AND decided_at IS NOT NULL "
    "AND (decision_kind = 'person' OR (decision_kind = 'source' AND observer_confirms)))"
)

_TRIGGER_FUNCTION_SQL = """
CREATE OR REPLACE FUNCTION entity_relations_no_demotion()
RETURNS trigger AS $$
BEGIN
    IF OLD.status <> 'proposed' AND NEW.status = 'proposed' THEN
        RAISE EXCEPTION
            'entity_relations.status cannot be demoted from % back to proposed (row %)',
            OLD.status, OLD.id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""

_TRIGGER_SQL = """
CREATE TRIGGER trg_entity_relations_no_demotion
BEFORE UPDATE ON entity_relations
FOR EACH ROW EXECUTE FUNCTION entity_relations_no_demotion();
"""


def upgrade() -> None:
    # ── observers.confirms_relations — the per-observer auto-confirm grant ──
    op.add_column(
        "observers",
        sa.Column("confirms_relations", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.create_check_constraint(
        "ck_observers_inferred_never_confirms",
        "observers",
        "NOT confirms_relations OR trust <> 'inferred'",
    )
    # Target of the composite FK below — Postgres requires a unique
    # constraint on exactly the referenced column tuple.
    op.create_unique_constraint(
        "uq_observers_id_confirms_relations", "observers", ["id", "confirms_relations"],
    )

    # ── org_entities ─────────────────────────────────────────────────────────
    op.create_table(
        "org_entities",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column("legal_name", sa.Text(), nullable=False),
        sa.Column("cik", sa.Text(), nullable=True),
        sa.Column("lei", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.CheckConstraint("length(btrim(legal_name)) > 0", name="ck_org_entities_legal_name_not_blank"),
        sa.CheckConstraint("cik ~ '^[0-9]{10}$'", name="ck_org_entities_cik_format"),
        sa.CheckConstraint("lei ~ '^[A-Z0-9]{18}[0-9]{2}$'", name="ck_org_entities_lei_format"),
        sa.UniqueConstraint("cik", name="uq_org_entities_cik"),
        sa.UniqueConstraint("lei", name="uq_org_entities_lei"),
    )

    # ── evidence_blobs — content, stored once, integrity checked by the DB ──
    op.create_table(
        "evidence_blobs",
        sa.Column("sha256", sa.LargeBinary(), primary_key=True),
        sa.Column("content", sa.LargeBinary(), nullable=False),
        sa.Column("content_type", sa.Text(), nullable=False),
        sa.Column("byte_length", sa.Integer(), nullable=False),
        # PG 18 ships sha256(bytea) as a built-in IMMUTABLE function — the DB
        # verifies the stored hash matches the stored bytes, not just trusts
        # whatever inserted the row.
        sa.CheckConstraint("sha256 = sha256(content)", name="ck_evidence_blobs_sha256_matches_content"),
        sa.CheckConstraint(
            "byte_length = octet_length(content) AND byte_length <= 10485760",
            name="ck_evidence_blobs_byte_length",
        ),
    )

    # ── evidence_fetches — one row per (URL, content) observation ──────────
    op.create_table(
        "evidence_fetches",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column(
            "sha256", sa.LargeBinary(),
            sa.ForeignKey("evidence_blobs.sha256", ondelete="RESTRICT"), nullable=False,
        ),
        sa.Column("source_url", sa.Text(), nullable=False),
        # No default — the fetcher states the time it fetched, never "now".
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("source_url ~ '^https?://'", name="ck_evidence_fetches_source_url_scheme"),
        sa.UniqueConstraint("source_url", "sha256", name="uq_evidence_fetches_source_url_sha256"),
    )

    # ── entity_relations — one row per source assertion ─────────────────────
    relation_check = " OR ".join(f"relation = '{v}'" for v in RELATION_TYPES)
    precision_check = " OR ".join(f"event_date_precision = '{v}'" for v in EVENT_DATE_PRECISIONS)
    decision_kind_check = " OR ".join(f"decision_kind = '{v}'" for v in DECISION_KINDS)
    status_check = " OR ".join(f"status = '{v}'" for v in RELATION_STATUSES)
    grounding_check = " OR ".join(f"grounding = '{v}'" for v in GROUNDING_VALUES)

    op.create_table(
        "entity_relations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column("subject_id", UUID(as_uuid=True), sa.ForeignKey("org_entities.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("object_id", UUID(as_uuid=True), sa.ForeignKey("org_entities.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("relation", sa.Text(), nullable=False),
        # No default — fact time, never observation time.
        sa.Column("event_date", sa.Date(), nullable=True),
        sa.Column("event_date_precision", sa.Text(), nullable=False),
        sa.Column("observer_id", UUID(as_uuid=True), nullable=False),
        sa.Column("observer_confirms", sa.Boolean(), nullable=False),
        sa.Column("evidence_id", UUID(as_uuid=True), sa.ForeignKey("evidence_fetches.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("quote", sa.Text(), nullable=False),
        sa.Column("grounding", sa.Text(), nullable=True),
        sa.Column("status", sa.Text(), nullable=False, server_default=sa.text("'proposed'")),
        sa.Column("decision_kind", sa.Text(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decided_by_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("subject_id <> object_id", name="ck_entity_relations_subject_ne_object"),
        sa.CheckConstraint(relation_check, name="ck_entity_relations_relation"),
        sa.CheckConstraint(precision_check, name="ck_entity_relations_event_date_precision"),
        sa.CheckConstraint(
            "(event_date_precision = 'unknown') = (event_date IS NULL)",
            name="ck_entity_relations_precision_matches_event_date",
        ),
        sa.CheckConstraint(decision_kind_check + " OR decision_kind IS NULL", name="ck_entity_relations_decision_kind"),
        sa.CheckConstraint(status_check, name="ck_entity_relations_status"),
        sa.CheckConstraint(grounding_check + " OR grounding IS NULL", name="ck_entity_relations_grounding"),
        sa.CheckConstraint("length(btrim(quote)) > 0", name="ck_entity_relations_quote_not_blank"),
        sa.CheckConstraint(_DECISION_CHECK, name="ck_entity_relations_decision"),
        sa.UniqueConstraint(
            "subject_id", "object_id", "relation", "observer_id", "evidence_id",
            name="uq_entity_relations_subject_object_relation_observer_evidence",
        ),
        sa.ForeignKeyConstraint(
            ["observer_id", "observer_confirms"],
            ["observers.id", "observers.confirms_relations"],
            onupdate="CASCADE",
            name="fk_entity_relations_observer_confirms",
        ),
    )
    op.create_index(
        "ix_entity_relations_status_proposed", "entity_relations", ["status"],
        postgresql_where=sa.text("status = 'proposed'"),
    )
    op.create_index("ix_entity_relations_subject_id", "entity_relations", ["subject_id"])
    op.create_index("ix_entity_relations_object_id", "entity_relations", ["object_id"])

    # ── the demotion-guard trigger (precedent: migration 0016) ──────────────
    op.execute(_TRIGGER_FUNCTION_SQL)
    op.execute(_TRIGGER_SQL)

    # ── FKs onto existing tables ─────────────────────────────────────────────
    op.add_column(
        "targets",
        sa.Column("entity_id", UUID(as_uuid=True), sa.ForeignKey("org_entities.id", ondelete="RESTRICT"), nullable=True),
    )
    op.create_index("ix_targets_entity_id", "targets", ["entity_id"])

    # `engagements.subject_entity_id` already exists (migration 0059) as a
    # bare, FK-less uuid — add the FK now that org_entities exists.
    op.create_foreign_key(
        "fk_engagements_subject_entity_id", "engagements", "org_entities",
        ["subject_entity_id"], ["id"], ondelete="RESTRICT",
    )


def downgrade() -> None:
    op.drop_constraint("fk_engagements_subject_entity_id", "engagements", type_="foreignkey")

    op.drop_index("ix_targets_entity_id", table_name="targets")
    op.drop_column("targets", "entity_id")

    op.execute("DROP TRIGGER IF EXISTS trg_entity_relations_no_demotion ON entity_relations")
    op.execute("DROP FUNCTION IF EXISTS entity_relations_no_demotion()")

    op.drop_index("ix_entity_relations_object_id", table_name="entity_relations")
    op.drop_index("ix_entity_relations_subject_id", table_name="entity_relations")
    op.drop_index("ix_entity_relations_status_proposed", table_name="entity_relations")
    op.drop_table("entity_relations")

    op.drop_table("evidence_fetches")
    op.drop_table("evidence_blobs")
    op.drop_table("org_entities")

    op.drop_constraint("uq_observers_id_confirms_relations", "observers", type_="unique")
    op.drop_constraint("ck_observers_inferred_never_confirms", "observers", type_="check")
    op.drop_column("observers", "confirms_relations")
