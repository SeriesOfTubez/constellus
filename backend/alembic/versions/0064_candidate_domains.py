"""candidate_domains — evidence-only domain candidates, human-accepted into
an engagement (planning#216, L6, MVP slice).

The only way a lineage result ever becomes scan scope. There is no code
path from an entity NAME to a domain: a candidate exists only as a row
citing stored evidence, and a target is created only when a person
accepts one (`app.services.candidate_domains.accept`).

## "A guess cannot be stored" is a DB fact, not a convention

  - `evidence_id` is NOT NULL (FK `evidence_fetches`, RESTRICT).
  - `ck_candidate_domains_quote_contains_domain`: the cited quote must
    literally contain the domain. A citation to a real filing that never
    mentions the domain is refused, so attaching an unrelated piece of
    evidence to a guessed domain does not get it in either.
  - `ck_candidate_domains_domain_shape`: lowercase ASCII hostname, at
    least one dot, alphabetic TLD. No scheme, path, port, IP literal, or
    `www.` prefix (the service strips it).

## Decided rows are frozen — `trg_candidate_domains_guard`

A BEFORE UPDATE trigger (the `trg_entity_relations_no_demotion` pattern,
migration 0061) refuses any `status` change once a row is decided, and any
change to what the row CLAIMS (`entity_id`, `domain`, `source`,
`observer_id`, `evidence_id`, `quote`) at any time. `target_id`,
`decided_by_id`, `last_cited_on` stay writable: the first two are
`ON DELETE SET NULL`, which Postgres performs as an UPDATE that this
trigger also sees; `last_cited_on` is advanced by re-ingest.

## `status` ⇔ decision columns

`decided_at` is set iff the row is decided, and `engagement_id` is set
iff it was accepted (RESTRICT, so it cannot vanish under the CHECK).
`target_id` is one-directional (`target_id IS NULL OR accepted`): deleting
the target is an ordinary operator action and must not break this row.
`decided_by_id` is SET NULL and outside every CHECK, same reasoning as
`engagements.authorised_by_id` (0059) and `entity_relations` (0061).

## `evidence_fetches.origin` — the provenance label

A manual candidate's evidence is an excerpt a PERSON pasted, not bytes
this system fetched. Storing it as an ordinary fetch row would make
`source_url` + `fetched_at` claim "we fetched this URL at this time",
which is false. `origin = 'person_supplied'` says what the row is.
Existing rows default to `fetched`, which is what every one of them is.

## `first_cited_on` / `last_cited_on`

The FILING dates of the first and latest 10-K that named the domain (NULL
for a manual candidate). A domain a filer stopped citing years ago may
since have been sold or lapsed and re-registered by a stranger, so the
reviewer needs to see when the evidence stopped as well as when it
started.

Revision ID: 0064
Revises: 0063
Create Date: 2026-09-26
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0064"
down_revision = "0063"
branch_labels = None
depends_on = None

_OBSERVER_WEBSITE = "edgar_10k_website"

# Labels: 1–63 of [a-z0-9-], not starting/ending with '-'; TLD alphabetic
# (punycode `xn--` TLDs included). Deliberately not full RFC 1035 — the
# service canonicalises first; this is the backstop that a raw insert
# cannot bypass.
_DOMAIN_REGEX = r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,63}|xn--[a-z0-9-]{1,59})$"

_GUARD_FUNCTION_SQL = """
CREATE OR REPLACE FUNCTION candidate_domains_guard()
RETURNS trigger AS $$
BEGIN
    IF OLD.status <> 'proposed' AND NEW.status IS DISTINCT FROM OLD.status THEN
        RAISE EXCEPTION
            'candidate_domains.status cannot change once decided (% -> %, row %)',
            OLD.status, NEW.status, OLD.id;
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

_GUARD_TRIGGER_SQL = """
CREATE TRIGGER trg_candidate_domains_guard
BEFORE UPDATE ON candidate_domains
FOR EACH ROW EXECUTE FUNCTION candidate_domains_guard();
"""


def _observers_table():
    return sa.table(
        "observers",
        sa.column("name", sa.Text()),
        sa.column("kind", sa.Text()),
        sa.column("trust", sa.Text()),
        sa.column("addressing", sa.Text()),
        sa.column("noise_class", sa.Text()),
        sa.column("description", sa.Text()),
        sa.column("confirms_relations", sa.Boolean()),
    )


def upgrade() -> None:
    op.add_column(
        "evidence_fetches",
        sa.Column("origin", sa.Text(), nullable=False, server_default=sa.text("'fetched'")),
    )
    op.create_check_constraint(
        "ck_evidence_fetches_origin", "evidence_fetches", "origin IN ('fetched', 'person_supplied')"
    )

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
        sa.CheckConstraint("(status = 'accepted') = (engagement_id IS NOT NULL)", name="ck_candidate_domains_engagement"),
        sa.CheckConstraint("target_id IS NULL OR status = 'accepted'", name="ck_candidate_domains_target"),
        sa.CheckConstraint(
            "first_cited_on IS NULL OR last_cited_on >= first_cited_on", name="ck_candidate_domains_cited_order"
        ),
        sa.UniqueConstraint("entity_id", "domain", name="uq_candidate_domains_entity_domain"),
    )
    op.create_index("ix_candidate_domains_status", "candidate_domains", ["status"])

    op.execute(_GUARD_FUNCTION_SQL)
    op.execute(_GUARD_TRIGGER_SQL)

    op.bulk_insert(
        _observers_table(),
        [
            {
                "name": _OBSERVER_WEBSITE,
                "kind": "connector",
                "trust": "observed",
                "addressing": "none",
                "noise_class": "silent",
                "confirms_relations": False,
                "description": (
                    "Reads the filer's own website from its 10-K (\"our website is ...\"), "
                    "in the primary document already fetched for the footnote section; "
                    "proposes candidate domains, never targets. Queries the SEC, never "
                    "the counterparty."
                ),
            },
        ],
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_candidate_domains_guard ON candidate_domains")
    op.execute("DROP FUNCTION IF EXISTS candidate_domains_guard()")
    op.drop_index("ix_candidate_domains_status", table_name="candidate_domains")
    op.drop_table("candidate_domains")
    observers = _observers_table()
    op.get_bind().execute(observers.delete().where(observers.c.name == _OBSERVER_WEBSITE))
    op.drop_constraint("ck_evidence_fetches_origin", "evidence_fetches", type_="check")
    op.drop_column("evidence_fetches", "origin")
