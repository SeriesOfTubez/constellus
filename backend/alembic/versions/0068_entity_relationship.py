"""A mapped company's relationship to us: ours vs M&A target (planning#240)

Mapping a company (the entity graph) says nothing about what it is TO US,
and that answer decides where its accepted domains go and which AI data
policy its reads run under. Jason, 2026-10-01: an explicit three-state
column, no default.

## Columns on `org_entities`

- `relationship` — NULL (unset: map and browse only; accept is blocked,
  AI reads run strict), `ours` (accepted domains join our own estate), or
  `ma_target` (the subject of at least one engagement).
- `ours_authorised_by_id` / `ours_authorised_at` / `ours_reference` — "ours"
  is an authorisation (it makes domains actively scannable), recorded with
  the same three fields as an engagement's day_0 record.

## `ck_org_entities_relationship`

`relationship IS NULL OR relationship IN ('ours', 'ma_target')`.

## `ck_org_entities_ours_authorisation`

`(relationship IS NOT DISTINCT FROM 'ours') = (ours_authorised_at IS NOT
NULL AND ours_reference IS NOT NULL AND btrim(ours_reference) <> '')`.
`IS NOT DISTINCT FROM`, not `=`: with `=`, an unset (NULL) relationship
makes the left side NULL, the whole CHECK NULL, and a NULL CHECK PASSES, so
an unset row could carry a live-looking authorisation. The fields are set
iff the row is `ours` right now, the same "claim about the current state"
rule as migration 0059's `ck_engagements_authorisation_matches_posture`.
`ours_authorised_by_id` is outside the CHECK for the reason 0059 gives: it
is ON DELETE SET NULL, and a deleted user must not flip a live CHECK.

The engagement-side invariants (`ma_target` iff the subject of at least one
engagement; `ours` never a subject) span two tables, so
`app.services.entity_relationship` enforces them on every write path.

## Backfill

Every entity that is already some engagement's subject becomes `ma_target`
(an engagement subject is an M&A target by definition). Nothing else is
touched: every other row stays unset, the safe direction.

## `candidate_domains.accepted_into` — where an accepted candidate went

An accepted candidate now has two possible destinations: an engagement,
or our own estate (a company that inherits "ours"). 0064's
`ck_candidate_domains_engagement` (`accepted ⇔ engagement_id IS NOT NULL`)
cannot record the second, and a NULL engagement alone would read the same
as "not decided". So the destination is explicit:

- `ck_candidate_domains_accepted_into`: `(status = 'accepted') =
  (accepted_into IS NOT NULL)`, value `engagement` or `estate`.
- `ck_candidate_domains_engagement_destination`: `(accepted_into IS NOT
  DISTINCT FROM 'engagement') = (engagement_id IS NOT NULL)`.

Existing accepted rows are backfilled `engagement` (before 0068 that was
the only destination). `candidate_domains_guard` also freezes
`accepted_into` and `engagement_id` once a row is decided: where a domain
was accepted into is part of the decision, not a later edit.

## Downgrade

Refuses while any candidate was accepted into the estate: 0064's CHECK
cannot represent one, and deleting decisions is not a downgrade's call.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

# Copied, not imported: a migration must not change meaning when an
# earlier one is edited. 0064's guard plus the two destination columns.
_GUARD_FUNCTION_SQL = """
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

_GUARD_FUNCTION_SQL_0064 = """
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

revision = "0068"
down_revision = "0067"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("org_entities", sa.Column("relationship", sa.Text(), nullable=True))
    op.add_column(
        "org_entities",
        sa.Column(
            "ours_authorised_by_id", UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
        ),
    )
    op.add_column("org_entities", sa.Column("ours_authorised_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("org_entities", sa.Column("ours_reference", sa.Text(), nullable=True))
    op.create_check_constraint(
        "ck_org_entities_relationship",
        "org_entities",
        "relationship IS NULL OR relationship IN ('ours', 'ma_target')",
    )
    op.create_check_constraint(
        "ck_org_entities_ours_authorisation",
        "org_entities",
        "(relationship IS NOT DISTINCT FROM 'ours') = "
        "(ours_authorised_at IS NOT NULL AND ours_reference IS NOT NULL AND btrim(ours_reference) <> '')",
    )
    op.execute(
        "UPDATE org_entities SET relationship = 'ma_target' "
        "WHERE id IN (SELECT subject_entity_id FROM engagements WHERE subject_entity_id IS NOT NULL)"
    )

    op.add_column("candidate_domains", sa.Column("accepted_into", sa.Text(), nullable=True))
    # Before the guard is replaced: status and the claim columns are
    # untouched, so the 0064 guard admits this UPDATE.
    op.execute("UPDATE candidate_domains SET accepted_into = 'engagement' WHERE status = 'accepted'")
    op.drop_constraint("ck_candidate_domains_engagement", "candidate_domains", type_="check")
    op.create_check_constraint(
        "ck_candidate_domains_accepted_into",
        "candidate_domains",
        "(status = 'accepted') = (accepted_into IS NOT NULL) "
        "AND (accepted_into IS NULL OR accepted_into IN ('engagement', 'estate'))",
    )
    op.create_check_constraint(
        "ck_candidate_domains_engagement_destination",
        "candidate_domains",
        "(accepted_into IS NOT DISTINCT FROM 'engagement') = (engagement_id IS NOT NULL)",
    )
    op.execute(_GUARD_FUNCTION_SQL)


def downgrade() -> None:
    bind = op.get_bind()
    estate = bind.execute(sa.text("SELECT count(*) FROM candidate_domains WHERE accepted_into = 'estate'")).scalar()
    if estate:
        raise RuntimeError(
            f"{estate} candidate domain(s) were accepted into our estate; migration 0064's CHECK "
            "cannot represent that. Resolve them by hand before downgrading."
        )
    op.execute(_GUARD_FUNCTION_SQL_0064)
    op.drop_constraint("ck_candidate_domains_engagement_destination", "candidate_domains", type_="check")
    op.drop_constraint("ck_candidate_domains_accepted_into", "candidate_domains", type_="check")
    op.drop_column("candidate_domains", "accepted_into")
    op.create_check_constraint(
        "ck_candidate_domains_engagement",
        "candidate_domains",
        "(status = 'accepted') = (engagement_id IS NOT NULL)",
    )
    op.drop_constraint("ck_org_entities_ours_authorisation", "org_entities", type_="check")
    op.drop_constraint("ck_org_entities_relationship", "org_entities", type_="check")
    op.drop_column("org_entities", "ours_reference")
    op.drop_column("org_entities", "ours_authorised_at")
    op.drop_column("org_entities", "ours_authorised_by_id")
    op.drop_column("org_entities", "relationship")
