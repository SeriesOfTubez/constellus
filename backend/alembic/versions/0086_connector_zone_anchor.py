"""Connector-instance trust anchor + connector claims (planning#277 S1b connector_zone).

Decisions: planning#277 comments 6387321196 and 6387392868.

## `scope_signals`: fourth anchor kind `connector_instance`

- `anchor_connector_instance_id` (FK `connector_instances`, ON DELETE
  RESTRICT: disable is the normal path, deletion is planning#291).
- `ck_scope_signals_anchor_kind` widened; `ck_scope_signals_anchor_connector_instance`:
  the kind and the column come together.
- `ck_scope_signals_connector_zone`: `connector_zone` signals, and only they,
  use the `connector_instance` anchor.
- `uq_scope_signals_route` gains the column (still NULLS NOT DISTINCT).
- `scope_signals_guard()`: the column is immutable like the other anchors.
- `scope_signals_anchor_check()` (BEFORE INSERT) gains a branch: the instance
  must exist and be bound to the candidate's root organization at the time
  the signal is written. A later rebind leaves old signals in place (the
  trigger is insert-only).

## `scope_candidates.decided_by_connector_instance_id`

A claim made by a connector instance (a credentialed zone listing) rather
than by a person. FK RESTRICT. `ck_scope_candidates_connector_decider`: set
only on a claimed row. `ck_scope_candidates_one_decider`: never together with
`decided_by_id` (which stays ON DELETE SET NULL, so "exactly one" cannot be a
CHECK).

## `scope_candidate_events.connector_instance_id`

Names the connector on its `claimed` event (FK RESTRICT). CHECK: only on a
`claimed` event with no user. The append-only guard is re-created so the new
column cannot be rewritten through the `user_id` SET NULL escape hatch.

## `connector_zone_clashes`

A zone a connector instance listed but did not act on, for a person to look
at. `reason`:
- `claimed_by_other_org`: a candidate for the zone is claimed under a
  different root (`conflicting_candidate_id`).
- `target_in_other_scope`: a target for the zone exists in a different scope
  than the instance's (`conflicting_target_id`).
- `target_other_entity`: the target is attributed to a different entity
  (`conflicting_target_id`).
- `not_a_claimable_domain`: the provider's zone is not a hostname, or its
  canonical form differs from the claimable form (e.g. a `www.` zone, whose
  control does not prove control of the apex). Nothing is claimed.
`instance_id` is ON DELETE CASCADE (a clash describes its instance); the
conflicting ids are SET NULL, so no CHECK ties them to `reason`.
`uq_connector_zone_clashes_open`: one unresolved row per (instance, zone).
`resolved_at` is set when a later sync no longer sees the clash.

## Downgrade

Refuses while any row uses the new columns (connector-anchored signals,
connector claims or events); otherwise drops everything and restores 0084's
guard, 0083's anchor trigger and event guard.

Revision ID: 0086
Revises: 0085
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0086"
down_revision = "0085"
branch_labels = None
depends_on = None

# Mirrored in app.models.scope_candidate.ANCHOR_KINDS.
ANCHOR_KINDS = ("claimed_candidate", "filer_filing", "person", "connector_instance")
OLD_ANCHOR_KINDS = ("claimed_candidate", "filer_filing", "person")
# Mirrored in app.models.connector_zone_clash.CLASH_REASONS.
CLASH_REASONS = (
    "claimed_by_other_org", "target_in_other_scope", "target_other_entity", "not_a_claimable_domain",
)


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


def _signal_guard(with_connector: bool) -> str:
    extra = (
        "        OR NEW.anchor_connector_instance_id IS DISTINCT FROM OLD.anchor_connector_instance_id\n"
        if with_connector else ""
    )
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
{extra}        OR (NEW.anchor_user_id IS DISTINCT FROM OLD.anchor_user_id AND NEW.anchor_user_id IS NOT NULL)
        OR NEW.via_entity_id IS DISTINCT FROM OLD.via_entity_id
        OR NEW.evidence_id IS DISTINCT FROM OLD.evidence_id
        OR NEW.quote IS DISTINCT FROM OLD.quote
        OR NEW.observer_id IS DISTINCT FROM OLD.observer_id
        OR NEW.matched_values IS DISTINCT FROM OLD.matched_values
        OR NEW.first_seen_at IS DISTINCT FROM OLD.first_seen_at
        OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION
            'scope_signals: only last_seen_at may change (row %)', OLD.id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""


_CONNECTOR_ANCHOR_BRANCH = """
    ELSIF NEW.anchor_kind = 'connector_instance' THEN
        PERFORM 1
        FROM connector_instances i
        JOIN scope_candidates c ON c.id = NEW.candidate_id
        WHERE i.id = NEW.anchor_connector_instance_id
          AND i.bound_entity_id = c.root_entity_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION
                'scope_signals: a connector_instance anchor must be an instance bound to the candidate''s root (instance %, candidate %)',
                NEW.anchor_connector_instance_id, NEW.candidate_id;
        END IF;
"""


def _anchor_function(with_connector: bool) -> str:
    branch = _CONNECTOR_ANCHOR_BRANCH if with_connector else ""
    return f"""
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
        END IF;{branch}
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""


def _event_guard(with_connector: bool) -> str:
    extra = (
        "        AND NEW.connector_instance_id IS NOT DISTINCT FROM OLD.connector_instance_id\n"
        if with_connector else ""
    )
    return f"""
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
{extra}        AND NEW.signal_id IS NOT DISTINCT FROM OLD.signal_id THEN
        RETURN NEW;  -- users.id ON DELETE SET NULL, performed as an UPDATE
    END IF;
    RAISE EXCEPTION 'scope_candidate_events is append-only (% on row %)', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;
"""


_ROUTE_COLUMNS_OLD = "candidate_id, signal_type, anchor_kind, anchor_candidate_id, anchor_entity_id, evidence_id"
_ROUTE_COLUMNS_NEW = (
    "candidate_id, signal_type, anchor_kind, anchor_candidate_id, anchor_entity_id, "
    "anchor_connector_instance_id, evidence_id"
)


def upgrade() -> None:
    # scope_signals
    op.add_column(
        "scope_signals",
        sa.Column(
            "anchor_connector_instance_id", UUID(as_uuid=True),
            sa.ForeignKey("connector_instances.id", ondelete="RESTRICT"), nullable=True,
        ),
    )
    op.create_index("ix_scope_signals_anchor_connector_instance", "scope_signals", ["anchor_connector_instance_id"])
    op.drop_constraint("ck_scope_signals_anchor_kind", "scope_signals", type_="check")
    op.create_check_constraint("ck_scope_signals_anchor_kind", "scope_signals", _in("anchor_kind", ANCHOR_KINDS))
    op.create_check_constraint(
        "ck_scope_signals_anchor_connector_instance", "scope_signals",
        "(anchor_kind = 'connector_instance') = (anchor_connector_instance_id IS NOT NULL)",
    )
    op.create_check_constraint(
        "ck_scope_signals_connector_zone", "scope_signals",
        "(signal_type = 'connector_zone') = (anchor_kind = 'connector_instance')",
    )
    op.execute("ALTER TABLE scope_signals DROP CONSTRAINT uq_scope_signals_route")
    op.execute(
        "ALTER TABLE scope_signals ADD CONSTRAINT uq_scope_signals_route UNIQUE NULLS NOT DISTINCT "
        f"({_ROUTE_COLUMNS_NEW})"
    )
    op.execute(_signal_guard(True))
    op.execute(_anchor_function(True))

    # scope_candidates
    op.add_column(
        "scope_candidates",
        sa.Column(
            "decided_by_connector_instance_id", UUID(as_uuid=True),
            sa.ForeignKey("connector_instances.id", ondelete="RESTRICT"), nullable=True,
        ),
    )
    op.create_index(
        "ix_scope_candidates_decided_by_connector_instance", "scope_candidates", ["decided_by_connector_instance_id"]
    )
    op.create_check_constraint(
        "ck_scope_candidates_connector_decider", "scope_candidates",
        "decided_by_connector_instance_id IS NULL OR status = 'claimed'",
    )
    op.create_check_constraint(
        "ck_scope_candidates_one_decider", "scope_candidates",
        "decided_by_id IS NULL OR decided_by_connector_instance_id IS NULL",
    )

    # scope_candidate_events
    op.add_column(
        "scope_candidate_events",
        sa.Column(
            "connector_instance_id", UUID(as_uuid=True),
            sa.ForeignKey("connector_instances.id", ondelete="RESTRICT"), nullable=True,
        ),
    )
    op.create_check_constraint(
        "ck_scope_candidate_events_connector", "scope_candidate_events",
        "connector_instance_id IS NULL OR (event = 'claimed' AND user_id IS NULL)",
    )
    op.execute(_event_guard(True))

    # connector_zone_clashes
    op.create_table(
        "connector_zone_clashes",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column(
            "instance_id", UUID(as_uuid=True),
            sa.ForeignKey("connector_instances.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("zone", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column(
            "conflicting_candidate_id", UUID(as_uuid=True),
            sa.ForeignKey("scope_candidates.id", ondelete="SET NULL"), nullable=True,
        ),
        sa.Column(
            "conflicting_target_id", UUID(as_uuid=True),
            sa.ForeignKey("targets.id", ondelete="SET NULL"), nullable=True,
        ),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(_in("reason", CLASH_REASONS), name="ck_connector_zone_clashes_reason"),
        sa.CheckConstraint("btrim(zone) <> ''", name="ck_connector_zone_clashes_zone_nonblank"),
        sa.CheckConstraint("last_seen_at >= first_seen_at", name="ck_connector_zone_clashes_seen_order"),
        sa.CheckConstraint(
            "resolved_at IS NULL OR resolved_at >= first_seen_at", name="ck_connector_zone_clashes_resolved_order"
        ),
    )
    op.create_index(
        "uq_connector_zone_clashes_open", "connector_zone_clashes", ["instance_id", "zone"],
        unique=True, postgresql_where=sa.text("resolved_at IS NULL"),
    )
    op.create_index("ix_connector_zone_clashes_instance", "connector_zone_clashes", ["instance_id", "resolved_at"])


def downgrade() -> None:
    bind = op.get_bind()
    in_use = bind.execute(sa.text(
        "SELECT (SELECT count(*) FROM scope_signals WHERE anchor_connector_instance_id IS NOT NULL)"
        " + (SELECT count(*) FROM scope_candidates WHERE decided_by_connector_instance_id IS NOT NULL)"
        " + (SELECT count(*) FROM scope_candidate_events WHERE connector_instance_id IS NOT NULL)"
    )).scalar_one()
    if in_use:
        raise RuntimeError(
            f"0086 downgrade refused: {in_use} rows use connector anchors or connector claims; remove them first"
        )

    op.drop_index("ix_connector_zone_clashes_instance", table_name="connector_zone_clashes")
    op.drop_index("uq_connector_zone_clashes_open", table_name="connector_zone_clashes")
    op.drop_table("connector_zone_clashes")

    op.execute(_event_guard(False))
    op.drop_constraint("ck_scope_candidate_events_connector", "scope_candidate_events", type_="check")
    op.drop_column("scope_candidate_events", "connector_instance_id")

    op.drop_constraint("ck_scope_candidates_one_decider", "scope_candidates", type_="check")
    op.drop_constraint("ck_scope_candidates_connector_decider", "scope_candidates", type_="check")
    op.drop_index("ix_scope_candidates_decided_by_connector_instance", table_name="scope_candidates")
    op.drop_column("scope_candidates", "decided_by_connector_instance_id")

    op.execute(_anchor_function(False))
    op.execute(_signal_guard(False))
    op.execute("ALTER TABLE scope_signals DROP CONSTRAINT uq_scope_signals_route")
    op.execute(
        "ALTER TABLE scope_signals ADD CONSTRAINT uq_scope_signals_route UNIQUE NULLS NOT DISTINCT "
        f"({_ROUTE_COLUMNS_OLD})"
    )
    op.drop_constraint("ck_scope_signals_connector_zone", "scope_signals", type_="check")
    op.drop_constraint("ck_scope_signals_anchor_connector_instance", "scope_signals", type_="check")
    op.drop_constraint("ck_scope_signals_anchor_kind", "scope_signals", type_="check")
    op.create_check_constraint("ck_scope_signals_anchor_kind", "scope_signals", _in("anchor_kind", OLD_ANCHOR_KINDS))
    op.drop_index("ix_scope_signals_anchor_connector_instance", table_name="scope_signals")
    op.drop_column("scope_signals", "anchor_connector_instance_id")
