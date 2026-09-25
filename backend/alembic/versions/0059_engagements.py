"""The engagement object — replaces `targets.ma_pre_close` (planning#211).

## Why a table, not a wider enum column on `targets`

planning#193 shipped posture as a bare boolean on `targets` because the
object it was actually gesturing at — a named, auditable unit of "we are
diligencing/onboarding/have abandoned this acquisition" — did not exist
yet. This migration builds that object and REPLACES the boolean: `targets`
now points at `engagements` via a nullable FK, and posture is read from the
engagement, never stored redundantly on the target. Keeping both and ORing
them would give posture two writers, which is exactly the drift
planning#196 spent a whole issue removing (see `app.services.posture`'s
module docstring) — planning#211's own decision record says so explicitly
and this migration holds that line.

## The posture enum and the restricting set

Four values: `pre_close`, `day_0`, `integrated`, `abandoned`. Only
`pre_close` and `abandoned` RESTRICT traffic (passive-only) — the
restricting set lives in `app.services.posture.RESTRICTING_POSTURES`, not
here, because a migration is frozen history that must not import app code
that can change under it (the same discipline 0058's docstring states for
its own three CHECK-backed tuples). `_RESTRICTING_POSTURES` below is this
migration's OWN literal copy, used only for the backfill/downgrade data
migrations — keep it in sync with `posture.py` by hand.

`abandoned` restricts FOREVER (terminal, no transition out) and stops
SCHEDULED scans of its member targets (`scan_executor._resolve_dynamic_
scope`) — deleting targets is a separate, explicit human action, never a
side effect of a posture change.

## `ck_engagements_authorisation_matches_posture`

`(posture IN ('day_0','integrated')) = (authorised_at IS NOT NULL AND
authorisation_reference IS NOT NULL)`. This is the invariant that makes the
row's authorisation fields a claim about the CURRENT posture, not a
historical record of some past widening. The fields are set iff the
engagement is in a widened (non-restricting) state; demotion (any state ->
`pre_close`) clears them immediately — the audit log keeps the "who/when"
history, this row only ever describes "as of right now". A `pre_close` row
carrying a stale `authorised_at` would read as "authorised", and it is not.
`authorised_by_id` is deliberately NOT part of this CHECK: it is `ON DELETE
SET NULL` against `users`, so a deleted authorising user must not be able
to flip a live CHECK constraint and break every future UPDATE of that row.

## `targets.engagement_id` is `ON DELETE RESTRICT`

Deliberate, unlike every other FK off `targets` in this schema. Deleting an
engagement out from under linked targets would silently NULL their
posture — a widening with no operator decision behind it. An admin who
wants to stop restricting those targets must detach them first (through
`patch_target`'s widening-rule audit trail, planning#211 §7), which is the
explicit action this schema wants to force.

## Backfill

One engagement per `ma_pre_close = true` target, `pre_close`, named
`f"Pre-close {target.id}"` — the id, not the target's value: names end up
rendered in the UI and written to logs, and a target's value can itself be
sensitive (see `feedback_real_customer_data` — never mint a name from
scan-derived data). `posture_changed_at = now()` at backfill time, since
there is no earlier timestamp to attribute the state to. Then `targets.
ma_pre_close` is dropped — this migration is the whole cutover, not a
staged one, per planning#211 decision 1 ("no OR of old and new").

## Downgrade

Lossy, on purpose. Re-adds `ma_pre_close boolean NOT NULL default false`
and sets it `true` wherever the target's linked engagement's posture is in
`_RESTRICTING_POSTURES` — `day_0`/`integrated` engagements downgrade to
`false` (a boolean cannot represent "widened with a recorded
authorisation"), and every engagement's name, authorisation record and
`abandoned` distinction from `pre_close` is discarded. Acceptable: the
boolean this migration is undoing could never represent any of that in the
first place, so nothing downgrade destroys was ever expressible pre-0059.

Revision ID: 0059
Revises: 0058
Create Date: 2026-09-23
"""

import uuid
from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0059"
down_revision = "0058"
branch_labels = None
depends_on = None

_POSTURES = ("pre_close", "day_0", "integrated", "abandoned")
# This migration's own frozen copy — see module docstring, "restricting set".
_RESTRICTING_POSTURES = ("pre_close", "abandoned")
_WIDENING_POSTURES = ("day_0", "integrated")


# Lightweight `sa.table()` handles for the data steps — Core, never
# runtime-built `sa.text()` (Semgrep `avoid-sqlalchemy-text` blocks that).
def _targets_table(*extra: sa.Column) -> sa.Table:
    return sa.table("targets", sa.column("id", UUID(as_uuid=True)), sa.column("engagement_id", UUID(as_uuid=True)), *extra)


def _engagements_table() -> sa.Table:
    return sa.table(
        "engagements",
        sa.column("id", UUID(as_uuid=True)),
        sa.column("name", sa.String()),
        sa.column("posture", sa.String()),
        sa.column("posture_changed_at", sa.DateTime(timezone=True)),
    )


def upgrade() -> None:
    posture_check = " OR ".join(f"posture = '{v}'" for v in _POSTURES)
    widening_check = " OR ".join(f"posture = '{v}'" for v in _WIDENING_POSTURES)

    op.create_table(
        "engagements",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("posture", sa.String(20), nullable=False, server_default=sa.text("'pre_close'")),
        # No FK yet — L3 (planning#212) adds the entity-graph table and
        # points this at it. Bare nullable uuid until then.
        sa.Column("subject_entity_id", UUID(as_uuid=True), nullable=True),
        sa.Column("created_by_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("authorised_by_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("authorised_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("authorisation_reference", sa.Text(), nullable=True),
        sa.Column("posture_changed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(posture_check, name="ck_engagements_posture"),
        sa.CheckConstraint(
            f"({widening_check}) = (authorised_at IS NOT NULL AND authorisation_reference IS NOT NULL)",
            name="ck_engagements_authorisation_matches_posture",
        ),
    )

    op.add_column(
        "targets",
        sa.Column("engagement_id", UUID(as_uuid=True), sa.ForeignKey("engagements.id", ondelete="RESTRICT"), nullable=True),
    )
    op.create_index("ix_targets_engagement_id", "targets", ["engagement_id"])

    # `scope_target_engagements` — see `app.models.scan.ScanRun`'s own
    # comment for the exact semantics ("named in scope", not "every asset
    # this run touched"). Lands in this migration because it is planning#211
    # scope too, same commit as the object it records.
    from sqlalchemy.dialects.postgresql import JSONB

    op.add_column(
        "scan_runs",
        sa.Column("scope_target_engagements", JSONB(), nullable=False, server_default=sa.text("'[]'")),
    )

    # ── backfill: one engagement per ma_pre_close=true target ──────────────
    conn = op.get_bind()
    now = datetime.now(timezone.utc)
    targets = _targets_table(sa.column("ma_pre_close", sa.Boolean()))
    engagements = _engagements_table()
    rows = conn.execute(sa.select(targets.c.id).where(targets.c.ma_pre_close.is_(True))).fetchall()
    for (target_id,) in rows:
        engagement_id = uuid.uuid4()
        conn.execute(
            engagements.insert().values(
                id=engagement_id, name=f"Pre-close {target_id}", posture="pre_close", posture_changed_at=now,
            )
        )
        conn.execute(targets.update().where(targets.c.id == target_id).values(engagement_id=engagement_id))

    op.drop_column("targets", "ma_pre_close")


def downgrade() -> None:
    op.drop_column("scan_runs", "scope_target_engagements")

    op.add_column(
        "targets",
        sa.Column("ma_pre_close", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )

    conn = op.get_bind()
    targets = _targets_table(sa.column("ma_pre_close", sa.Boolean()))
    engagements = _engagements_table()
    conn.execute(
        targets.update()
        .where(
            targets.c.engagement_id.in_(
                sa.select(engagements.c.id).where(engagements.c.posture.in_(_RESTRICTING_POSTURES))
            )
        )
        .values(ma_pre_close=True)
    )

    op.drop_index("ix_targets_engagement_id", table_name="targets")
    op.drop_column("targets", "engagement_id")
    op.drop_table("engagements")
