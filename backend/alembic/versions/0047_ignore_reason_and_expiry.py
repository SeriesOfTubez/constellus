"""Ignore gets a reason and an expiry — suppression stops being permanent.

`assets_canonical.ignored` has been a bare boolean since it was added: no
reason, no author, no review date. That shape has one failure mode and it
is the expensive one — an ignore set once for a reason nobody recorded,
against an asset nobody re-examines, silently suppresses that asset from
the absence query, the hygiene score, and the asset list forever. A wrong
suppression becomes permanent by default, which is the exact opposite of
CLAUDE.md's "fix findings, never suppress; suppressions are a last resort
with strict criteria" — a criterion you cannot read back is not a
criterion.

Borrowed wholesale from Wiz's `DiscoveredResource`, which pairs its
classification with `ignoreReason` (BY_DESIGN | EXCEPTION | FALSE_POSITIVE)
+ `ignoreReasonDetails` + `ignoreExpiresAt` (see Obsidian
`Constellus — Wiz API Reference` §9.1). Their vocabulary is adopted
verbatim rather than reinvented: the three reasons are genuinely the three
that occur, and matching an established vocabulary costs nothing.

Columns added:
  * `ignore_reason`        — CHECK-constrained to the three values above.
  * `ignore_reason_details`— free text, the "why" that the enum can't carry.
  * `ignore_expires_at`    — NULL means indefinite. Note that NULL here is
                             an EXPLICIT choice made at ignore time, not an
                             accidental default: the API requires the caller
                             to pass a reason, and leaving expiry unset is
                             then a deliberate "this is permanent".
  * `ignored_at` / `ignored_by_id` — audit. Who suppressed this, and when.

The load-bearing half of this change is NOT the columns — it is that
`AssetCanonical.suppressed` (a hybrid property, same commit) replaces every
`ignored == False` filter in the read path, so an ignore whose
`ignore_expires_at` has passed stops suppressing on its own without any
sweeper job needing to run. A column nobody reads would be decoration.

Existing rows: `ignored = true` rows predate the reason requirement and are
backfilled to `EXCEPTION` with details recording that they were set before
reasons existed, and a NULL expiry (indefinite) — preserving today's exact
behaviour rather than silently un-ignoring anything on upgrade. They are
findable afterwards via `ignore_reason_details LIKE 'Backfilled%'` if
someone wants to review them.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0047"
down_revision = "0046"
branch_labels = None
depends_on = None

IGNORE_REASONS = ("BY_DESIGN", "EXCEPTION", "FALSE_POSITIVE")


def upgrade() -> None:
    op.add_column("assets_canonical", sa.Column("ignore_reason", sa.Text(), nullable=True))
    op.add_column("assets_canonical", sa.Column("ignore_reason_details", sa.Text(), nullable=True))
    op.add_column(
        "assets_canonical",
        sa.Column("ignore_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "assets_canonical",
        sa.Column("ignored_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column("assets_canonical", sa.Column("ignored_by_id", UUID(as_uuid=True), nullable=True))

    op.create_check_constraint(
        "ck_assets_canonical_ignore_reason",
        "assets_canonical",
        "ignore_reason IS NULL OR ignore_reason IN ('BY_DESIGN', 'EXCEPTION', 'FALSE_POSITIVE')",
    )

    # Partial index: the read path's hot question is "is this suppressed
    # right now", which only ever touches rows where ignored is true.
    op.execute(
        "CREATE INDEX ix_assets_canonical_ignore_expires_at "
        "ON assets_canonical (ignore_expires_at) WHERE ignored"
    )

    # Backfill pre-existing ignores — preserve current behaviour exactly
    # (indefinite), but make them auditable and findable.
    op.execute(
        """
        UPDATE assets_canonical
           SET ignore_reason = 'EXCEPTION',
               ignore_reason_details = 'Backfilled by migration 0047 — this asset was '
                                       'ignored before ignore reasons existed; the original '
                                       'reason was never recorded. Review and re-set with a '
                                       'real reason, or clear the ignore.',
               ignored_at = COALESCE(ignored_at, now())
         WHERE ignored AND ignore_reason IS NULL
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_assets_canonical_ignore_expires_at")
    op.drop_constraint("ck_assets_canonical_ignore_reason", "assets_canonical", type_="check")
    for col in (
        "ignored_by_id",
        "ignored_at",
        "ignore_expires_at",
        "ignore_reason_details",
        "ignore_reason",
    ):
        op.drop_column("assets_canonical", col)
