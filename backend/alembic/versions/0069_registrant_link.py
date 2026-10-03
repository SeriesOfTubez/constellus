"""Link a CIK-less acquired company to its SEC registrant (planning#236 S1)

An acquired company found by the acquisition reader (#218) is mapped
without a CIK (0061: never merge by name). Jason, 2026-10-02: a person
confirms which SEC registrant it is, and the CIK is set on THAT existing
entity (no new entity, no `same_as` edge), so the confirmed `acquired` edge
still reaches it and the ingest that follows attaches its output there.

## Columns on `org_entities`

- `registrant_linked_at` / `registrant_linked_by_id` — set iff this row's
  CIK came from a person-confirmed registrant link. They mark the CIK as
  undoable: unlink applies only to a linked CIK, never to a filer mapped
  directly by ingest (whose CIK is its identity, not a decision).

## `ck_org_entities_registrant_link`

`registrant_linked_at IS NULL OR cik IS NOT NULL`: a link record without a
CIK would claim a link that is not there. `registrant_linked_by_id` is
outside the CHECK for the reason 0059 gives (a deleted user must not flip a
live CHECK); it is `ON DELETE SET NULL`.

No existing row changes: every row starts unlinked.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0069"
down_revision = "0068"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("org_entities", sa.Column("registrant_linked_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "org_entities",
        sa.Column(
            "registrant_linked_by_id", UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
        ),
    )
    op.create_check_constraint(
        "ck_org_entities_registrant_link",
        "org_entities",
        "registrant_linked_at IS NULL OR cik IS NOT NULL",
    )


def downgrade() -> None:
    bind = op.get_bind()
    linked = bind.execute(
        sa.text("SELECT count(*) FROM org_entities WHERE registrant_linked_at IS NOT NULL")
    ).scalar()
    if linked:
        raise RuntimeError(
            f"{linked} entit(y/ies) carry a person-confirmed registrant link; downgrading would "
            "make those CIKs indistinguishable from directly mapped filers. Unlink them first."
        )
    op.drop_constraint("ck_org_entities_registrant_link", "org_entities", type_="check")
    op.drop_column("org_entities", "registrant_linked_by_id")
    op.drop_column("org_entities", "registrant_linked_at")
