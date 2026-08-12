"""Strip the legacy `naabu_ports` key from asset_metadata.

Pre-refactor naabu wrote a `naabu_ports: "53,80"` shallow string into the
ip_address metadata. The new connector only writes structured `open_ports[]`
entries; the legacy key is redundant and the writer's "fill if empty" merge
rule means it would otherwise persist forever.

Idempotent — `metadata - 'naabu_ports'` is a no-op when the key isn't
present. Same trick covers any row that picked up the legacy key from a
mid-migration scan.
"""

from alembic import op

revision = "0030"
down_revision = "0029"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "UPDATE assets_canonical "
        "SET metadata = metadata - 'naabu_ports' "
        "WHERE metadata ? 'naabu_ports'"
    )


def downgrade() -> None:
    # No-op — the legacy field was never load-bearing.
    pass
