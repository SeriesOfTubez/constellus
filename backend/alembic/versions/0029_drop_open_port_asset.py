"""Drop open_port as a first-class asset type.

Naabu (and future tlsx/httpx/banner) now write ports as properties of the
parent ip_address asset under `metadata.open_ports` — a list of
`{port, protocol, sources, last_seen_at, naabu_tier, ...}` dicts merged
by the writer. This matches the model every other EASM uses (Tenable,
Qualys, Shodan, Censys): hosts are inventory; ports are observations
about hosts.

This migration:
  1. Deletes existing `open_port` asset rows (transitional data only).
  2. Deletes `has_open_port` edges (no longer emitted).
  3. Widens the edge_type CHECK constraint to drop `has_open_port`.

No data migration of the port info is needed — the user does destructive
rebuilds when the time comes, and only `scanme.nmap.org`'s two ports
exist today. Re-running naabu repopulates `ip.metadata.open_ports`.
"""

import sqlalchemy as sa
from alembic import op

revision = "0029"
down_revision = "0028"
branch_labels = None
depends_on = None


# New edge-type set (has_open_port removed).
EDGE_TYPES_NEW = (
    "resolves_to",
    "runs_service",
    "has_finding",
    "registered_to",
    "discovered_in_target",
    "belongs_to_apex",
)

EDGE_TYPES_OLD = EDGE_TYPES_NEW + ("has_open_port",)


def upgrade() -> None:
    # Drop edges first so the rows go before the constraint reshapes.
    op.execute("DELETE FROM asset_edges WHERE edge_type = 'has_open_port'")
    op.execute("DELETE FROM assets_canonical WHERE asset_type = 'open_port'")

    op.drop_constraint("ck_asset_edges_edge_type", "asset_edges", type_="check")
    check = " OR ".join(f"edge_type = '{t}'" for t in EDGE_TYPES_NEW)
    op.create_check_constraint("ck_asset_edges_edge_type", "asset_edges", check)


def downgrade() -> None:
    op.drop_constraint("ck_asset_edges_edge_type", "asset_edges", type_="check")
    check = " OR ".join(f"edge_type = '{t}'" for t in EDGE_TYPES_OLD)
    op.create_check_constraint("ck_asset_edges_edge_type", "asset_edges", check)
