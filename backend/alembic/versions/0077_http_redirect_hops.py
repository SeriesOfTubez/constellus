"""HTTP redirect chains, followed through the probe gate (planning#268)

Jason, 2026-10-11 (#268 6115160279):

- `http_redirect_hops` is the chain for one probed endpoint (origin asset,
  port), one row per Location destination. A row is about the HOP's URL, and
  `hop_asset_id` names the hop's own asset. The origin's `open_ports` entry
  keeps only what the origin itself answered (status, title, Location), so no
  hop data is ever attributed to the origin. A relative hop lands on the same
  asset at a different URL, which is why this cannot live on the port entry.
  #267 (endpoints as first-class) is expected to absorb this table.
- `followed` = a request was sent. An unfollowed row still records the URL and
  the reason (the gate's own `rule_fired`, or one of the local refusals below)
  and NO request was sent to it.
- The `redirect` observer is the provenance for a hostname first seen in a
  Location header. It is passive (`addressing = 'none'`, `silent`): recording
  a name sends nothing to it. The fetches themselves are httpx's, under its own
  observer and the gate.

A chain is replaced wholesale when its origin endpoint is re-probed, so rows
are mutable at the chain level; nothing references them.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0077"
down_revision = "0076"
branch_labels = None
depends_on = None

# Local refusals that are not gate rules. A gate denial stores the gate's own
# `rule_fired` verbatim (e.g. `posture:passive_only`, `probe_class:no_probe`),
# so `reason` is deliberately not a closed vocabulary.
_MAX_HOP_INDEX = 6  # 5 followed fetches + the one destination refused by the hop cap


def upgrade() -> None:
    op.create_table(
        "http_redirect_hops",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column(
            "origin_asset_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets_canonical.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("origin_port", sa.Integer(), nullable=False),
        sa.Column("origin_scheme", sa.Text(), nullable=False),
        sa.Column("hop_index", sa.SmallInteger(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column(
            "hop_asset_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets_canonical.id", ondelete="SET NULL"), nullable=True,
        ),
        sa.Column("followed", sa.Boolean(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("http_title", sa.Text(), nullable=True),
        sa.Column("http_location", sa.Text(), nullable=True),
        sa.Column(
            "scan_run_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scan_runs.id", ondelete="SET NULL"), nullable=True,
        ),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("origin_asset_id", "origin_port", "hop_index", name="uq_http_redirect_hops_endpoint_hop"),
        sa.CheckConstraint("origin_port BETWEEN 1 AND 65535", name="ck_http_redirect_hops_port"),
        sa.CheckConstraint("origin_scheme IN ('http', 'https')", name="ck_http_redirect_hops_scheme"),
        sa.CheckConstraint(f"hop_index BETWEEN 1 AND {_MAX_HOP_INDEX}", name="ck_http_redirect_hops_index"),
        sa.CheckConstraint("length(url) BETWEEN 1 AND 2048", name="ck_http_redirect_hops_url"),
        # Followed <=> no refusal reason. A followed hop that failed to answer
        # keeps followed = true with a null status: the request WAS sent.
        sa.CheckConstraint("followed = (reason IS NULL)", name="ck_http_redirect_hops_reason"),
        # Response fields exist only for a request that was sent.
        sa.CheckConstraint(
            "followed OR (http_status IS NULL AND http_title IS NULL AND http_location IS NULL)",
            name="ck_http_redirect_hops_unfollowed_no_response",
        ),
        sa.CheckConstraint(
            "http_status IS NULL OR http_status BETWEEN 100 AND 599", name="ck_http_redirect_hops_status",
        ),
        sa.CheckConstraint("http_title IS NULL OR length(http_title) <= 512", name="ck_http_redirect_hops_title"),
        sa.CheckConstraint(
            "http_location IS NULL OR length(http_location) <= 300", name="ck_http_redirect_hops_location",
        ),
    )
    op.create_index("ix_http_redirect_hops_hop_asset", "http_redirect_hops", ["hop_asset_id"])

    op.execute(
        "INSERT INTO observers (name, kind, trust, addressing, description, noise_class, confirms_relations) "
        "VALUES ('redirect', 'discovery', 'derived', 'none', "
        "'A hostname first seen as an HTTP redirect (Location) destination of a probed endpoint.', "
        "'silent', false)"
    )


def downgrade() -> None:
    # Claims cite observers with a plain FK; remove any redirect-sourced
    # claims' observer reference by refusing loudly rather than cascading
    # through someone's claim history.
    op.execute(
        "DO $$ BEGIN "
        "IF EXISTS (SELECT 1 FROM asset_claims c JOIN observers o ON o.id = c.observer_id "
        "WHERE o.name = 'redirect') THEN "
        "RAISE EXCEPTION '0077 downgrade: asset_claims rows cite the redirect observer; remove them first'; "
        "END IF; END $$"
    )
    op.execute("DELETE FROM observers WHERE name = 'redirect'")
    op.drop_index("ix_http_redirect_hops_hop_asset", table_name="http_redirect_hops")
    op.drop_table("http_redirect_hops")
