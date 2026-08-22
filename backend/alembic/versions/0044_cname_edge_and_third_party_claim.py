"""Activate the `cname` edge type and add the `third_party_dependency` claim
(planning#147 — capture the dns_resolve CNAME boundary target as a node).

`dns_resolve` suppresses the customer→third-party boundary target and
everything past it, so a CNAME pointing at a lapsed or vendor-owned domain
survives only as a `cdn_domain` STRING on the owned record. There is no node
to hang a WHOIS check, takeover fingerprint, or vendor-incident query on.
planning#147 captures that target as a real asset — capture, not modeling.

Two vocabulary additions, both anticipated by migration 0039:

1. `cname` joins the `asset_edges.edge_type` CHECK constraint. 0039 seeded
   `edge_type_relationships` with `cname -> dependency` and noted that
   "several seeded edge_types (cname, spf_include, script_include, ...) are
   not yet in asset_edge.EDGE_TYPES; that's expected, their producers land in
   later epics." planning#147 is the first such producer.

   `cname` is deliberately distinct from the existing `resolves_to`, which is
   DNS mechanics shared with A/AAAA records. Tagging `resolves_to` as a
   dependency would make an A record pointing at our OWN ip_address a
   third-party dependency edge. `cname` carries the attribution axis;
   `resolves_to` stays the plain resolution mechanic, and the boundary hop
   emits `cname` INSTEAD of `resolves_to` so the pair gets one edge, not two.

2. `third_party_dependency` joins `claim_types`. It is what makes the
   captured node's `estate = not_ours` and `probe_class = no_probe` derivable
   in the projector rather than asserted at read time — dns_resolve observed
   the name to be outside every declared target domain, and that observation
   gets an observer and a timestamp like any other claim.

   NOT `affinity_confirmation`: that claim means "we actively probed this and
   the ownership evidence came back rejected". This one means "we never
   probed it at all and never will". Collapsing them would make
   `rejected_shared_infra` unfalsifiable.

Revision ID: 0044
Revises: 0043
Create Date: 2026-08-22
"""

from alembic import op
import sqlalchemy as sa


revision = "0044"
down_revision = "0043"
branch_labels = None
depends_on = None


# Mirrors app/models/asset_edge.py's EDGE_TYPES (companion change, same commit).
_PRIOR_EDGE_TYPES = (
    "resolves_to", "runs_service", "has_finding", "registered_to",
    "discovered_in_target", "belongs_to_apex",
)
_NEW_EDGE_TYPE = "cname"
_ALL_EDGE_TYPES = _PRIOR_EDGE_TYPES + (_NEW_EDGE_TYPE,)

# Mirrors app/models/claim.py's CLAIM_TYPES (companion change, same commit).
_PRIOR_CLAIM_TYPES = (
    "port_observation", "proxy_state", "dns_ttl", "cloudflare_zone",
    "host_tarpit", "hosting_class", "reverse_ip", "spf_policy",
    "mx_preference", "ct_cert_issuance", "shodan_host", "reverse_hostname",
    "affinity_confirmation", "eol_status", "cloud_inventory", "observation",
    "cdn_boundary",
)
_NEW_CLAIM_TYPE = "third_party_dependency"
_ALL_CLAIM_TYPES = _PRIOR_CLAIM_TYPES + (_NEW_CLAIM_TYPE,)

_CLAIM_DESCRIPTION = (
    "This asset is third-party infrastructure a customer-owned record depends "
    "on, captured as context and never probed (estate=not_ours, no_probe)."
)


def upgrade() -> None:
    # ── asset_edges.edge_type += cname ──────────────────────────────────────
    op.drop_constraint("ck_asset_edges_edge_type", "asset_edges", type_="check")
    op.create_check_constraint(
        "ck_asset_edges_edge_type",
        "asset_edges",
        " OR ".join(f"edge_type = '{t}'" for t in _ALL_EDGE_TYPES),
    )

    # ── claim_types += third_party_dependency ───────────────────────────────
    claim_types_table = sa.table(
        "claim_types",
        sa.column("claim_type", sa.Text()),
        sa.column("description", sa.Text()),
    )
    op.bulk_insert(
        claim_types_table,
        [{"claim_type": _NEW_CLAIM_TYPE, "description": _CLAIM_DESCRIPTION}],
    )
    op.drop_constraint("ck_asset_claims_claim_type", "asset_claims", type_="check")
    op.create_check_constraint(
        "ck_asset_claims_claim_type",
        "asset_claims",
        " OR ".join(f"claim_type = '{v}'" for v in _ALL_CLAIM_TYPES),
    )


def downgrade() -> None:
    # Claims first — the CHECK cannot be narrowed while rows violate it, and
    # asset_claims.claim_type is an FK to claim_types.
    op.execute(
        sa.text("DELETE FROM asset_claims WHERE claim_type = :ct").bindparams(ct=_NEW_CLAIM_TYPE)
    )
    op.drop_constraint("ck_asset_claims_claim_type", "asset_claims", type_="check")
    op.create_check_constraint(
        "ck_asset_claims_claim_type",
        "asset_claims",
        " OR ".join(f"claim_type = '{v}'" for v in _PRIOR_CLAIM_TYPES),
    )
    op.execute(
        sa.text("DELETE FROM claim_types WHERE claim_type = :ct").bindparams(ct=_NEW_CLAIM_TYPE)
    )

    # Same for the edges: drop the rows this edge type produced, then narrow.
    op.execute(
        sa.text("DELETE FROM asset_edges WHERE edge_type = :et").bindparams(et=_NEW_EDGE_TYPE)
    )
    op.drop_constraint("ck_asset_edges_edge_type", "asset_edges", type_="check")
    op.create_check_constraint(
        "ck_asset_edges_edge_type",
        "asset_edges",
        " OR ".join(f"edge_type = '{t}'" for t in _PRIOR_EDGE_TYPES),
    )
