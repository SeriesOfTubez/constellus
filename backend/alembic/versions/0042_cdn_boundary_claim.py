"""Add the `cdn_boundary` claim type (L3c-3, planning#144).

`cdn` / `cdn_domain` are the CDN-boundary annotation `dns_resolve` writes
onto a CNAME hop it declines to follow past a known CDN edge
(discovery/dns_resolve.py). Until this slice they reached readers only via
the persisted `assets_canonical.metadata` column: the merge loop wrote them
there, and the L3b-2 projector mirrored them straight back out into
`asset_state.attributes` as an explicit stopgap.

That stopgap is a dead end. L3c-4 stops the merge loop authoring the column
and drops it — at which point a passthrough mirror OF that column has no
source, and `cdn` silently goes dark. The failure is not cosmetic:
`dangling_dns_analyzer` excludes CDN-annotated records from probing
entirely (Layer 1 doesn't apply past a CDN boundary), so losing the flag
means CDN-fronted records start getting probed and can raise false
dangling_dns findings.

`dns_resolve` already writes cdn/cdn_domain onto the transient
`DiscoveredAsset.asset_metadata`, which is exactly what `emit_claims`
decomposes — so the boundary judgment becomes a claim by the same Table 1
route as every other key, attributed to the observer that made it. The
projector then reads `attributes["cdn"]` from the claim and the stopgap
passthrough is deleted.

This is deliberately NOT #147's job. #147 replaces the CDN annotation with
a real CNAME -> third-party edge; this migration only gives the existing
judgment a home that survives the column drop, and #147 can retire the
claim type when it lands.

Companion changes in the same commit: `app/models/claim.py` (CLAIM_TYPES),
`app/services/claim_emitter.py` (_accumulate_cdn_claim), and
`app/services/projector.py` (reads the claim, drops the mirror).

Revision ID: 0042
Revises: 0041
Create Date: 2026-08-21
"""

from alembic import op
import sqlalchemy as sa


revision = "0042"
down_revision = "0041"
branch_labels = None
depends_on = None


# The 16 types in force after 0041, plus the new `cdn_boundary` type —
# mirrors app/models/claim.py's CLAIM_TYPES frozenset (companion change,
# same commit).
_PRIOR_CLAIM_TYPES = (
    "port_observation", "proxy_state", "dns_ttl", "cloudflare_zone",
    "host_tarpit", "hosting_class", "reverse_ip", "spf_policy",
    "mx_preference", "ct_cert_issuance", "shodan_host", "reverse_hostname",
    "affinity_confirmation", "eol_status", "cloud_inventory", "observation",
)
_NEW_CLAIM_TYPE = "cdn_boundary"
_ALL_CLAIM_TYPES = _PRIOR_CLAIM_TYPES + (_NEW_CLAIM_TYPE,)

_CDN_BOUNDARY_DESCRIPTION = (
    "A CNAME hop terminates at a known CDN edge, so resolution stopped "
    "there (carries the CDN domain that matched)."
)


def upgrade() -> None:
    claim_types_table = sa.table(
        "claim_types",
        sa.column("claim_type", sa.Text()),
        sa.column("description", sa.Text()),
    )
    op.bulk_insert(
        claim_types_table,
        [{"claim_type": _NEW_CLAIM_TYPE, "description": _CDN_BOUNDARY_DESCRIPTION}],
    )

    op.drop_constraint("ck_asset_claims_claim_type", "asset_claims", type_="check")
    new_check = " OR ".join(f"claim_type = '{v}'" for v in _ALL_CLAIM_TYPES)
    op.create_check_constraint("ck_asset_claims_claim_type", "asset_claims", new_check)


def downgrade() -> None:
    op.execute(
        sa.text("DELETE FROM asset_claims WHERE claim_type = :ct").bindparams(ct=_NEW_CLAIM_TYPE)
    )
    op.drop_constraint("ck_asset_claims_claim_type", "asset_claims", type_="check")
    old_check = " OR ".join(f"claim_type = '{v}'" for v in _PRIOR_CLAIM_TYPES)
    op.create_check_constraint("ck_asset_claims_claim_type", "asset_claims", old_check)

    op.execute(
        sa.text("DELETE FROM claim_types WHERE claim_type = :ct").bindparams(ct=_NEW_CLAIM_TYPE)
    )
