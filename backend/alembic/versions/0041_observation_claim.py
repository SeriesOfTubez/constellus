"""Add the `observation` claim type (L3c-2a, planning#144).

The L3c-2 serializer bridge (previous migration/commit) reconstructs
`asset_metadata["sources"]` from asset_claims — "distinct scan/discovery/
connector-kind observers across the asset's claims" — but that only works
for observers whose write actually produces a claim. `emit_claims`
(claim_emitter.py) only emits a claim when a DiscoveredAsset's metadata
carries at least one of the mapped Table 1 keys (ttl, proxied, spf, ...).
An identity-only DNS observation — dns_resolve/dns_records writing just
`{sources, record_type, content}`, the common shape for a plain A/AAAA/
CNAME hop with nothing else to say about it — carries none of those keys,
so it emits NO claim at all, and that observer silently vanishes from the
bridge's reconstructed `sources` (see test_serializer_bridge.py's CNAME
case, KNOWN GAP note, fixed in the same commit as this migration).

This migration adds a 16th claim type, `observation`, whose only job is to
exist: it has no meaningful claim_value (always `{}`), so it can be emitted
unconditionally for every asset+observer pair `emit_claims` resolves,
whether or not that pair also produced a "real" claim. It carries no
authorisation_ttl, reporting_ttl, or default_trust — base provenance, not a
judgement.

Companion changes in the same commit: `app/models/claim.py` (CLAIM_TYPES
frozenset) and `app/services/claim_emitter.py` (emit_claims now
accumulates an `observation` claim alongside its existing per-key
accumulation, whenever the asset-level observer resolves).

Revision ID: 0041
Revises: 0040
Create Date: 2026-08-19
"""

from alembic import op
import sqlalchemy as sa


revision = "0041"
down_revision = "0040"
branch_labels = None
depends_on = None


# The 15 types seeded by 0039, plus the new `observation` type — mirrors
# app/models/claim.py's CLAIM_TYPES frozenset (companion change, same commit).
_PRIOR_CLAIM_TYPES = (
    "port_observation", "proxy_state", "dns_ttl", "cloudflare_zone",
    "host_tarpit", "hosting_class", "reverse_ip", "spf_policy",
    "mx_preference", "ct_cert_issuance", "shodan_host", "reverse_hostname",
    "affinity_confirmation", "eol_status", "cloud_inventory",
)
_NEW_CLAIM_TYPE = "observation"
_ALL_CLAIM_TYPES = _PRIOR_CLAIM_TYPES + (_NEW_CLAIM_TYPE,)

_OBSERVATION_DESCRIPTION = (
    "A producer observed this asset (base provenance; carries no value "
    "beyond who saw it and when)."
)


def upgrade() -> None:
    claim_types_table = sa.table(
        "claim_types",
        sa.column("claim_type", sa.Text()),
        sa.column("description", sa.Text()),
    )
    op.bulk_insert(
        claim_types_table,
        [{"claim_type": _NEW_CLAIM_TYPE, "description": _OBSERVATION_DESCRIPTION}],
    )

    op.drop_constraint("ck_asset_claims_claim_type", "asset_claims", type_="check")
    new_check = " OR ".join(f"claim_type = '{v}'" for v in _ALL_CLAIM_TYPES)
    op.create_check_constraint("ck_asset_claims_claim_type", "asset_claims", new_check)


def downgrade() -> None:
    op.drop_constraint("ck_asset_claims_claim_type", "asset_claims", type_="check")
    old_check = " OR ".join(f"claim_type = '{v}'" for v in _PRIOR_CLAIM_TYPES)
    op.create_check_constraint("ck_asset_claims_claim_type", "asset_claims", old_check)

    op.execute(
        sa.text("DELETE FROM claim_types WHERE claim_type = :ct").bindparams(ct=_NEW_CLAIM_TYPE)
    )
