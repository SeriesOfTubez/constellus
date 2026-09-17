"""Cloud provider range mirror + tenancy claim (planning#181 Tier 0).

Two new tables and one new observer/claim-type pair, moving hosting/tenancy
enrichment off the scan path (planning#181). `app.services.cloud_ranges`
mirrors constellus-binaries' published `cloud-ranges` dataset (planning#179)
daily; `app.services.tenancy_enricher` drips a per-asset `tenancy` claim off
that local mirror. Neither is read from a scan path in this slice — the
gate that will read `tenancy` alongside an ownership claim to promote
bare-IP probing is planning#182's, deliberately not built here.

Why the dataset lives in Postgres rather than in memory: it survives a
process restart (an in-memory cache would silently go cold on every
deploy, right when the tenancy_enricher drip needs it most), it is safe to
read from multiple worker processes without a cache-warming race, and
Postgres' native `inet`/`cidr` containment operator (`>>=`) does
longest-prefix matching for us — reimplementing that over a Python
in-memory trie would be strictly worse for no benefit.

Why there is no unique constraint on `(prefix, service_raw)`: overlapping
prefixes are the signal, not noise, to dedupe away. A provider's edge
service can carve a more specific block out of a broader compute range
(see `cloud_ranges.lookup`'s specificity ORDER BY, and
test_cloud_ranges.py's longest-prefix-wins case) — SCHEMA.md documents this
as intentional. A unique constraint here would make a legitimate published
overlap a load failure.

Why `claim_types.tenancy` carries a 7-day `authorisation_ttl`: this claim
is authorisation-grade — planning#182 composes it with an ownership verdict
(`affinity_confirmation` / `cloud_inventory`) to decide whether bare-IP
probing may proceed at all, so its freshness is a probe-authorisation
policy, not a reporting one, mirroring `affinity_confirmation`'s own 7-day
TTL (the claim `tenancy` is composed with in #182).

Companion changes in the same commit: `app/models/cloud_range.py` (new
models), `app/models/claim.py` (CLAIM_TYPES frozenset += "tenancy", and the
`ck_asset_claims_claim_type` CHECK constraint widened to match — same
two-file/one-constraint pattern every prior claim-type migration follows,
see 0041/0042/0044).

Revision ID: 0050
Revises: 0049
Create Date: 2026-09-16
"""

from datetime import timedelta

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import CIDR, JSONB, UUID

revision = "0050"
down_revision = "0049"
branch_labels = None
depends_on = None


_SERVICE_CLASSES = ("compute", "edge", "storage", "managed", "unknown")

_OBSERVER = (
    "tenancy_enricher",
    "enrich",
    "inferred",
    False,
    "none",
    "Derives IP tenancy from mirrored cloud provider range feeds (planning#181 Tier 0).",
)

# Mirrors app/models/claim.py's CLAIM_TYPES (companion change, same commit).
_PRIOR_CLAIM_TYPES = (
    "port_observation", "proxy_state", "dns_ttl", "cloudflare_zone",
    "host_tarpit", "hosting_class", "reverse_ip", "spf_policy",
    "mx_preference", "ct_cert_issuance", "shodan_host", "reverse_hostname",
    "affinity_confirmation", "eol_status", "cloud_inventory", "observation",
    "cdn_boundary", "third_party_dependency",
)
_NEW_CLAIM_TYPE = "tenancy"
_ALL_CLAIM_TYPES = _PRIOR_CLAIM_TYPES + (_NEW_CLAIM_TYPE,)

_TENANCY_DESCRIPTION = (
    "Whether a SYN scan of this IP reaches exactly one tenant, derived from mirrored "
    "cloud provider range feeds. Authorisation-grade — composes with an ownership "
    "verdict to promote bare-IP probing (planning#181/#182). NOT an ownership claim."
)
_TENANCY_TTL_DAYS = 7


def upgrade() -> None:
    # ── cloud_ranges (data — local mirror of constellus-binaries' feed) ────
    service_class_check = " OR ".join(f"service_class = '{v}'" for v in _SERVICE_CLASSES)
    op.create_table(
        "cloud_ranges",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column("prefix", CIDR(), nullable=False),
        sa.Column("ip_version", sa.SmallInteger(), nullable=False),
        sa.Column("provider", sa.Text(), nullable=False),
        sa.Column("service_raw", sa.Text(), nullable=True),
        sa.Column("service_class", sa.Text(), nullable=False),
        sa.Column("region", sa.Text(), nullable=True),
        sa.Column("source", sa.Text(), nullable=False),
        # No unique constraint on (prefix, service_raw) — see module
        # docstring: overlapping prefixes are the signal, not noise.
        sa.CheckConstraint(service_class_check, name="ck_cloud_ranges_service_class"),
    )
    op.execute("CREATE INDEX ix_cloud_ranges_prefix ON cloud_ranges USING gist (prefix inet_ops)")
    op.create_index("ix_cloud_ranges_provider", "cloud_ranges", ["provider"])

    # ── cloud_ranges_meta (data — single-row freshness/provenance marker) ──
    op.create_table(
        "cloud_ranges_meta",
        sa.Column("id", sa.Boolean(), primary_key=True, server_default=sa.text("true")),
        sa.Column("dataset_sha256", sa.Text(), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_count", sa.Integer(), nullable=False),
        sa.Column("refreshed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("manifest", JSONB(), nullable=False),
        # CHECK (id) + boolean PK: only id = true is insertable, so there is
        # exactly one row by construction — no advisory lock or app-level
        # singleton discipline needed to keep it that way.
        sa.CheckConstraint("id", name="ck_cloud_ranges_meta_single_row"),
    )

    # ── observers += tenancy_enricher ───────────────────────────────────────
    observers = sa.table(
        "observers",
        sa.column("name", sa.Text()),
        sa.column("kind", sa.Text()),
        sa.column("trust", sa.Text()),
        sa.column("emits_traffic_to_target", sa.Boolean()),
        sa.column("addressing", sa.Text()),
        sa.column("description", sa.Text()),
    )
    name, kind, trust, emits, addressing, description = _OBSERVER
    op.bulk_insert(
        observers,
        [{
            "name": name,
            "kind": kind,
            "trust": trust,
            "emits_traffic_to_target": emits,
            "addressing": addressing,
            "description": description,
        }],
    )

    # ── claim_types += tenancy ───────────────────────────────────────────────
    claim_types_table = sa.table(
        "claim_types",
        sa.column("claim_type", sa.Text()),
        sa.column("description", sa.Text()),
        sa.column("authorisation_ttl", sa.Interval()),
    )
    op.bulk_insert(
        claim_types_table,
        [{
            "claim_type": _NEW_CLAIM_TYPE,
            "description": _TENANCY_DESCRIPTION,
            "authorisation_ttl": timedelta(days=_TENANCY_TTL_DAYS),
        }],
    )
    op.drop_constraint("ck_asset_claims_claim_type", "asset_claims", type_="check")
    op.create_check_constraint(
        "ck_asset_claims_claim_type",
        "asset_claims",
        " OR ".join(f"claim_type = '{v}'" for v in _ALL_CLAIM_TYPES),
    )


def downgrade() -> None:
    # Claims first — the CHECK cannot be narrowed while rows violate it, and
    # asset_claims.claim_type is an FK to claim_types (0041/0042/0044 precedent).
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
    op.execute("DELETE FROM observers WHERE name = 'tenancy_enricher'")

    op.drop_table("cloud_ranges_meta")
    op.drop_index("ix_cloud_ranges_provider", table_name="cloud_ranges")
    op.execute("DROP INDEX IF EXISTS ix_cloud_ranges_prefix")
    op.drop_table("cloud_ranges")
