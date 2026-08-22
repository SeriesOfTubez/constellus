"""Claims layer + observer identity (L1, planning#142).

Constellus currently derives everything an asset "is" (open ports, hosting
class, EOL status, ownership) straight into `assets_canonical.metadata`
(the "metadata" attribute — see AssetCanonical) with no record of which
producer asserted it, how it was obtained, or when the claim goes stale.
That collapse is what made the shared-infra false-attribution problem
possible in the first place (see epic#81): a Shodan-inferred fact and a
naabu-observed fact carry the same weight once they're merged into one JSON
blob, and nothing distinguishes a claim that authorises probing a target
from one that's merely descriptive.

This migration lays the L0/L1 grounding-claims schema: WHO claimed WHAT
about an asset, with what trust and addressing mode (Observer), a typed
vocabulary of WHAT can be claimed (ClaimType), the current-value claims
themselves (AssetClaim) plus an append-only history (ClaimHistory), a
projection target for the future L2 projector (AssetState), a forward
declaration of edge-type relationship semantics for later attribution work
(EdgeTypeRelationship), and a decision log for the future authorisation
gate (AuthorisationDecision).

This is a green slice: **new tables only**. `assets_canonical.metadata`
stays authoritative — nothing here is read by any projector, gate, or API/
service reader, and no connector or asset_writer.py code path writes to
these tables yet. See planning#142 for the phased rollout (L1 here → L2
projector/gate → L3 cutover that finally drops `metadata`).

Design decisions carried from the spec (do not re-litigate in a later
migration without a real reason):
  D1 — probe-authorisation claims (`affinity_confirmation`,
       `cloud_inventory`) carry their authorised names directly in
       `claim_value` rather than on a separate edge, so a future gate's read
       path stays a single lookup keyed by (asset, observer, claim_type).
  D2 — authorisation-grade vs reporting freshness is a per-claim-type
       policy on `claim_types` (`authorisation_ttl` / `reporting_ttl`), not
       a second timestamp on every claim row.

Seed data notes:
  - `observers`: the 18 current L0 producers. tlsx/httpx are declared
    `name`-addressing here even though the raw sweep is mixed ip+name — the
    CDN/SNI path is the one that actually needs authorisation, and the IP
    path is already covered by naabu/banner_grab being `ip`-addressing.
    Revisit in L2/#148 if the ip path ever needs its own observer identity.
    The `cloud_inventory` observer (Wiz/cloudlist) is deliberately NOT
    seeded — it arrives with #118.
  - `claim_types`: the 15 L0 claim types. `authorisation_ttl` is non-NULL
    only for `affinity_confirmation` (7 days) and `cloud_inventory` (24
    hours) — conservative starting values for #148 to tune, not a
    considered policy.
  - `edge_type_relationships`: 7 seed rows covering `dependency` and
    `recipient`. `authority` is reserved by the 2026-08-19 three-axis
    attribution redesign but intentionally NOT added to the CHECK
    constraint yet — it has no producer. Several seeded edge_types (cname,
    spf_include, script_include, ...) are not yet in asset_edge.EDGE_TYPES;
    that's expected, their producers land in later epics. asset_edge.py is
    untouched by this migration.

`claim_history` is natively range-partitioned on `changed_at`. Alembic/
SQLAlchemy cannot emit `PARTITION BY` via op.create_table, so the table and
its partitions are created with raw `op.execute(...)` SQL. Partition bounds
are computed at migration-run-time (current month / next month) rather than
hardcoded, so this migration behaves the same whenever it's actually
applied. A DEFAULT partition catches anything outside the seeded range.
Monthly rollover is an L2 scheduler concern, not built here.

`uuidv7()` is a core PostgreSQL 18 built-in (no extension required) — see
test_database_requirements.py, which asserts no extension beyond `plpgsql`
is installed.

Revision ID: 0039
Revises: 0038
Create Date: 2026-08-19
"""

from datetime import timedelta

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID


revision = "0039"
down_revision = "0038"
branch_labels = None
depends_on = None


# ── Vocabularies (mirrors the frozensets in app/models/*.py) ────────────────
OBSERVER_KINDS = ("scan", "discovery", "connector", "verify", "enrich")
OBSERVER_TRUST = ("observed", "derived", "inferred")
OBSERVER_ADDRESSING = ("ip", "name", "none")
CLAIM_TYPES = (
    "port_observation", "proxy_state", "dns_ttl", "cloudflare_zone",
    "host_tarpit", "hosting_class", "reverse_ip", "spf_policy",
    "mx_preference", "ct_cert_issuance", "shodan_host", "reverse_hostname",
    "affinity_confirmation", "eol_status", "cloud_inventory",
)
ESTATE_VALUES = ("proven_ours", "claimed_ours", "not_ours")
EDGE_RELATIONSHIPS = ("dependency", "recipient")


# ── Seed data ─────────────────────────────────────────────────────────────
# (name, kind, trust, emits_traffic_to_target, addressing, description)
OBSERVER_SEED = [
    ("naabu", "scan", "observed", True, "ip", "Active TCP/UDP port sweep against a resolved IP."),
    ("tlsx", "scan", "observed", True, "name", "TLS handshake/cert probe addressed by hostname (SNI)."),
    ("httpx", "scan", "observed", True, "name", "HTTP(S) probe addressed by hostname."),
    ("banner_grab", "scan", "observed", True, "ip", "Raw TCP banner grab against a resolved IP:port."),
    ("domain_affinity", "verify", "derived", True, "name", "Derives shared-origin affinity from observed response fingerprints."),
    ("shared_infra_verifier", "verify", "derived", True, "name", "Confirms or rejects ownership of shared-infrastructure findings."),
    ("dangling_dns_analyzer", "verify", "derived", True, "name", "Detects dangling/takeover-prone DNS records."),
    ("dnsrecon", "discovery", "observed", True, "name", "Active DNS enumeration (zone walking, wordlist resolution)."),
    ("dns_records", "discovery", "observed", False, "none", "Passive DNS record collection (A/AAAA/MX/TXT/NS/...)."),
    ("dns_resolve", "discovery", "observed", False, "none", "Resolves a hostname to its current IP addresses."),
    ("subfinder", "discovery", "observed", False, "none", "Passive subdomain enumeration."),
    ("bruteforce", "discovery", "observed", False, "none", "Wordlist-based subdomain discovery."),
    ("cert_transparency", "discovery", "observed", False, "none", "Certificate Transparency log enumeration (Certspotter)."),
    ("shodan", "connector", "inferred", False, "none", "Third-party internet-scan data via the Shodan API."),
    ("cloudflare", "connector", "observed", False, "none", "Zone/DNS inventory pulled from a connected Cloudflare account."),
    ("hosting_classifier", "enrich", "inferred", False, "none", "Infers hosting class (datacenter/cloud/residential) and provider for an IP."),
    ("eol_enrichment", "enrich", "derived", False, "none", "Resolves end-of-life status for detected software/CPEs."),
    ("cpe_normalizer", "enrich", "derived", False, "none", "Normalizes detected software identifiers to canonical CPEs."),
]

# (claim_type, description, authorisation_ttl_days, reporting_ttl, default_trust)
# authorisation_ttl given as a Python value used to build an INTERVAL literal;
# None means NULL (never authorises a probe).
CLAIM_TYPE_SEED = [
    ("port_observation", "Open TCP/UDP port observed on a host by a network-level scan.", None),
    ("proxy_state", "Whether a host is confirmed to sit behind a reverse proxy / CDN edge.", None),
    ("dns_ttl", "TTL value observed on a DNS record at resolution time.", None),
    ("cloudflare_zone", "Domain confirmed present as an active zone in a connected Cloudflare account.", None),
    ("host_tarpit", "Host exhibits tarpit/deception behaviour (uniform open-port sweep, anomalous timing).", None),
    ("hosting_class", "Inferred hosting classification (datacenter/cloud/residential) and provider for an IP.", None),
    ("reverse_ip", "Reverse-DNS (PTR) hostname observed for an IP address.", None),
    ("spf_policy", "SPF record content and mechanisms observed for a domain.", None),
    ("mx_preference", "MX record host and preference value observed for a domain.", None),
    ("ct_cert_issuance", "Certificate issuance observed via Certificate Transparency logs for a hostname.", None),
    ("shodan_host", "Host/service data returned by the Shodan connector for an IP.", None),
    ("reverse_hostname", "Forward-confirmed hostname a reverse-DNS PTR record resolves back to.", None),
    ("affinity_confirmation", "A name-addressed probe confirmed our identity is served at this address; carries authorised_names (D1). Authorisation-grade — promotes to IP-addressed probing.", 7),
    ("eol_status", "End-of-life status for a detected software/CPE.", None),
    ("cloud_inventory", "Credentialed proof the IP belongs to a cloud account we control (from a connected inventory, e.g. Wiz/cloudlist, #118). Authorisation-grade — promotes to IP-addressed probing.", 1),
]

# (edge_type, relationship, description)
EDGE_TYPE_RELATIONSHIP_SEED = [
    ("cname", "dependency", "Target hostname is a CNAME alias resolving through this edge's host."),
    ("ns", "dependency", "Target domain delegates authority to this nameserver."),
    ("mx", "dependency", "Target domain routes mail through this MX host."),
    ("spf_include", "dependency", "Target's SPF policy includes this domain's SPF record via an include: mechanism."),
    ("script_include", "dependency", "Target's page includes a script served from this origin."),
    ("dmarc_rua", "recipient", "Target's DMARC policy sends aggregate (rua) reports to this recipient."),
    ("tls_rpt_rua", "recipient", "Target's TLS-RPT policy sends reports to this recipient."),
]


def upgrade() -> None:
    # ── observers (reference, seeded) ───────────────────────────────────────
    observer_kind_check = " OR ".join(f"kind = '{v}'" for v in OBSERVER_KINDS)
    observer_trust_check = " OR ".join(f"trust = '{v}'" for v in OBSERVER_TRUST)
    observer_addressing_check = " OR ".join(f"addressing = '{v}'" for v in OBSERVER_ADDRESSING)

    op.create_table(
        "observers",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("trust", sa.Text(), nullable=False),
        sa.Column("emits_traffic_to_target", sa.Boolean(), nullable=False),
        sa.Column("addressing", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.UniqueConstraint("name", name="uq_observers_name"),
        sa.CheckConstraint(observer_kind_check, name="ck_observers_kind"),
        sa.CheckConstraint(observer_trust_check, name="ck_observers_trust"),
        sa.CheckConstraint(observer_addressing_check, name="ck_observers_addressing"),
    )

    # ── claim_types (reference, seeded — the L0 grounding ontology) ─────────
    op.create_table(
        "claim_types",
        sa.Column("claim_type", sa.Text(), primary_key=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("authorisation_ttl", sa.Interval(), nullable=True),
        sa.Column("reporting_ttl", sa.Interval(), nullable=True),
        sa.Column("default_trust", sa.Text(), nullable=True),
    )

    # ── edge_type_relationships (reference, seeded — standalone, no FK) ─────
    edge_relationship_check = " OR ".join(f"relationship = '{v}'" for v in EDGE_RELATIONSHIPS)
    op.create_table(
        "edge_type_relationships",
        sa.Column("edge_type", sa.Text(), primary_key=True),
        sa.Column("relationship", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.CheckConstraint(edge_relationship_check, name="ck_edge_type_relationships_relationship"),
    )

    # ── asset_claims (data — current-value claims layer) ────────────────────
    claim_type_check = " OR ".join(f"claim_type = '{v}'" for v in CLAIM_TYPES)
    op.create_table(
        "asset_claims",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column("asset_canonical_id", UUID(as_uuid=True), sa.ForeignKey("assets_canonical.id", ondelete="CASCADE"), nullable=False),
        sa.Column("observer_id", UUID(as_uuid=True), sa.ForeignKey("observers.id"), nullable=False),
        sa.Column("claim_type", sa.Text(), sa.ForeignKey("claim_types.claim_type"), nullable=False),
        sa.Column("claim_value", JSONB, nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("evidence", JSONB, nullable=False, server_default=sa.text("'{}'")),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint(
            "asset_canonical_id", "observer_id", "claim_type",
            name="uq_asset_claims_asset_observer_type",
        ),
        sa.CheckConstraint(claim_type_check, name="ck_asset_claims_claim_type"),
    )
    op.create_index("ix_asset_claims_last_observed_at", "asset_claims", ["last_observed_at"])

    # ── asset_state (data — L2 projection target, no writer yet) ────────────
    estate_check = " OR ".join(f"estate = '{v}'" for v in ESTATE_VALUES)
    op.create_table(
        "asset_state",
        sa.Column("asset_canonical_id", UUID(as_uuid=True), sa.ForeignKey("assets_canonical.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("open_ports", JSONB, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("estate", sa.Text(), nullable=True),
        sa.Column("hosting", JSONB, nullable=False, server_default=sa.text("'{}'")),
        sa.Column("eol_summary", JSONB, nullable=False, server_default=sa.text("'{}'")),
        sa.Column("attributes", JSONB, nullable=False, server_default=sa.text("'{}'")),
        sa.Column("projected_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(f"estate IS NULL OR ({estate_check})", name="ck_asset_state_estate"),
    )

    # ── authorisation_decisions (data — decision log, no writer yet) ────────
    op.create_table(
        "authorisation_decisions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column("asset_canonical_id", UUID(as_uuid=True), sa.ForeignKey("assets_canonical.id"), nullable=True),
        sa.Column("observer_id", UUID(as_uuid=True), sa.ForeignKey("observers.id"), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("allowed", sa.Boolean(), nullable=False),
        sa.Column("probe_modes", JSONB, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("authorised_names", JSONB, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("rule_fired", sa.Text(), nullable=True),
        sa.Column("evidence_snapshot", JSONB, nullable=False, server_default=sa.text("'{}'")),
    )
    op.create_index("ix_authorisation_decisions_decided_at", "authorisation_decisions", ["decided_at"])

    # ── claim_history (data — append-only, natively partitioned) ────────────
    # PARTITION BY cannot be expressed via op.create_table; hand-write it.
    op.execute("""
        CREATE TABLE claim_history (
            id uuid NOT NULL DEFAULT uuidv7(),
            asset_canonical_id uuid NOT NULL,
            observer_id uuid NOT NULL,
            claim_type text NOT NULL,
            claim_value jsonb NOT NULL,
            confidence double precision,
            evidence jsonb NOT NULL DEFAULT '{}',
            changed_at timestamptz NOT NULL,
            PRIMARY KEY (changed_at, id)
        ) PARTITION BY RANGE (changed_at);
    """)

    # Seed current-month + next-month partitions, computed at migration-run
    # time so this doesn't drift into a hardcoded date. A DEFAULT partition
    # catches anything outside the seeded range until #<rollover job> exists.
    op.execute("""
        DO $$
        DECLARE
            this_month date := date_trunc('month', now())::date;
            next_month date := (date_trunc('month', now()) + interval '1 month')::date;
            month_after date := (date_trunc('month', now()) + interval '2 month')::date;
        BEGIN
            EXECUTE format(
                'CREATE TABLE %I PARTITION OF claim_history FOR VALUES FROM (%L) TO (%L)',
                'claim_history_' || to_char(this_month, 'YYYY_MM'), this_month, next_month
            );
            EXECUTE format(
                'CREATE TABLE %I PARTITION OF claim_history FOR VALUES FROM (%L) TO (%L)',
                'claim_history_' || to_char(next_month, 'YYYY_MM'), next_month, month_after
            );
        END $$;
    """)
    op.execute("CREATE TABLE claim_history_default PARTITION OF claim_history DEFAULT;")

    # ── Seed reference data ──────────────────────────────────────────────────
    observers_table = sa.table(
        "observers",
        sa.column("name", sa.Text()),
        sa.column("kind", sa.Text()),
        sa.column("trust", sa.Text()),
        sa.column("emits_traffic_to_target", sa.Boolean()),
        sa.column("addressing", sa.Text()),
        sa.column("description", sa.Text()),
    )
    op.bulk_insert(
        observers_table,
        [
            {
                "name": name, "kind": kind, "trust": trust,
                "emits_traffic_to_target": emits, "addressing": addressing,
                "description": description,
            }
            for name, kind, trust, emits, addressing, description in OBSERVER_SEED
        ],
    )

    claim_types_table = sa.table(
        "claim_types",
        sa.column("claim_type", sa.Text()),
        sa.column("description", sa.Text()),
        sa.column("authorisation_ttl", sa.Interval()),
    )
    op.bulk_insert(
        claim_types_table,
        [
            {
                "claim_type": claim_type,
                "description": description,
                "authorisation_ttl": timedelta(days=ttl_days) if ttl_days is not None else None,
            }
            for claim_type, description, ttl_days in CLAIM_TYPE_SEED
        ],
    )

    edge_type_relationships_table = sa.table(
        "edge_type_relationships",
        sa.column("edge_type", sa.Text()),
        sa.column("relationship", sa.Text()),
        sa.column("description", sa.Text()),
    )
    op.bulk_insert(
        edge_type_relationships_table,
        [
            {"edge_type": edge_type, "relationship": relationship, "description": description}
            for edge_type, relationship, description in EDGE_TYPE_RELATIONSHIP_SEED
        ],
    )


def downgrade() -> None:
    # FK-safe order: drop dependents before the reference tables they point to.
    op.drop_index("ix_authorisation_decisions_decided_at", table_name="authorisation_decisions")
    op.drop_table("authorisation_decisions")

    op.drop_table("asset_state")

    # Dropping a partitioned parent drops all of its partitions (including
    # the DEFAULT one) — no need to drop them individually.
    op.execute("DROP TABLE claim_history")

    op.drop_index("ix_asset_claims_last_observed_at", table_name="asset_claims")
    op.drop_table("asset_claims")

    op.drop_table("edge_type_relationships")
    op.drop_table("claim_types")
    op.drop_table("observers")
