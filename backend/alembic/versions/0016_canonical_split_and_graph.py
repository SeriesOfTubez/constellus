"""Phase 1: canonical/observation split + graph edges + target attribution

Lays down the new identity tables (scan_templates, assets_canonical,
findings_canonical) and the relationship/graph tables (target_asset_links,
asset_edges) alongside the existing observation tables. The existing assets,
findings, and scan_runs hypertables are left untouched in this migration —
they'll be refactored in a follow-up once the writers are updated to populate
both sides.

Phase 1 design decisions captured here:
  - Canonical identity tables are NOT hypertables (one row per logical entity).
    Observation tables (assets, findings) remain hypertables.
  - asset_edges uses a polymorphic FK pattern (source_type + source_id and
    target_type + target_id). Integrity is enforced by a trigger function
    that validates the referenced row exists in the right table.
  - edge_type is text + CHECK constraint, not a Postgres enum (enums are
    painful to ALTER as the model evolves).
  - target_asset_links is a true N-to-N join table; assets are
    garbage-collected when their link count reaches zero (handled in app code,
    not by FK cascades).
  - targets gain source_type + auto_managed for connector ownership semantics.

Revision ID: 0016
Revises: 0015
Create Date: 2026-05-24
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


# Edge types — keep in sync with app code. New types are added by editing the
# CHECK constraint via a follow-up migration.
EDGE_TYPES = (
    "resolves_to",          # dns_record asset → ip_address asset
    "has_open_port",        # ip_address asset → port asset
    "runs_service",         # port asset → service asset
    "has_finding",          # any asset → finding (findings as first-class nodes)
    "registered_to",        # target / asset → whois_org
    "discovered_in_target", # target → asset (also recorded in target_asset_links)
    "belongs_to_apex",      # asset → apex target (DNS subdomain tree)
)

# Source/target type discriminators for the polymorphic FK columns.
NODE_TYPES = (
    "target",
    "asset_canonical",
    "finding_canonical",
    "whois_org",  # synthetic node — keyed by org name; populated lazily
)


def upgrade() -> None:
    # ── Scan templates: durable scan configuration ────────────────────────────
    op.create_table(
        "scan_templates",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("scope", JSONB, nullable=False, server_default=sa.text("'{}'")),
        sa.Column("options", JSONB, nullable=False, server_default=sa.text("'{}'")),
        sa.Column("schedule_cron", sa.Text, nullable=True),  # null = on-demand only
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("tags", JSONB, nullable=False, server_default=sa.text("'[]'")),
    )
    op.create_index("ix_scan_templates_enabled", "scan_templates", ["enabled"])

    # ── Canonical asset identity ──────────────────────────────────────────────
    op.create_table(
        "assets_canonical",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("asset_type", sa.Text, nullable=False),
        sa.Column("value", sa.Text, nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("ignored", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("tags", JSONB, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("metadata", JSONB, nullable=False, server_default=sa.text("'{}'")),
        sa.UniqueConstraint("asset_type", "value", name="uq_assets_canonical_type_value"),
    )
    op.create_index("ix_assets_canonical_type", "assets_canonical", ["asset_type"])
    op.create_index("ix_assets_canonical_value", "assets_canonical", ["value"])
    op.create_index("ix_assets_canonical_last_seen", "assets_canonical", ["last_seen_at"])

    # ── Canonical finding identity ────────────────────────────────────────────
    op.create_table(
        "findings_canonical",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("asset_canonical_id", UUID(as_uuid=True), sa.ForeignKey("assets_canonical.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_type", sa.Text, nullable=False),
        sa.Column("source", sa.Text, nullable=False),
        # Source-specific uniqueness key: cve_id for Shodan/Nuclei CVE findings,
        # template_id for Nuclei rules, tag name for Shodan tag findings, etc.
        sa.Column("fingerprint", sa.Text, nullable=False),
        sa.Column("severity", sa.Text, nullable=False),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("state", sa.Text, nullable=False, server_default=sa.text("'open'")),
        sa.Column("category", sa.Text, nullable=True),
        sa.Column("cve_id", sa.Text, nullable=True),
        sa.Column("cvss_score", sa.Float, nullable=True),
        sa.Column("cvss_vector", sa.Text, nullable=True),
        sa.Column("cvss_version", sa.Text, nullable=True),
        sa.Column("epss_score", sa.Float, nullable=True),
        sa.Column("epss_percentile", sa.Float, nullable=True),
        sa.Column("kev", sa.Boolean, nullable=True),
        sa.Column("kev_date_added", sa.Date, nullable=True),
        sa.Column("cwe", sa.Text, nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("suppressed_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("detail", JSONB, nullable=False, server_default=sa.text("'{}'")),
        sa.Column("tags", JSONB, nullable=False, server_default=sa.text("'[]'")),
        sa.UniqueConstraint(
            "asset_canonical_id", "finding_type", "source", "fingerprint",
            name="uq_findings_canonical_fingerprint",
        ),
    )
    op.create_index("ix_findings_canonical_asset", "findings_canonical", ["asset_canonical_id"])
    op.create_index("ix_findings_canonical_state", "findings_canonical", ["state"])
    op.create_index("ix_findings_canonical_severity", "findings_canonical", ["severity"])
    op.create_index("ix_findings_canonical_cve", "findings_canonical", ["cve_id"])
    op.create_index("ix_findings_canonical_last_seen", "findings_canonical", ["last_seen_at"])

    # ── Target → canonical asset linkage (N-to-N) ─────────────────────────────
    # Assets garbage-collected by app code when link count reaches zero.
    op.create_table(
        "target_asset_links",
        sa.Column("target_id", UUID(as_uuid=True), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_canonical_id", UUID(as_uuid=True), sa.ForeignKey("assets_canonical.id", ondelete="CASCADE"), nullable=False),
        sa.Column("first_linked_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("target_id", "asset_canonical_id"),
    )
    op.create_index("ix_target_asset_links_asset", "target_asset_links", ["asset_canonical_id"])

    # ── Typed graph edges ─────────────────────────────────────────────────────
    edge_check = " OR ".join(f"edge_type = '{t}'" for t in EDGE_TYPES)
    node_check_src = " OR ".join(f"source_type = '{t}'" for t in NODE_TYPES)
    node_check_tgt = " OR ".join(f"target_type = '{t}'" for t in NODE_TYPES)

    op.create_table(
        "asset_edges",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("source_type", sa.Text, nullable=False),
        sa.Column("source_id", UUID(as_uuid=True), nullable=False),
        sa.Column("target_type", sa.Text, nullable=False),
        sa.Column("target_id", UUID(as_uuid=True), nullable=False),
        sa.Column("edge_type", sa.Text, nullable=False),
        # nullable float — populated only on edges relevant to attack-path
        # scoring (Phase 5). Descriptive edges leave it null.
        sa.Column("weight", sa.Float, nullable=True),
        sa.Column("metadata", JSONB, nullable=False, server_default=sa.text("'{}'")),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(edge_check, name="ck_asset_edges_edge_type"),
        sa.CheckConstraint(node_check_src, name="ck_asset_edges_source_type"),
        sa.CheckConstraint(node_check_tgt, name="ck_asset_edges_target_type"),
        sa.UniqueConstraint(
            "source_type", "source_id", "target_type", "target_id", "edge_type",
            name="uq_asset_edges_unique",
        ),
    )
    op.create_index("ix_asset_edges_source", "asset_edges", ["source_type", "source_id"])
    op.create_index("ix_asset_edges_target", "asset_edges", ["target_type", "target_id"])
    op.create_index("ix_asset_edges_type", "asset_edges", ["edge_type"])
    op.create_index("ix_asset_edges_metadata", "asset_edges", ["metadata"], postgresql_using="gin")

    # Polymorphic FK integrity: trigger validates that source_id / target_id
    # actually reference an existing row in the table named by source_type /
    # target_type. Cheap (one SELECT EXISTS per insert/update), and avoids
    # the silent-orphan problem you'd otherwise get from a polymorphic FK.
    # whois_org is a synthetic node — we don't have a table for it yet, so it
    # bypasses the existence check (will be added in a later migration when
    # the whois_orgs table exists).
    op.execute("""
    CREATE OR REPLACE FUNCTION asset_edges_validate_endpoints()
    RETURNS trigger AS $$
    DECLARE
        src_exists boolean;
        tgt_exists boolean;
    BEGIN
        -- Validate source endpoint
        IF NEW.source_type = 'target' THEN
            SELECT EXISTS(SELECT 1 FROM targets WHERE id = NEW.source_id) INTO src_exists;
        ELSIF NEW.source_type = 'asset_canonical' THEN
            SELECT EXISTS(SELECT 1 FROM assets_canonical WHERE id = NEW.source_id) INTO src_exists;
        ELSIF NEW.source_type = 'finding_canonical' THEN
            SELECT EXISTS(SELECT 1 FROM findings_canonical WHERE id = NEW.source_id) INTO src_exists;
        ELSIF NEW.source_type = 'whois_org' THEN
            src_exists := true;  -- synthetic node, no table yet
        ELSE
            RAISE EXCEPTION 'unknown source_type: %', NEW.source_type;
        END IF;

        IF NOT src_exists THEN
            RAISE EXCEPTION 'asset_edges.source_id % does not exist in %', NEW.source_id, NEW.source_type;
        END IF;

        -- Validate target endpoint
        IF NEW.target_type = 'target' THEN
            SELECT EXISTS(SELECT 1 FROM targets WHERE id = NEW.target_id) INTO tgt_exists;
        ELSIF NEW.target_type = 'asset_canonical' THEN
            SELECT EXISTS(SELECT 1 FROM assets_canonical WHERE id = NEW.target_id) INTO tgt_exists;
        ELSIF NEW.target_type = 'finding_canonical' THEN
            SELECT EXISTS(SELECT 1 FROM findings_canonical WHERE id = NEW.target_id) INTO tgt_exists;
        ELSIF NEW.target_type = 'whois_org' THEN
            tgt_exists := true;
        ELSE
            RAISE EXCEPTION 'unknown target_type: %', NEW.target_type;
        END IF;

        IF NOT tgt_exists THEN
            RAISE EXCEPTION 'asset_edges.target_id % does not exist in %', NEW.target_id, NEW.target_type;
        END IF;

        RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;
    """)

    op.execute("""
    CREATE TRIGGER asset_edges_validate_endpoints_trg
    BEFORE INSERT OR UPDATE ON asset_edges
    FOR EACH ROW EXECUTE FUNCTION asset_edges_validate_endpoints();
    """)

    # ── Target attribution columns ────────────────────────────────────────────
    # source_type: where this target came from. Auto_managed indicates whether
    # its lifecycle is controlled by a connector (deleted on sync removal) or
    # by the user (deleted explicitly via UI). Existing rows: derive
    # source_type from connector_id, auto_managed=true if connector-sourced.
    op.add_column(
        "targets",
        sa.Column("source_type", sa.Text, nullable=False, server_default=sa.text("'manual'")),
    )
    op.add_column(
        "targets",
        sa.Column("auto_managed", sa.Boolean, nullable=False, server_default=sa.text("false")),
    )
    op.execute("""
        UPDATE targets
        SET source_type = 'dns_connector', auto_managed = true
        WHERE connector_id IS NOT NULL;
    """)
    op.create_index("ix_targets_source_type", "targets", ["source_type"])
    op.create_index("ix_targets_auto_managed", "targets", ["auto_managed"])


def downgrade() -> None:
    op.drop_index("ix_targets_auto_managed", table_name="targets")
    op.drop_index("ix_targets_source_type", table_name="targets")
    op.drop_column("targets", "auto_managed")
    op.drop_column("targets", "source_type")

    op.execute("DROP TRIGGER IF EXISTS asset_edges_validate_endpoints_trg ON asset_edges")
    op.execute("DROP FUNCTION IF EXISTS asset_edges_validate_endpoints()")
    op.drop_table("asset_edges")
    op.drop_table("target_asset_links")
    op.drop_table("findings_canonical")
    op.drop_table("assets_canonical")
    op.drop_table("scan_templates")
