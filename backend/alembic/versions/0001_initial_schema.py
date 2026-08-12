"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-05-03
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(255), nullable=False),
        sa.Column("role", sa.String(50), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_users_email", "users", ["email"])

    op.create_table(
        "scan_runs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=True),
        sa.Column("status", sa.String(50), nullable=False, server_default="pending"),
        sa.Column("scope", JSONB(), nullable=False),
        sa.Column("connectors_used", JSONB(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("created_by_id", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
    )

    # TimescaleDB hypertables — partition column must be part of the primary key
    op.create_table(
        "assets",
        sa.Column("id", UUID(as_uuid=True), nullable=False),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("scan_run_id", UUID(as_uuid=True), sa.ForeignKey("scan_runs.id"), nullable=False),
        sa.Column("asset_type", sa.String(50), nullable=False),
        sa.Column("value", sa.String(512), nullable=False),
        sa.Column("parent_value", sa.String(512), nullable=True),
        sa.Column("metadata", JSONB(), nullable=True),
        sa.PrimaryKeyConstraint("id", "discovered_at"),
    )
    op.create_index("ix_assets_scan_run_id", "assets", ["scan_run_id"])
    op.create_index("ix_assets_value", "assets", ["value"])
    op.create_index("ix_assets_asset_type", "assets", ["asset_type"])
    op.create_index("ix_assets_discovered_at", "assets", ["discovered_at"])
    op.execute("SELECT create_hypertable('assets', 'discovered_at', if_not_exists => TRUE)")

    op.create_table(
        "findings",
        sa.Column("id", UUID(as_uuid=True), nullable=False),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("scan_run_id", UUID(as_uuid=True), sa.ForeignKey("scan_runs.id"), nullable=False),
        sa.Column("asset_value", sa.String(512), nullable=False),
        sa.Column("finding_type", sa.String(255), nullable=False),
        sa.Column("source", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("detail", JSONB(), nullable=True),
        sa.Column("state", sa.String(50), nullable=False, server_default="open"),
        sa.Column("acknowledged_by_id", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("suppressed_until", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", "discovered_at"),
    )
    op.create_index("ix_findings_scan_run_id", "findings", ["scan_run_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_state", "findings", ["state"])
    op.create_index("ix_findings_discovered_at", "findings", ["discovered_at"])
    op.execute("SELECT create_hypertable('findings', 'discovered_at', if_not_exists => TRUE)")

    op.create_table(
        "audit_logs",
        sa.Column("id", UUID(as_uuid=True), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("action", sa.String(255), nullable=False),
        sa.Column("resource_type", sa.String(100), nullable=True),
        sa.Column("resource_id", sa.String(255), nullable=True),
        sa.Column("detail", JSONB(), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.PrimaryKeyConstraint("id", "occurred_at"),
    )
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_occurred_at", "audit_logs", ["occurred_at"])
    op.execute("SELECT create_hypertable('audit_logs', 'occurred_at', if_not_exists => TRUE)")


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("findings")
    op.drop_table("assets")
    op.drop_table("scan_runs")
    op.drop_table("users")
