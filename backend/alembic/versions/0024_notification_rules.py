"""Add notification_rules for finding alerts via the Mailtrap connector

Operators define one or more rules: "notify these recipients when a
finding lands at or above severity X, optionally restricted to certain
categories." When a finding_canonical row is newly inserted by the
finding_writer the dispatcher walks enabled rules and fires email via
whichever NotificationConnector (Mailtrap today) is enabled.

severity_threshold values: critical | high | medium | low | info.
Severity ordering critical > high > medium > low > info.

recipients is a JSONB array of email addresses. categories is JSONB; an
empty list means the rule matches any category.

Revision ID: 0024
Revises: 0023
Create Date: 2026-05-28
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID


revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "notification_rules",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("severity_threshold", sa.String(length=20), nullable=False, server_default=sa.text("'high'")),
        sa.Column("categories", JSONB(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("recipients", JSONB(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_notification_rules_enabled", "notification_rules", ["enabled"])


def downgrade() -> None:
    op.drop_index("ix_notification_rules_enabled", table_name="notification_rules")
    op.drop_table("notification_rules")
