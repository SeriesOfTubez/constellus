"""convert VARCHAR columns on hypertables to TEXT (TimescaleDB best practice)

Revision ID: 0012
Revises: 0011
Create Date: 2026-05-09
"""

from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None

# VARCHAR → TEXT is a metadata-only change in PostgreSQL; no table rewrite needed.

def upgrade() -> None:
    # assets hypertable
    op.execute("ALTER TABLE assets ALTER COLUMN asset_type TYPE TEXT")
    op.execute("ALTER TABLE assets ALTER COLUMN value TYPE TEXT")
    op.execute("ALTER TABLE assets ALTER COLUMN parent_value TYPE TEXT")

    # findings hypertable
    for col in ("asset_value", "finding_type", "source", "severity",
                "title", "state", "category", "cve_id",
                "cvss_vector", "cvss_version", "cwe"):
        op.execute(f"ALTER TABLE findings ALTER COLUMN {col} TYPE TEXT")

    # audit_logs hypertable
    for col in ("action", "resource_type", "resource_id", "ip_address"):
        op.execute(f"ALTER TABLE audit_logs ALTER COLUMN {col} TYPE TEXT")


def downgrade() -> None:
    # TEXT → VARCHAR(N) would require choosing lengths; just leave as TEXT on downgrade
    pass
