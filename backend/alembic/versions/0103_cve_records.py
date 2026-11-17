"""CVE-level records and the first-confirmed stamp (planning#360).

`cve_records` holds one row per CVE for facts that are about the CVE, not about
a finding: the publication date (with the source it came from) and the date
VulnCheck listed it as exploited. `refreshed_at` is the last time a refresh of
the CVE was attempted and `refresh_failed` says that attempt failed; the
rolling refresh job orders by `refreshed_at`.

`findings_canonical.ownership_confirmed_at` is the first time a finding's
ownership verdict became `confirmed_ours`. It is never overwritten.

No backfill: existing findings keep NULL, because we do not know when they were
first confirmed and a guessed date is worse than none.
"""

import sqlalchemy as sa
from alembic import op

revision = "0103"
down_revision = "0102"
branch_labels = None
depends_on = None

CVE_PUBLISHED_SOURCES = ("vulncheck_nvd2",)
_SOURCES_SQL = ", ".join(f"'{s}'" for s in CVE_PUBLISHED_SOURCES)


def upgrade() -> None:
    op.create_table(
        "cve_records",
        sa.Column("cve_id", sa.Text(), primary_key=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("published_source", sa.Text(), nullable=True),
        sa.Column("vulncheck_kev_date_added", sa.Date(), nullable=True),
        sa.Column("refreshed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("refresh_failed", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint("cve_id = upper(cve_id)", name="ck_cve_records_cve_id_upper"),
        sa.CheckConstraint(
            f"published_source IS NULL OR published_source IN ({_SOURCES_SQL})",
            name="ck_cve_records_published_source",
        ),
        sa.CheckConstraint(
            "(published_at IS NULL) = (published_source IS NULL)",
            name="ck_cve_records_published_pair",
        ),
    )
    op.create_index("ix_cve_records_refreshed_at", "cve_records", ["refreshed_at"])
    op.add_column(
        "findings_canonical",
        sa.Column("ownership_confirmed_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("findings_canonical", "ownership_confirmed_at")
    op.drop_index("ix_cve_records_refreshed_at", table_name="cve_records")
    op.drop_table("cve_records")
