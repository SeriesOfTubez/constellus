"""Add SSVC (CISA Vulnrichment) columns to findings_canonical.

SSVC decision points ingested per-CVE from the CVE.org CISA-ADP "Vulnrichment"
block (ssvc_enrichment): Exploitation (none/poc/active), Automatable (yes/no →
bool), Technical Impact (total/partial). ssvc_source distinguishes a real
Vulnrichment value from a derived CVSS-vector fallback (chunk c); ssvc_scored_at
is CISA's SSVC timestamp (provenance / staleness). All nullable — a CVE CISA
hasn't scored leaves these NULL and the derived fallback takes over, never an error.

These are orthogonal Risk-Score signals (Automatable → capability axis; Technical
Impact → impact term) and the basis for a future BOD-26-04 remediation-deadline
lens. Indexed for finding-list filter facets + group-by (low cardinality).

Revision ID: 0034
Revises: 0033
Create Date: 2026-06-18
"""

from alembic import op
import sqlalchemy as sa


revision = "0034"
down_revision = "0033"
branch_labels = None
depends_on = None

_EXPLOITATION = ("none", "poc", "active")
_TECH_IMPACT = ("total", "partial")
_SOURCE = ("vulnrichment", "derived")


def upgrade() -> None:
    op.add_column("findings_canonical", sa.Column("ssvc_exploitation", sa.Text(), nullable=True))
    op.add_column("findings_canonical", sa.Column("ssvc_automatable", sa.Boolean(), nullable=True))
    op.add_column("findings_canonical", sa.Column("ssvc_technical_impact", sa.Text(), nullable=True))
    op.add_column("findings_canonical", sa.Column("ssvc_source", sa.Text(), nullable=True))
    op.add_column("findings_canonical", sa.Column("ssvc_scored_at", sa.DateTime(timezone=True), nullable=True))

    op.create_check_constraint(
        "ck_findings_canonical_ssvc_exploitation",
        "findings_canonical",
        f"ssvc_exploitation IS NULL OR ssvc_exploitation IN ({', '.join(repr(v) for v in _EXPLOITATION)})",
    )
    op.create_check_constraint(
        "ck_findings_canonical_ssvc_technical_impact",
        "findings_canonical",
        f"ssvc_technical_impact IS NULL OR ssvc_technical_impact IN ({', '.join(repr(v) for v in _TECH_IMPACT)})",
    )
    op.create_check_constraint(
        "ck_findings_canonical_ssvc_source",
        "findings_canonical",
        f"ssvc_source IS NULL OR ssvc_source IN ({', '.join(repr(v) for v in _SOURCE)})",
    )
    # Filter facets + group-by on the SSVC axes (low cardinality).
    op.create_index("ix_findings_canonical_ssvc_automatable", "findings_canonical", ["ssvc_automatable"])
    op.create_index("ix_findings_canonical_ssvc_technical_impact", "findings_canonical", ["ssvc_technical_impact"])
    op.create_index("ix_findings_canonical_ssvc_exploitation", "findings_canonical", ["ssvc_exploitation"])


def downgrade() -> None:
    op.drop_index("ix_findings_canonical_ssvc_exploitation", table_name="findings_canonical")
    op.drop_index("ix_findings_canonical_ssvc_technical_impact", table_name="findings_canonical")
    op.drop_index("ix_findings_canonical_ssvc_automatable", table_name="findings_canonical")
    op.drop_constraint("ck_findings_canonical_ssvc_source", "findings_canonical", type_="check")
    op.drop_constraint("ck_findings_canonical_ssvc_technical_impact", "findings_canonical", type_="check")
    op.drop_constraint("ck_findings_canonical_ssvc_exploitation", "findings_canonical", type_="check")
    for col in ("ssvc_scored_at", "ssvc_source", "ssvc_technical_impact", "ssvc_automatable", "ssvc_exploitation"):
        op.drop_column("findings_canonical", col)
