"""Add Constellus Risk Score columns to findings_canonical.

Per-finding risk scoring (v1). Three enrichment modules populate the signal
columns post-scan (vulncheck_enrichment, vulnx_enrichment), then risk_scorer
computes risk_score / risk_band / building_velocity. All columns nullable —
the scorer degrades gracefully when VulnCheck/PDCP keys aren't configured.

Signal columns:
  has_exploit / exploit_count / ransomware_use / canary_detected  — VulnCheck KEV/XDB
  vulncheck_kev                                                   — membership in VulnCheck KEV
  is_template / is_poc                                            — vulnx / PDCP
  epss_score_previous                                            — prior EPSS sample, for Building Velocity

Computed columns:
  risk_score   — 0-100, tier-banded (Imminent 75-100 / High 50-74 / Elevated 25-49 / Low 1-24 / Secure 0)
  risk_band    — the verdict tier string (derivable from risk_score; stored for query convenience)
  building_velocity — orthogonal momentum flag (about to jump tiers)

Revision ID: 0031
Revises: 0030
Create Date: 2026-06-10
"""

from alembic import op
import sqlalchemy as sa


revision = "0031"
down_revision = "0030"
branch_labels = None
depends_on = None


_BANDS = ("imminent_compromise", "high", "elevated", "low", "secure")

_BOOL_COLS = (
    "has_exploit",
    "ransomware_use",
    "canary_detected",
    "is_template",
    "is_poc",
    "vulncheck_kev",
    "building_velocity",
)


def upgrade() -> None:
    for col in _BOOL_COLS:
        op.add_column("findings_canonical", sa.Column(col, sa.Boolean(), nullable=True))
    op.add_column("findings_canonical", sa.Column("exploit_count", sa.Integer(), nullable=True))
    op.add_column("findings_canonical", sa.Column("epss_score_previous", sa.Float(), nullable=True))
    op.add_column("findings_canonical", sa.Column("risk_score", sa.Integer(), nullable=True))
    op.add_column("findings_canonical", sa.Column("risk_band", sa.Text(), nullable=True))

    op.create_check_constraint(
        "ck_findings_canonical_risk_band",
        "findings_canonical",
        f"risk_band IS NULL OR risk_band IN ({', '.join(repr(b) for b in _BANDS)})",
    )
    op.create_check_constraint(
        "ck_findings_canonical_risk_score_range",
        "findings_canonical",
        "risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100)",
    )
    # Findings page default sort is by risk_score desc — index it.
    op.create_index(
        "ix_findings_canonical_risk_score",
        "findings_canonical",
        ["risk_score"],
    )


def downgrade() -> None:
    op.drop_index("ix_findings_canonical_risk_score", table_name="findings_canonical")
    op.drop_constraint("ck_findings_canonical_risk_score_range", "findings_canonical", type_="check")
    op.drop_constraint("ck_findings_canonical_risk_band", "findings_canonical", type_="check")
    for col in ("risk_band", "risk_score", "epss_score_previous", "exploit_count", *_BOOL_COLS):
        op.drop_column("findings_canonical", col)
