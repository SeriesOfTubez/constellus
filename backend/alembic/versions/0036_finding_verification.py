"""Add shared-infra verification columns to findings_canonical (planning#77 / planning#103).

New per-finding verification dimension, ORTHOGONAL to `state` (the analyst's
triage state): `verification` records whether the automated shared-infra
verifier (services/shared_infra_verifier.py, epic#81 Phase A) could confirm
a host-level/passive finding is actually attributable to an asset we own,
using the domain-affinity primitive (planning#102) to probe owned hostnames
against the finding's IP.

- NULL: not checked (the default — most findings never go through this;
  it's scoped to host-level/passive sources per the epic's Phase-A mandate).
- 'unverified': checked, but couldn't reach a conclusion (no owned hostname
  resolves to the IP, or every probe came back indeterminate).
- 'confirmed_ours': at least one owned hostname shows affinity with the IP.
- 'rejected_shared_infra': every owned hostname probed shows NO affinity
  (co-tenant/default vhost only) — the finding is excluded from Risk Score
  / dashboard aggregates by default (see findings.py / assets.py query
  changes) but stays individually visible and reversible, never deleted.

verification_evidence stores the probe matrix + per-hostname reasoning that
produced the verdict (planning#102's AffinityResult.signals/matrix) so the
verdict is auditable, not a black box. verified_at is the verifier's own
timestamp — separate from last_seen_at, since a finding can be re-verified
on a later scan without a new observation.

Revision ID: 0036
Revises: 0035
Create Date: 2026-07-03
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0036"
down_revision = "0035"
branch_labels = None
depends_on = None

_VERIFICATION = ("unverified", "confirmed_ours", "rejected_shared_infra")


def upgrade() -> None:
    op.add_column("findings_canonical", sa.Column("verification", sa.Text(), nullable=True))
    op.add_column(
        "findings_canonical",
        sa.Column("verification_evidence", postgresql.JSONB(), nullable=True),
    )
    op.add_column("findings_canonical", sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True))

    op.create_check_constraint(
        "ck_findings_canonical_verification",
        "findings_canonical",
        f"verification IS NULL OR verification IN ({', '.join(repr(v) for v in _VERIFICATION)})",
    )
    # Dashboard/score queries filter out verification='rejected_shared_infra'
    # by default (see api/findings.py security_score, api/assets.py
    # _compute_asset_risk) — low cardinality, worth indexing.
    op.create_index("ix_findings_canonical_verification", "findings_canonical", ["verification"])


def downgrade() -> None:
    op.drop_index("ix_findings_canonical_verification", table_name="findings_canonical")
    op.drop_constraint("ck_findings_canonical_verification", "findings_canonical", type_="check")
    for col in ("verified_at", "verification_evidence", "verification"):
        op.drop_column("findings_canonical", col)
