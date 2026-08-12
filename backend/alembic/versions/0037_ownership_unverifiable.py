"""Add 'ownership_unverifiable' to findings_canonical.verification (epic#81 Phase D, planning#108).

A fourth value between 'unverified' and 'rejected_shared_infra': the
shared-infra verifier (services/shared_infra_verifier.py) could not
directly disprove ownership (the aggregate isn't a unanimous not_affine —
that's still 'rejected_shared_infra''s job), but positive counter-evidence
exists that the origin genuinely serves a different, unrelated tenant —
a HackerTarget/Shodan-corroborated hostname with a matching TLS cert, a
Shodan-banner identity mismatch, or (supporting only) a fingerprintable
CVE's product not showing up in the owned vhost's own tech-detect.

Deliberately NOT a hard reject: 'rejected_shared_infra' means "we directly
disproved ownership" (unanimous not_affine across every owned hostname).
Corroboration is inferential — "the origin serves someone else" proves the
box is alive-for-somebody, not that our vulnerable artifact isn't ALSO
reachable under our own vhost (shared hosting tenants coexist by design).
'ownership_unverifiable' gets the same behavioral treatment as a reject
(excluded from the main findings list, Risk Score, dashboard aggregates,
and notifications — see api/findings.py, api/assets.py,
services/notification_dispatcher.py) without asserting that stronger,
unsupported epistemic claim.

See Constellus — Epic 81 Phase D (Ownership Unverifiable), vault doc, for
the full design + the live dry run that validated this against the
epic's own contoso.com motivating case.

Revision ID: 0037
Revises: 0036
Create Date: 2026-07-05
"""

from alembic import op

revision = "0037"
down_revision = "0036"
branch_labels = None
depends_on = None

_VERIFICATION = ("unverified", "confirmed_ours", "rejected_shared_infra", "ownership_unverifiable")
_OLD_VERIFICATION = ("unverified", "confirmed_ours", "rejected_shared_infra")


def upgrade() -> None:
    op.drop_constraint("ck_findings_canonical_verification", "findings_canonical", type_="check")
    op.create_check_constraint(
        "ck_findings_canonical_verification",
        "findings_canonical",
        f"verification IS NULL OR verification IN ({', '.join(repr(v) for v in _VERIFICATION)})",
    )


def downgrade() -> None:
    op.drop_constraint("ck_findings_canonical_verification", "findings_canonical", type_="check")
    op.create_check_constraint(
        "ck_findings_canonical_verification",
        "findings_canonical",
        f"verification IS NULL OR verification IN ({', '.join(repr(v) for v in _OLD_VERIFICATION)})",
    )
