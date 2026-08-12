"""Auto-verify existing unverified targets

The UI-driven domain TXT verification flow has been removed. Targets are now
implicitly trusted on add — the operator confirms authorisation via the warning
in the Add Target dialog. Any rows that were created under the old flow and
remained verified=False are stranded (no UI to verify them, no scanner gate
will admit them under strict mode). Backfill them to verified=true with
method='manual' so they participate in scanning going forward.

Backend plumbing for verification (columns, /verify and /acknowledge endpoints,
scan_authorisation_mode setting) is kept in place — only the UI was removed.

Revision ID: 0019
Revises: 0018
Create Date: 2026-05-27
"""

from alembic import op


revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        UPDATE targets
           SET verified = true,
               verification_method = 'manual',
               verified_at = NOW()
         WHERE verified = false
    """)


def downgrade() -> None:
    op.execute("""
        UPDATE targets
           SET verified = false,
               verification_method = NULL,
               verified_at = NULL
         WHERE verification_method = 'manual'
    """)
