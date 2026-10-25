"""RIR lookup cache (planning#278 S3b1).

Org discovery looks up ARIN Whois-RWS records by contact-email domain and by
handle (POCs, orgs, nets, ASNs). `rir_lookup_cache` holds those responses so a
repeat run inside the TTL makes no network request. The fetcher is
`app/services/org_discovery/rir_fetch.py`; generators come in a later slice.

It is a new table rather than more columns on `whois_cache` because that
table is keyed by IP with `org` / `asn` columns; putting handle-keyed RIR
responses in it would change what those columns mean.

- Primary key (`rir`, `path`): `path` is the path under the registry's fixed
  base URL (e.g. `poc/<handle>/orgs`).
- Only 200 and 404 are cached. `body` is the parsed JSON object for a 200 and
  NULL for a 404.
- `ck_rir_lookup_cache_rir`: rir in ('arin', 'ripe') (RIPE joins in S3b2).
- `ck_rir_lookup_cache_status`: status_code in (200, 404).
- `ck_rir_lookup_cache_body_iff_200`: a body exists exactly for a 200.
- `ck_rir_lookup_cache_path_nonblank`: the path is not blank.

Downgrade drops the table.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0088"
down_revision = "0087"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "rir_lookup_cache",
        sa.Column("rir", sa.Text(), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("status_code", sa.SmallInteger(), nullable=False),
        sa.Column("body", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("fetched_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("rir", "path", name="pk_rir_lookup_cache"),
        sa.CheckConstraint("rir IN ('arin', 'ripe')", name="ck_rir_lookup_cache_rir"),
        sa.CheckConstraint("status_code IN (200, 404)", name="ck_rir_lookup_cache_status"),
        sa.CheckConstraint("(status_code = 200) = (body IS NOT NULL)", name="ck_rir_lookup_cache_body_iff_200"),
        sa.CheckConstraint("length(btrim(path)) > 0", name="ck_rir_lookup_cache_path_nonblank"),
    )


def downgrade() -> None:
    op.drop_table("rir_lookup_cache")
