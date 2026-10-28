"""Page capture: the `page_capture` observer, `page_captures` and
`page_capture_requests` (planning#280 S5b-2a).

One `page_captures` row per capture: one ordinary page load of a scope
candidate's domain by the capture browser (`docs/architecture/capture-spool.md`).
The row is the record of the load, whether or not an image file is still kept
for it; S5b-2b prunes image FILES to the latest N per domain, never rows.

`page_capture_requests` holds one row per request the enforcing proxy saw for
that capture, read from the proxy's own log. That log is the only source of
`pinned_ip`: the browser cannot write it, so the IP the S5c cert signal leans on
is the proxy's word, not the page's.

The observer is `scan` / `observed` / `name` / `browse` (planning#280 comment
6443895725): a page load is one name-addressed request to the host.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0091"
down_revision = "0090"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "INSERT INTO observers (name, kind, trust, addressing, description, noise_class, confirms_relations) "
        "VALUES ('page_capture', 'scan', 'observed', 'name', "
        "'One ordinary page load of a domain by the capture browser: screenshot, final URL, "
        "redirect chain, title and certificate (planning#280).', 'browse', false)"
    )

    op.create_table(
        "page_captures",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column(
            "candidate_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scope_candidates.id", ondelete="RESTRICT"), nullable=False,
        ),
        sa.Column("domain", sa.Text(), nullable=False),
        sa.Column("observer_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("observers.id"), nullable=False),
        sa.Column("requested_url", sa.Text(), nullable=False),
        sa.Column(
            "requested_by_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
        ),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("status", sa.Text(), nullable=False, server_default=sa.text("'queued'")),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        # What the worker reported (result.json `error`), verbatim and length-capped by the ingest.
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("final_url", sa.Text(), nullable=True),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("redirect_chain", postgresql.JSONB(), nullable=True),
        sa.Column("title", sa.Text(), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("cert", postgresql.JSONB(), nullable=True),
        sa.Column("cert_sha256", sa.Text(), nullable=True),
        sa.Column("cert_san_dns", postgresql.ARRAY(sa.Text()), nullable=True),
        # The proxy-pinned IP of the request that fetched the final URL's document.
        sa.Column("pinned_ip", postgresql.INET(), nullable=True),
        sa.Column("proxy_log_truncated", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("image_path", sa.Text(), nullable=True),
        sa.Column("image_bytes", sa.Integer(), nullable=True),
        sa.Column("image_sha256", sa.Text(), nullable=True),
        sa.Column("image_quality", sa.SmallInteger(), nullable=True),
        sa.Column("image_omitted_reason", sa.Text(), nullable=True),
        sa.CheckConstraint("status IN ('queued', 'done', 'failed')", name="ck_page_captures_status"),
        sa.CheckConstraint(
            "(status = 'queued') = (finished_at IS NULL)", name="ck_page_captures_finished_follows_status"
        ),
        sa.CheckConstraint(
            "(status = 'failed') = (failure_reason IS NOT NULL)", name="ck_page_captures_failure_follows_status"
        ),
    )
    op.create_index("ix_page_captures_candidate_requested", "page_captures", ["candidate_id", "requested_at"])
    op.create_index("ix_page_captures_domain_requested", "page_captures", ["domain", "requested_at"])
    op.create_index(
        "ix_page_captures_queued", "page_captures", ["requested_at"], postgresql_where=sa.text("status = 'queued'")
    )
    # At most one queued capture per candidate: two concurrent requests must not
    # both pass the producer's already-queued check and make two live visits.
    op.create_index(
        "uq_page_captures_one_queued_per_candidate", "page_captures", ["candidate_id"],
        unique=True, postgresql_where=sa.text("status = 'queued'"),
    )

    op.create_table(
        "page_capture_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column(
            "capture_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("page_captures.id", ondelete="RESTRICT"), nullable=False,
        ),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=True),
        sa.Column("method", sa.Text(), nullable=True),
        sa.Column("scheme", sa.Text(), nullable=True),
        sa.Column("host", sa.Text(), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("resolved", postgresql.ARRAY(postgresql.INET()), nullable=True),
        sa.Column("pinned_ip", postgresql.INET(), nullable=True),
        sa.Column("decision", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("bytes_up", sa.BigInteger(), nullable=True),
        sa.Column("bytes_down", sa.BigInteger(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.UniqueConstraint("capture_id", "seq", name="uq_page_capture_requests_capture_seq"),
    )
    op.create_index("ix_page_capture_requests_host", "page_capture_requests", ["host"])


def downgrade() -> None:
    op.drop_table("page_capture_requests")
    op.drop_table("page_captures")
    op.execute("DELETE FROM observers WHERE name = 'page_capture'")
