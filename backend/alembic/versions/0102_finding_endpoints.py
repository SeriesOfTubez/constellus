"""Record where each finding was observed (planning#347).

`finding_endpoints` holds one row per place a finding was observed: the
address, the port and the transport protocol, with first and last seen. It
exists because a finding's identity is (asset, finding_type, source,
fingerprint) and carries no port: the same flaw on two ports of one address,
or on two addresses behind one hostname, is ONE finding with several
endpoints. Until now the port lived only as a per-source key in `detail`
(last write wins) and the address a hostname finding was observed on was not
kept at all.

- `address` is a single host (`inet`, never a network). NULL means the source
  did not record which address it reached.
- `port` NULL means the source recorded no port (a host-level observation).
- `protocol` is the transport, `tcp` or `udp`. NULL means the source did not
  state it; it is never defaulted.
- A row has an address or a port (a protocol alone says nothing).
- One row per (finding, address, port, protocol), NULLs compared as equal, so
  re-observing an endpoint only moves `last_seen_at`.
- The observer is the finding's own `source`; a finding has exactly one.
- Rows are never deleted on re-observation: an endpoint that stops being seen
  keeps its older `last_seen_at`. They go with the finding (CASCADE).

Data change: backfills one endpoint per existing finding from what the row
already proves. The address comes from the finding's asset when that asset is
an address, or from `detail.origin_ip` for a dangling-DNS finding; the port
from a numeric `detail.port` in range; the protocol from `detail.protocol`
when it is tcp or udp. A finding that proves neither an address nor a port
gets no row. The parsing rules are written out here, not imported from the app.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0102"
down_revision = "0101"
branch_labels = None
depends_on = None


_BACKFILL = """
WITH proven AS (
    SELECT
        f.id AS finding_id,
        CASE
            WHEN a.asset_type = 'ip_address'
                 AND a.value NOT LIKE '%/%'
                 AND pg_input_is_valid(a.value, 'inet')
                THEN a.value::inet
            WHEN f.finding_type = 'dangling_dns'
                 AND jsonb_typeof(f.detail -> 'origin_ip') = 'string'
                 AND (f.detail ->> 'origin_ip') NOT LIKE '%/%'
                 AND pg_input_is_valid(f.detail ->> 'origin_ip', 'inet')
                THEN (f.detail ->> 'origin_ip')::inet
        END AS address,
        CASE
            WHEN jsonb_typeof(f.detail -> 'port') = 'number'
                 AND (f.detail ->> 'port') ~ '^[0-9]{1,5}$'
                 AND (f.detail ->> 'port')::integer BETWEEN 1 AND 65535
                THEN (f.detail ->> 'port')::integer
        END AS port,
        CASE
            WHEN jsonb_typeof(f.detail -> 'protocol') = 'string'
                 AND lower(f.detail ->> 'protocol') IN ('tcp', 'udp')
                THEN lower(f.detail ->> 'protocol')
        END AS protocol,
        f.first_seen_at,
        f.last_seen_at
    FROM findings_canonical f
    JOIN assets_canonical a ON a.id = f.asset_canonical_id
)
INSERT INTO finding_endpoints (finding_id, address, port, protocol, first_seen_at, last_seen_at)
SELECT finding_id, address, port, protocol, first_seen_at, last_seen_at
FROM proven
WHERE address IS NOT NULL OR port IS NOT NULL
"""


def upgrade() -> None:
    op.create_table(
        "finding_endpoints",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column(
            "finding_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("findings_canonical.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("address", postgresql.INET(), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.Text(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint(
            "finding_id", "address", "port", "protocol",
            name="uq_finding_endpoints_endpoint",
            postgresql_nulls_not_distinct=True,
        ),
        sa.CheckConstraint(
            "address IS NOT NULL OR port IS NOT NULL",
            name="ck_finding_endpoints_address_or_port",
        ),
        sa.CheckConstraint(
            "address IS NULL OR masklen(address) = CASE family(address) WHEN 4 THEN 32 ELSE 128 END",
            name="ck_finding_endpoints_address_is_host",
        ),
        sa.CheckConstraint(
            "port IS NULL OR (port >= 1 AND port <= 65535)",
            name="ck_finding_endpoints_port_range",
        ),
        sa.CheckConstraint(
            "protocol IS NULL OR protocol IN ('tcp', 'udp')",
            name="ck_finding_endpoints_protocol",
        ),
        sa.CheckConstraint(
            "last_seen_at >= first_seen_at",
            name="ck_finding_endpoints_last_after_first",
        ),
    )
    op.create_index("ix_finding_endpoints_address", "finding_endpoints", ["address"])
    op.create_index("ix_finding_endpoints_port", "finding_endpoints", ["port"])
    op.execute(_BACKFILL)


def downgrade() -> None:
    op.drop_index("ix_finding_endpoints_port", table_name="finding_endpoints")
    op.drop_index("ix_finding_endpoints_address", table_name="finding_endpoints")
    op.drop_table("finding_endpoints")
