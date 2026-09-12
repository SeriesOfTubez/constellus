"""Seed the `wiz` observer — the first internal claim source.

`cloud_inventory` has been a seeded claim type since migration 0039 and the
projector has consumed it since planning#145 L4 (`confirmed is True` ->
`estate = "proven_ours"`, outranking every other estate rule). It has never
had a producer. Every one of the 18 observers seeded by 0039 is an
external-observation source — we look at the outside of an estate and infer
inward. This row is the first that reads an estate's own control plane.

Why the taxonomy values are what they are:

  * `kind = "connector"` — a third-party API, same class as `shodan` and
    `cloudflare`.
  * `trust = "observed"` — matches `cloudflare`, NOT `shodan`. The
    distinction 0039 drew between those two is exactly the one that matters
    here: `shodan` is `inferred` because it reports someone else's scan of
    an estate from the outside; `cloudflare` is `observed` because it reads
    an account we hold credentials for. Wiz is the latter — a credentialed
    read of our own cloud inventory. `cloud_inventory` is *defined* as
    credentialed proof of ownership (planning#142 D1), so a producer of it
    that was only `inferred` would be a contradiction in terms.
  * `emits_traffic_to_target = False`, `addressing = "none"` — Wiz never
    sends a packet to the asset; it answers from its own graph. Note what
    this costs, deliberately: `addressing = "none"` means the
    probe-authorisation gate will refuse `wiz` as a *prober*
    (`observer_addressing_none`, see probe_authorisation.py). That is
    correct and intended. `wiz` is a claim PRODUCER whose claims authorise
    *other* connectors' probes; it is not itself a probe.

Scope note (planning#118a): this seeds the observer only. The connector
that writes rows attributed to it lands in the same slice, but the
migration is deliberately separable — a deployment that never configures
Wiz simply has an observer row nothing references, which is inert.
"""

import sqlalchemy as sa
from alembic import op

revision = "0048"
down_revision = "0047"
branch_labels = None
depends_on = None

_OBSERVER = (
    "wiz",
    "connector",
    "observed",
    False,
    "none",
    "Credentialed cloud inventory pulled from a connected Wiz tenant.",
)


def upgrade() -> None:
    observers = sa.table(
        "observers",
        sa.column("name", sa.Text()),
        sa.column("kind", sa.Text()),
        sa.column("trust", sa.Text()),
        sa.column("emits_traffic_to_target", sa.Boolean()),
        sa.column("addressing", sa.Text()),
        sa.column("description", sa.Text()),
    )
    name, kind, trust, emits, addressing, description = _OBSERVER
    op.bulk_insert(
        observers,
        [{
            "name": name,
            "kind": kind,
            "trust": trust,
            "emits_traffic_to_target": emits,
            "addressing": addressing,
            "description": description,
        }],
    )


def downgrade() -> None:
    # asset_claims.observer_id FKs to observers.id with no ON DELETE, so this
    # will (correctly) fail rather than orphan claims if any wiz claim exists.
    op.execute("DELETE FROM observers WHERE name = 'wiz'")
