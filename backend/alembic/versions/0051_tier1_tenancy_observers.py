"""Tier 1 tenancy observers + widened observer addressing vocabulary (planning#181 Tier 1).

Scaffolding only (slice 1 of 2): seeds the two Tier 1 observers and widens
the `observers.addressing` CHECK to accept the new `ip_handshake` mode. No
producer code, no evidence-classification logic, and no scanner-worker
change land here — those are slice 2's. Nothing in this migration changes
any live gate decision: nothing yet declares `tenancy_ptr`/`tenancy_tls` as
a prober, so `probe_authorisation` never sees an `ip_handshake` connector
in practice until slice 2 lands.

Why the addressing vocabulary grew: `app.services.probe_authorisation`'s
gate licenses probe addressing per `probe_class`, and Tier 1b (the no-SNI
TLS certificate) needs to reach a `name_only` asset — one whose tenancy is
undetermined — to collect the evidence that would resolve that tenancy.
Granting it full `ip` addressing would license a bare-IP connect and a port
sweep to resolve that circularity, which is a much bigger widening than the
single unauthenticated TLS handshake Tier 1b actually needs. `ip_handshake`
is added as a third, strictly narrower addressing mode instead: one
handshake, no payload, no port sweep. `name_only` is then granted
`ip_handshake` alongside `name` (see `probe_authorisation._probe_class_cap`)
while `ip` stays denied there — the carve-out is argued in that function's
docstring, not assumed.

Two Tier 1 observers, not one, because the two halves have genuinely
different gate status and `asset_claims`' uniqueness constraint is
(asset, observer, claim_type) — one observer could only ever hold one of
them:
  - `tenancy_ptr` — reverse-DNS. A resolver query, no traffic to the
    target, `addressing = "none"`, never passes through the gate.
  - `tenancy_tls` — bare-IP no-SNI TLS handshake. Emits traffic,
    `addressing = "ip_handshake"`, authorised per-asset by the gate like
    any other connector.

Companion changes in the same commit: `app/models/observer.py`
(`OBSERVER_ADDRESSING` += "ip_handshake"), `app/services/probe_authorisation.py`
(`ADDRESSING_MODES` += "ip_handshake", `_probe_class_cap`'s `name_only`/
`direct_addressable` caps widened), `app/services/projector.py`
(`_TENANCY_OBSERVERS` += the two new names, `_PROMOTING_TIERS` += 1).

Revision ID: 0051
Revises: 0050
Create Date: 2026-09-19
"""

import sqlalchemy as sa
from alembic import op

revision = "0051"
down_revision = "0050"
branch_labels = None
depends_on = None


# Mirrors app/models/observer.py's OBSERVER_ADDRESSING before/after this
# migration (companion change, same commit).
_PRIOR_ADDRESSING = ("ip", "name", "none")
_NEW_ADDRESSING = ("ip", "name", "none", "ip_handshake")

_OBSERVERS = (
    (
        "tenancy_ptr",
        "enrich",
        "inferred",
        False,
        "none",
        "Derives IP tenancy from the address's reverse-DNS record (planning#181 Tier 1a). "
        "Sends no traffic to the target: a PTR lookup is a resolver query, so this observer "
        "never passes through the probe-authorisation gate.",
    ),
    (
        "tenancy_tls",
        "enrich",
        "inferred",
        True,
        "ip_handshake",
        "Derives IP tenancy from the certificate a bare-IP no-SNI TLS handshake returns "
        "(planning#181 Tier 1b). Emits traffic to the target and is authorised per-asset by "
        "the probe-authorisation gate under the `ip_handshake` mode.",
    ),
)


def upgrade() -> None:
    # ── widen observers.addressing to admit ip_handshake ───────────────────
    op.drop_constraint("ck_observers_addressing", "observers", type_="check")
    op.create_check_constraint(
        "ck_observers_addressing",
        "observers",
        " OR ".join(f"addressing = '{v}'" for v in _NEW_ADDRESSING),
    )

    # ── observers += tenancy_ptr, tenancy_tls ───────────────────────────────
    observers = sa.table(
        "observers",
        sa.column("name", sa.Text()),
        sa.column("kind", sa.Text()),
        sa.column("trust", sa.Text()),
        sa.column("emits_traffic_to_target", sa.Boolean()),
        sa.column("addressing", sa.Text()),
        sa.column("description", sa.Text()),
    )
    op.bulk_insert(
        observers,
        [
            {
                "name": name,
                "kind": kind,
                "trust": trust,
                "emits_traffic_to_target": emits,
                "addressing": addressing,
                "description": description,
            }
            for name, kind, trust, emits, addressing, description in _OBSERVERS
        ],
    )


def downgrade() -> None:
    # Rows that REFERENCE the observers first. `asset_claims.observer_id` and
    # `authorisation_decisions.observer_id` are both plain FKs to
    # `observers.id` with no ON DELETE action (migration 0039), so once slice
    # 2 ships the producers this DELETE would otherwise fail on an FK
    # violation rather than downgrade. Same shape as 0050's downgrade, which
    # clears asset_claims before dropping its claim type.
    #
    # `claim_history.observer_id` is deliberately NOT included: it is a
    # hand-written partitioned table whose observer_id is a bare uuid column
    # with no FK (0039), so it does not block, and it is the append-only
    # audit trail — a downgrade should not rewrite history.
    op.execute(
        "DELETE FROM asset_claims WHERE observer_id IN "
        "(SELECT id FROM observers WHERE name IN ('tenancy_ptr', 'tenancy_tls'))"
    )
    op.execute(
        "DELETE FROM authorisation_decisions WHERE observer_id IN "
        "(SELECT id FROM observers WHERE name IN ('tenancy_ptr', 'tenancy_tls'))"
    )

    # Then the observers themselves — the CHECK cannot be narrowed back while
    # tenancy_tls' row (addressing = 'ip_handshake') violates it, the same
    # ordering hazard 0050's downgrade comments call out for claim types.
    op.execute("DELETE FROM observers WHERE name IN ('tenancy_ptr', 'tenancy_tls')")

    op.drop_constraint("ck_observers_addressing", "observers", type_="check")
    op.create_check_constraint(
        "ck_observers_addressing",
        "observers",
        " OR ".join(f"addressing = '{v}'" for v in _PRIOR_ADDRESSING),
    )
