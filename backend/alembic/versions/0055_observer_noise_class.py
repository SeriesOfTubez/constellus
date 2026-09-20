"""Replace observers.emits_traffic_to_target with noise_class (planning#196 step 1).

planning#196 needs "which observers are too noisy for a pre-close M&A
target" to be **data on the observer**, not a hardcoded list in the
discovery phase (that hardcoded list is exactly the shape of bug
planning#193 shipped with: `dnsrecon` is gated but `bruteforce` — which
hammers the target's own authoritative nameservers just as hard — is not).
This migration adds that data. It changes no behaviour: nothing reads
`noise_class` yet. Wiring it into the gate/discovery phase is step 2, a
separate piece of work.

Why this is a new axis rather than an overload of `addressing`:
`addressing` answers "did this observer send traffic to the target asset",
because that is what decides which authorisation grant
(`OBSERVER_ADDRESSING` — ip / name / none / ip_handshake) a claim from this
observer can satisfy. Overloading it with a noise decision would couple
claim-authorisation semantics to a question `addressing` was never designed
to answer, and there is no honest value to give `bruteforce`: it is
`addressing = 'none'` (no packet reaches the target host — the wordlist
lookups resolve through the operator's own resolver) and yet 60-250
NXDOMAIN lookups land on the target's own authoritative nameservers, which
is exactly the kind of activity a counterparty could notice. `addressing`
cannot express that without contradicting what it already means for every
other observer.

Why `emits_traffic_to_target` is replaced rather than kept or supplemented:
it was seeded on all 23 rows and is exactly equal to `addressing != 'none'`
— zero rows disagree — so it carries no information `addressing` doesn't
already carry. Nothing in production reads it: only the model definition,
the migrations that wrote it, and four test assertions about seeded
taxonomy. And at least one of its values is outright wrong:
`dangling_dns_analyzer` is seeded `true` even though it is pure DB analysis
over already-collected claims — it imports nothing network-capable and
performs no I/O at all. Keeping it alongside `noise_class` would leave the
model with three axes where the third is a duplicate of the first, which is
worse than not having it. It is dropped in this same migration.

The `third_party_infra` boundary, because it is the one a future reader
will want to "tidy" back into `silent`: it is permitted pre-close
**deliberately, not because it is obviously silent**. A `dns_resolve` cache
miss does reach the counterparty's authoritative nameservers, the same
infrastructure `target_infra` denies traffic to. The line planning#193
shipped, and this migration's classification reproduces exactly, is
*"resolve names we already know" permitted, "enumerate names we are
guessing" denied* — a distinction of volume and pattern (one lookup per
already-discovered name vs. 60-250+ speculative wordlist lookups), not
strictly whether a packet ever arrives at the counterparty's resolver.

`shared_infra_verifier` is classified by **consequence, not behaviour**: it
sends nothing itself, but it calls `domain_affinity.check_affinity`
(`shared_infra_verifier.py:201`), which does probe. The noise axis answers
"could the counterparty notice", and the counterparty cannot tell which
module in our call graph originated a packet — so it is seeded
`target_host`, and its seeded `description` is updated to say so, so a
future reader does not "correct" it back to `silent` for looking
behaviourally inert in isolation.

This mapping is meant to reproduce planning#193's shipped behaviour
exactly, which is the property that lets step 2 be a refactor rather than
a policy change:

    passive-only = deny target_infra and target_host; permit silent and
    third_party_infra

Checked against what planning#193 ships today: `dnsrecon` and `bruteforce`
are both denied today (both classified `target_infra` here); every
observer that reaches the probe-authorisation gate is denied today (all
classified `target_host` here); `subfinder`, Certificate Transparency,
`dns_resolve`, `dns_records`, and Shodan are permitted today (`silent` /
`third_party_infra` here).

The `downgrade()` backfill — `emits_traffic_to_target = (addressing !=
'none')` — exactly reproduces the pre-migration state; verified against the
live table, all 23 rows agree. That is what makes this downgrade honest
rather than approximate: replaying it recreates the exact column this
migration removes, not merely a column of the same name and type.

Revision ID: 0055
Revises: 0054
Create Date: 2026-09-20
"""

from alembic import op
import sqlalchemy as sa


revision = "0055"
down_revision = "0054"
branch_labels = None
depends_on = None


# Mirrors app/models/observer.py's OBSERVER_NOISE (companion change, same
# commit).
OBSERVER_NOISE = ("silent", "third_party_infra", "target_infra", "target_host")

# (name, noise_class) for all 23 seeded observers (migrations 0039, 0048,
# 0049, 0050, 0051). Seeded from each module's ACTUAL BEHAVIOUR, never by
# analogy to `addressing` — see the module docstring above for why that
# matters (it's exactly how `emits_traffic_to_target` went wrong for
# `dangling_dns_analyzer`).
NOISE_SEED = (
    # target_host (8) — packets at the target host itself.
    ("naabu", "target_host"),
    ("banner_grab", "target_host"),
    ("httpx", "target_host"),
    ("tlsx", "target_host"),
    ("nuclei", "target_host"),
    ("tenancy_tls", "target_host"),
    ("domain_affinity", "target_host"),
    ("shared_infra_verifier", "target_host"),  # by consequence — see docstring
    # target_infra (2) — queries the TARGET'S OWN authoritative nameservers.
    ("dnsrecon", "target_infra"),
    ("bruteforce", "target_infra"),
    # third_party_infra (3) — queries someone else's infrastructure (public
    # recursors), not the target's.
    ("dns_resolve", "third_party_infra"),
    ("dns_records", "third_party_infra"),
    ("tenancy_ptr", "third_party_infra"),
    # silent (10) — no network I/O attributable to us.
    ("subfinder", "silent"),
    ("cert_transparency", "silent"),
    ("shodan", "silent"),
    ("wiz", "silent"),
    ("cloudflare", "silent"),
    ("hosting_classifier", "silent"),
    ("tenancy_enricher", "silent"),
    ("eol_enrichment", "silent"),
    ("cpe_normalizer", "silent"),
    ("dangling_dns_analyzer", "silent"),
)

_SHARED_INFRA_VERIFIER_DESCRIPTION = (
    "Confirms or rejects ownership of shared-infrastructure findings. "
    "Classified target_host by consequence, not behaviour: it sends nothing "
    "itself but triggers domain_affinity probes (shared_infra_verifier.py:201), "
    "and the counterparty cannot tell which module in our call graph "
    "originated a packet."
)


def upgrade() -> None:
    # ── observers.noise_class ────────────────────────────────────────────
    # Seeding goes through SQLAlchemy Core expressions against an sa.table()
    # handle, not interpolated SQL strings — the idiom every other migration
    # that touches `observers` already uses (0039/0048/0049/0050/0051, all
    # via bulk_insert on exactly this handle). The values here are module
    # constants rather than anything caller-supplied, so this is about
    # staying on one idiom rather than about injection: the repo builds no
    # SQL by string concatenation over DATA, and the one f-string
    # `op.execute` in its history (0012) interpolates column IDENTIFIERS,
    # which cannot be bound as parameters. `noise_class` can.
    observers = sa.table(
        "observers",
        sa.column("name", sa.Text()),
        sa.column("noise_class", sa.Text()),
        sa.column("description", sa.Text()),
    )

    op.add_column("observers", sa.Column("noise_class", sa.Text(), nullable=True))

    for name, noise_class in NOISE_SEED:
        op.execute(
            observers.update().where(observers.c.name == name).values(noise_class=noise_class)
        )

    # NOT NULL is the guard, not a formality: an observer seeded by some
    # later migration and never classified here leaves a NULL, and this
    # ALTER fails loudly on it rather than letting an unclassified observer
    # default quietly into whatever step 2 treats as permitted.
    op.alter_column("observers", "noise_class", nullable=False)

    # Built from a TUPLE, not the model's frozenset: frozenset iteration
    # order is not guaranteed stable across processes, so generating the
    # constraint text from one would make the emitted DDL vary run to run.
    noise_class_check = " OR ".join(f"noise_class = '{v}'" for v in OBSERVER_NOISE)
    op.create_check_constraint("ck_observers_noise_class", "observers", noise_class_check)

    # `shared_infra_verifier` is classified by consequence, not behaviour
    # (see module docstring) — say so in its seeded description, otherwise a
    # future reader "corrects" it back to `silent` for looking behaviourally
    # inert. Every other seeded description is left unchanged.
    op.execute(
        observers.update()
        .where(observers.c.name == "shared_infra_verifier")
        .values(description=_SHARED_INFRA_VERIFIER_DESCRIPTION)
    )

    op.drop_column("observers", "emits_traffic_to_target")


def downgrade() -> None:
    # Re-add emits_traffic_to_target and backfill it from `addressing` — the
    # exact expression this column always satisfied (see module docstring).
    op.add_column("observers", sa.Column("emits_traffic_to_target", sa.Boolean(), nullable=True))
    op.execute(
        sa.text("UPDATE observers SET emits_traffic_to_target = (addressing <> 'none')")
    )
    op.alter_column("observers", "emits_traffic_to_target", nullable=False)

    op.drop_constraint("ck_observers_noise_class", "observers", type_="check")
    op.drop_column("observers", "noise_class")
