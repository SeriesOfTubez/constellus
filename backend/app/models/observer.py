import uuid

from sqlalchemy import Boolean, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# Observer kind vocabulary — what class of activity produced the claim.
# Adding a new kind means editing the CHECK constraint in a follow-up
# migration AND this frozenset (see EDGE_TYPES in asset_edge.py for the
# established pattern).
OBSERVER_KINDS: frozenset[str] = frozenset({
    "scan",       # active network probe (naabu, tlsx, httpx, banner_grab)
    "discovery",  # enumeration / resolution (subfinder, dns_resolve, ...)
    "connector",  # third-party API (shodan, cloudflare)
    "verify",     # derives a claim from other claims, no independent probe
    "enrich",     # attaches context to an already-discovered asset
})

# Observer trust vocabulary — how directly the observer's claim was obtained.
OBSERVER_TRUST: frozenset[str] = frozenset({
    "observed",  # first-hand network/API observation
    "derived",   # computed from other observed claims, no independent probe
    "inferred",  # third-party/heuristic inference, no direct observation
})

# Addressing mode the observer used to reach the target, if any. Determines
# which authorisation grant (ip vs name) a claim from this observer can
# satisfy. 'none' = the observer never sent traffic to the target itself.
# 'ip_handshake' = a single unauthenticated TLS handshake to a bare IP, no
# payload and no port sweep — narrower than 'ip', and deliberately a distinct
# mode so that name_only assets can be granted it without being granted full
# 'ip' probing (planning#181 Tier 1b).
OBSERVER_ADDRESSING: frozenset[str] = frozenset({
    "ip",
    "name",
    "none",
    "ip_handshake",
})

# Noise class — what a THIRD PARTY could notice, which is a different
# question from `addressing` above. `addressing` answers "did this observer
# send traffic to the target asset", because that is what decides which
# authorisation grant a claim satisfies (see OBSERVER_ADDRESSING). It cannot
# express "could the counterparty notice", and `bruteforce` is exactly where
# the two diverge: addressing='none' (no packet reaches the target host) yet
# 60-250 NXDOMAIN lookups land on the target's own authoritative nameservers.
# planning#193 hit that wall; planning#196 is the fix.
#
# Ordered least to most noticeable. Seeded from each module's ACTUAL
# BEHAVIOUR, never by analogy to `addressing` — the column this replaces was
# seeded that way and was consequently both useless and, for
# dangling_dns_analyzer, wrong.
OBSERVER_NOISE: frozenset[str] = frozenset({
    "silent",             # no network I/O attributable to us: third-party APIs, or derived from existing claims
    "third_party_infra",  # queries someone else's infrastructure (public recursors), not the target's
    "target_infra",       # queries the TARGET'S OWN infrastructure — authoritative nameservers
    "target_host",        # packets at the target host itself
})


class Observer(Base):
    """Registry of claim producers — the L0 grounding ontology's observer
    identity axis (planning#142).

    One row per named producer (connector, scanner module, or analyzer) that
    can write an asset_claims row. `name` is the stable slug producers
    self-report via DiscoveredAsset.observer (connectors/base.py); claims FK
    to `id` rather than storing the name inline so the taxonomy
    (kind/trust/addressing) is looked up once per observer, not duplicated
    onto every claim row. Seeded in migration 0039 — see that file's
    docstring for the current producer roster and the tlsx/httpx addressing
    simplification.

    This is a green slice (L1): the table exists and is seeded, but nothing
    yet writes asset_claims rows or reads this table for a gate decision.

    `noise_class` (migration 0055, planning#196) is a second, independent
    axis: what a third party could notice, as opposed to `addressing`'s
    "did this observer send traffic to the target". `addressing` is
    deliberately untouched by that migration — it keeps deciding claim
    authorisation and carries no noise information itself.

    `confirms_relations` (migration 0061, planning#212) is a THIRD,
    independent axis for the entity graph: may a relation asserted by this
    observer auto-confirm without a person deciding it. It is per-observer,
    not derived from `trust`, because `trust = 'observed'` alone cannot
    express "SEC filing yes, Wayback capture no" — both are `observed`.
    `ck_observers_inferred_never_confirms` guarantees it can never be `true`
    for an `inferred` observer, and `uq_observers_id_confirms_relations`
    lets `entity_relations` pin a denormalised copy of this column to this
    row with a composite FK (see that migration's docstring).
    """

    __tablename__ = "observers"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    trust: Mapped[str] = mapped_column(Text, nullable=False)
    addressing: Mapped[str] = mapped_column(Text, nullable=False)
    noise_class: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    confirms_relations: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=text("false"))
