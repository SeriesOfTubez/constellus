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
OBSERVER_ADDRESSING: frozenset[str] = frozenset({
    "ip",
    "name",
    "none",
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
    """

    __tablename__ = "observers"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    trust: Mapped[str] = mapped_column(Text, nullable=False)
    emits_traffic_to_target: Mapped[bool] = mapped_column(Boolean, nullable=False)
    addressing: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
