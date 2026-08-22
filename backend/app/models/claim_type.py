from datetime import timedelta

from sqlalchemy import Interval, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class ClaimType(Base):
    """Reference table for the L0 grounding-claim vocabulary (planning#142).

    This IS the L0 grounding ontology — one row per claim type a claim
    producer can assert, seeded in migration 0039. `claim_type` doubles as
    the FK target for `asset_claims.claim_type`.

    `authorisation_ttl` / `reporting_ttl` encode Decision D2: authorisation-
    grade freshness is a per-claim-type policy here, not a second timestamp
    on every claim row. A NULL `authorisation_ttl` means this claim type
    never authorises a probe (the default — only `affinity_confirmation`
    and `cloud_inventory` currently have one). `default_trust` is advisory
    only; the trust an individual claim actually carries travels on the
    observer that produced it (see Observer.trust), not here.
    """

    __tablename__ = "claim_types"

    claim_type: Mapped[str] = mapped_column(Text, primary_key=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    authorisation_ttl: Mapped[timedelta | None] = mapped_column(Interval, nullable=True)
    reporting_ttl: Mapped[timedelta | None] = mapped_column(Interval, nullable=True)
    default_trust: Mapped[str | None] = mapped_column(Text, nullable=True)
