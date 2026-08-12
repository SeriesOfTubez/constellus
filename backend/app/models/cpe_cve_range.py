from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class CpeCveRange(Base):
    """One vulnerable cpeMatch range for a D7 product, mirrored from NVD/VulnCheck.

    The local CPE→CVE version-range index behind native version→CVE matching
    (#66). `vendor`/`product` are the canonical NVD tokens (aliases folded in).
    Rows are refreshed by delete-by-cve + re-insert, so there's no natural-key
    uniqueness constraint — the surrogate `id` is the PK.
    """

    __tablename__ = "cpe_cve_ranges"

    id: Mapped[int] = mapped_column(BigInteger, autoincrement=True, primary_key=True)
    cve_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    vendor: Mapped[str] = mapped_column(Text, nullable=False)
    product: Mapped[str] = mapped_column(Text, nullable=False)

    version_start_including: Mapped[str | None] = mapped_column(Text, nullable=True)
    version_start_excluding: Mapped[str | None] = mapped_column(Text, nullable=True)
    version_end_including: Mapped[str | None] = mapped_column(Text, nullable=True)
    version_end_excluding: Mapped[str | None] = mapped_column(Text, nullable=True)
    exact_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    all_versions: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    source: Mapped[str] = mapped_column(Text, nullable=False)
    cpe_criteria: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
