from datetime import date, datetime

from sqlalchemy import Boolean, CheckConstraint, Date, DateTime, Index, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# Mirror the CHECK-backed vocabulary in migration 0103 by hand.
CVE_PUBLISHED_SOURCES: tuple[str, ...] = ("vulncheck_nvd2",)

_SOURCES_SQL = ", ".join(f"'{s}'" for s in CVE_PUBLISHED_SOURCES)


class CveRecord(Base):
    """CVE-level facts that do not belong on any one finding (planning#360).

    CVE intel is otherwise mirrored onto every finding sharing a CVE; this table
    keeps the dates once per CVE. `published_at` is the CVE's publication date
    from `published_source`; `vulncheck_kev_date_added` is when VulnCheck listed
    it as exploited. A stored date is never overwritten with NULL. `refreshed_at`
    is the last attempt (scan-time or rolling job); `refresh_failed` says the
    last attempt failed."""

    __tablename__ = "cve_records"
    __table_args__ = (
        CheckConstraint("cve_id = upper(cve_id)", name="ck_cve_records_cve_id_upper"),
        CheckConstraint(
            f"published_source IS NULL OR published_source IN ({_SOURCES_SQL})",
            name="ck_cve_records_published_source",
        ),
        CheckConstraint(
            "(published_at IS NULL) = (published_source IS NULL)",
            name="ck_cve_records_published_pair",
        ),
        Index("ix_cve_records_refreshed_at", "refreshed_at"),
    )

    cve_id: Mapped[str] = mapped_column(Text, primary_key=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    published_source: Mapped[str | None] = mapped_column(Text, nullable=True)
    vulncheck_kev_date_added: Mapped[date | None] = mapped_column(Date, nullable=True)
    refreshed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    refresh_failed: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("now()"))
