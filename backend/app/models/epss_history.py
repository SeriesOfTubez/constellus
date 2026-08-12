from datetime import datetime

from sqlalchemy import DateTime, Float, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class EpssHistory(Base):
    """One row per (cve_id, calendar day). TimescaleDB hypertable on recorded_date.

    recorded_date is stored as midnight UTC — callers convert Python date objects
    via datetime.combine(d, time.min, tzinfo=timezone.utc) before inserting.
    """

    __tablename__ = "epss_history"

    cve_id: Mapped[str] = mapped_column(Text, primary_key=True)
    recorded_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    epss_score: Mapped[float] = mapped_column(Float, nullable=False)
    epss_percentile: Mapped[float] = mapped_column(Float, nullable=False)
