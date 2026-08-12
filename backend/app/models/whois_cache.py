from datetime import datetime

from sqlalchemy import DateTime, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class WhoisCache(Base):
    __tablename__ = "whois_cache"

    ip: Mapped[str] = mapped_column(Text, primary_key=True)
    org: Mapped[str | None] = mapped_column(Text, nullable=True)
    asn: Mapped[str | None] = mapped_column(Text, nullable=True)
    looked_up_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
