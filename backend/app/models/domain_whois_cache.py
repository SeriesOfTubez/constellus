from datetime import datetime

from sqlalchemy import DateTime, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class DomainWhoisCache(Base):
    __tablename__ = "domain_whois_cache"

    domain: Mapped[str] = mapped_column(Text, primary_key=True)
    registrar: Mapped[str | None] = mapped_column(Text, nullable=True)
    registrant_org: Mapped[str | None] = mapped_column(Text, nullable=True)
    registrant_country: Mapped[str | None] = mapped_column(Text, nullable=True)
    creation_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expiration_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    name_servers: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default=text("'[]'"))
    status: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default=text("'[]'"))
    dnssec: Mapped[str | None] = mapped_column(Text, nullable=True)
    looked_up_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
