from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, SmallInteger, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class RirLookupCache(Base):
    """Cached RIR Whois-RWS responses (planning#278 S3b1), keyed by registry and
    the path under that registry's fixed base URL. Only 200 and 404 are cached."""

    __tablename__ = "rir_lookup_cache"
    __table_args__ = (
        CheckConstraint("rir IN ('arin', 'ripe')", name="ck_rir_lookup_cache_rir"),
        CheckConstraint("status_code IN (200, 404)", name="ck_rir_lookup_cache_status"),
        CheckConstraint("(status_code = 200) = (body IS NOT NULL)", name="ck_rir_lookup_cache_body_iff_200"),
        CheckConstraint("length(btrim(path)) > 0", name="ck_rir_lookup_cache_path_nonblank"),
    )

    rir: Mapped[str] = mapped_column(Text, primary_key=True)
    path: Mapped[str] = mapped_column(Text, primary_key=True)
    status_code: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    body: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
