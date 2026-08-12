"""Cached Certspotter API responses keyed by domain.

The free-tier API limits us to 100 req/hr. With ~200+ targets running daily,
each monitoring tick is enough to blow past that ceiling unless we cache.
A successful response is cached for CT_CACHE_TTL_SECONDS and reused as if
we'd hit the network — same downstream behavior, no API hit.

Failures are also cached (with a shorter TTL) so 429s and connection errors
don't get retried on every chunk in a long run.
"""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class CTQueryCache(Base):
    __tablename__ = "ct_query_cache"

    domain: Mapped[str] = mapped_column(String(253), primary_key=True)
    payload: Mapped[list] = mapped_column(JSONB, nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
