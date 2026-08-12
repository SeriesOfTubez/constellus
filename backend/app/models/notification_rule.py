import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class NotificationRule(Base):
    """A rule that emits a notification when a new finding lands.

    Matches new findings_canonical inserts only — re-observations don't
    re-fire. severity_threshold is the minimum severity the rule cares
    about (critical > high > medium > low > info). categories is an
    optional list; empty matches any category.
    """

    __tablename__ = "notification_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default=text("true"))
    severity_threshold: Mapped[str] = mapped_column(String(20), nullable=False, default="high", server_default=text("'high'"))
    categories: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default=text("'[]'"))
    recipients: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default=text("'[]'"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
