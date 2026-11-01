import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# Mirrors the CHECK in migration 0080.
RULE_MODES: frozenset[str] = frozenset({"immediate", "digest", "both"})
# Mirrors the CHECK in migration 0099 (planning#319).
RULE_KIND_FINDING = "finding"
RULE_KIND_ORG_DISCOVERY = "org_discovery"
RULE_KINDS: frozenset[str] = frozenset({RULE_KIND_FINDING, RULE_KIND_ORG_DISCOVERY})


class NotificationRule(Base):
    """A rule is either a finding rule or an organization discovery rule
    (planning#319), told apart by `kind`.

    A FINDING rule emits a notification when a new finding lands.

    Matches new findings_canonical inserts only — re-observations don't
    re-fire. severity_threshold is the minimum severity the rule cares
    about (critical > high > medium > low > info). categories is an
    optional list; empty matches any category.

    An ORG_DISCOVERY rule is sent in the daily digest only (a CHECK: mode
    `digest`, no categories) and lists new open organization discovery
    candidates. Its severity threshold is unused. It is never loaded by the
    finding dispatcher.
    """

    __tablename__ = "notification_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default=text("true"))
    severity_threshold: Mapped[str] = mapped_column(String(20), nullable=False, default="high", server_default=text("'high'"))
    categories: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default=text("'[]'"))
    recipients: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default=text("'[]'"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    # planning#233 slice 2a: "immediate" sends as findings land (the old
    # behaviour), "digest" only in the daily digest, "both" does both. Events
    # are recorded in every mode.
    mode: Mapped[str] = mapped_column(Text, nullable=False, default="immediate", server_default=text("'immediate'"))
    # planning#319: `finding` (default, every existing rule) or `org_discovery`.
    kind: Mapped[str] = mapped_column(Text, nullable=False, default=RULE_KIND_FINDING, server_default=text("'finding'"))
