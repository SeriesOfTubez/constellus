import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Text, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

# These mirror migration 0085's CHECK constraints
# (`ck_connector_instances_type`, `ck_connector_instances_binding` and the
# partial unique index) and must be edited together with them.
# `app/tests/test_connector_instances.py` parses the migration to prove it.
CONNECTOR_TYPES: frozenset[str] = frozenset({
    "certspotter", "cloudflare", "shodan", "wiz", "fortimanager", "tenable",
    "vulncheck", "nuclei", "naabu", "banner_grab", "httpx_probe", "tlsx",
    "mailtrap", "openrouter",
})
# Multi-instance types, each bound to an organization. Every other type is a
# global service or scanning tool: unbound, at most one instance.
ACCOUNT_TYPES: frozenset[str] = frozenset({"cloudflare", "wiz", "tenable", "fortimanager"})


class ConnectorInstance(Base):
    """One configured connector: a global service, a scanning tool, or one
    account of an account-style connector (planning#284). See migration 0085
    for the constraints and the binding trigger."""

    __tablename__ = "connector_instances"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    type: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default=text("true"))
    config_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    bound_entity_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("org_entities.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    bound_entity: Mapped["OrgEntity | None"] = relationship("OrgEntity", lazy="select")  # noqa: F821


class ConnectorEnvSeed(Base):
    """A connector type whose one-time environment seeding is settled."""

    __tablename__ = "connector_env_seeds"

    type: Mapped[str] = mapped_column(Text, primary_key=True)
    seeded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    instance_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("connector_instances.id", ondelete="SET NULL"), nullable=True
    )
