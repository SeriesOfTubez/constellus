"""A role held at a scope (planning#261): global, or one engagement.

"Membership" of an engagement is holding an assignment on it; there is no
members table. The principal is a user or (planning#243 slice 2) an API key:
exactly one of `user_id` / `api_key_id` is set. `api_key_id` has no foreign key
yet because no API-key table exists; slice 2 adds only the constraint.

A user's GLOBAL assignment mirrors `users.role`: the `before_flush` hook below
writes it whenever a user is created or their role changes, in the same flush,
so every writer (setup, the user-admin API, SAML first login, tests) keeps the
two in step without knowing about this table. `users.role` goes away when the
frontend reads permissions (planning#243 slice 2); until then it is the edit
surface and this table is what `has_permission` reads.

One role per principal per scope (the partial unique indexes in 0082).
"""

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, event, func, inspect, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, Session, mapped_column

from app.core.database import Base
from app.models.user import User


class RoleAssignment(Base):
    __tablename__ = "role_assignments"
    __table_args__ = (
        CheckConstraint("num_nonnulls(user_id, api_key_id) = 1", name="ck_role_assignments_one_principal"),
        Index("uq_role_assignments_user_global", "user_id", unique=True,
              postgresql_where=text("user_id IS NOT NULL AND engagement_id IS NULL")),
        Index("uq_role_assignments_user_engagement", "user_id", "engagement_id", unique=True,
              postgresql_where=text("user_id IS NOT NULL AND engagement_id IS NOT NULL")),
        Index("uq_role_assignments_api_key_global", "api_key_id", unique=True,
              postgresql_where=text("api_key_id IS NOT NULL AND engagement_id IS NULL")),
        Index("uq_role_assignments_api_key_engagement", "api_key_id", "engagement_id", unique=True,
              postgresql_where=text("api_key_id IS NOT NULL AND engagement_id IS NOT NULL")),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=text("uuidv7()"))
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True
    )
    api_key_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    role: Mapped[str] = mapped_column(String(50), nullable=False)
    # NULL = global.
    engagement_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


def _role_value(role) -> str:
    return getattr(role, "value", role)


@event.listens_for(Session, "before_flush")
def _sync_global_assignment(session: Session, _flush_context, _instances) -> None:
    """Mirror `users.role` into the user's global assignment (module docstring)."""
    with session.no_autoflush:
        for obj in list(session.new) + list(session.dirty):
            if not isinstance(obj, User) or obj.role is None:
                continue
            if obj not in session.new and not inspect(obj).attrs.role.history.has_changes():
                continue
            role = _role_value(obj.role)
            current = next((a for a in obj.assignments if a.engagement_id is None), None)
            if current is None:
                obj.assignments.append(RoleAssignment(role=role, engagement_id=None))
            elif current.role != role:
                current.role = role
