import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, SmallInteger, Text, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class HttpRedirectHop(Base):
    """One Location destination in the redirect chain of a probed endpoint
    (origin asset, port) (planning#268, migration 0077).

    A row is about the HOP's URL. `followed` means a request was sent;
    an unfollowed row records the URL and the refusal `reason` (the probe
    gate's own `rule_fired`, or a local refusal such as `loop`, `hop_cap`,
    `unsupported_url`, `ssrf_blocked`, `dns_failed`, `unresolved_asset`)
    and nothing was sent. The chain is replaced wholesale when the origin
    endpoint is re-probed (`app.services.redirect_follow`)."""

    __tablename__ = "http_redirect_hops"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    origin_asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets_canonical.id", ondelete="CASCADE"), nullable=False
    )
    origin_port: Mapped[int] = mapped_column(Integer, nullable=False)
    origin_scheme: Mapped[str] = mapped_column(Text, nullable=False)
    hop_index: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    hop_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets_canonical.id", ondelete="SET NULL"), nullable=True
    )
    followed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    http_title: Mapped[str | None] = mapped_column(Text, nullable=True)
    http_location: Mapped[str | None] = mapped_column(Text, nullable=True)
    scan_run_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_runs.id", ondelete="SET NULL"), nullable=True
    )
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
