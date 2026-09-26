import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, LargeBinary, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class EvidenceBlob(Base):
    """Content-addressed evidence bytes, stored once (planning#212, L3).

    Keyed by its own sha256 (not a surrogate id) so identical bytes fetched
    from two different URLs, or the same URL at two different times, are
    stored once. `ck_evidence_blobs_sha256_matches_content` (migration 0061)
    has Postgres itself verify the stored hash against the stored bytes,
    using the built-in `sha256(bytea)` function (Postgres 18+) — integrity
    is not merely trusted to whatever inserted the row.

    See `EvidenceFetch` for why the (url, time) axis is a SEPARATE table
    rather than columns here.
    """

    __tablename__ = "evidence_blobs"

    sha256: Mapped[bytes] = mapped_column(LargeBinary, primary_key=True)
    content: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    content_type: Mapped[str] = mapped_column(Text, nullable=False)
    byte_length: Mapped[int] = mapped_column(Integer, nullable=False)


class EvidenceFetch(Base):
    """One row per (source_url, content) observation (planning#212, L3).

    Deduplicating blobs by hash and NOT keeping a second table would lose
    the second URL/time for byte-identical content — not hypothetical:
    Wayback's raw (`id_`) capture mode returns byte-identical bytes for
    every capture of an unchanged page, and for planning#214 the capture
    TIMESTAMP is itself the evidence. `fetched_at` has no default: the
    fetcher states the time it captured the content, never "now" at insert
    time. `UNIQUE (source_url, sha256)` makes re-fetching identical bytes
    from the same URL idempotent without losing a distinct URL or time.
    """

    __tablename__ = "evidence_fetches"
    __table_args__ = (
        UniqueConstraint("source_url", "sha256", name="uq_evidence_fetches_source_url_sha256"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()"))
    sha256: Mapped[bytes] = mapped_column(
        LargeBinary, ForeignKey("evidence_blobs.sha256", ondelete="RESTRICT"), nullable=False
    )
    source_url: Mapped[str] = mapped_column(Text, nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # planning#216 (migration 0064): `person_supplied` = an excerpt a person
    # pasted and attributed to `source_url`; nothing was fetched, and
    # `fetched_at` is when it was supplied. Every other row is `fetched`.
    origin: Mapped[str] = mapped_column(Text, nullable=False, default="fetched", server_default=text("'fetched'"))
