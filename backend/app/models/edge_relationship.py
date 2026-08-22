from sqlalchemy import Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# Relationship vocabulary. 'authority' is reserved for a later epic — the
# 2026-08-19 attribution redesign settled on THREE axes (probe class /
# operational layer / relationship) and this is the relationship axis, but
# 'authority' isn't wired to a producer yet. Do NOT add it to the CHECK
# constraint until it has one; adding a value here means editing the CHECK
# constraint in a follow-up migration too.
EDGE_RELATIONSHIPS: frozenset[str] = frozenset({
    "dependency",
    "recipient",
})


class EdgeTypeRelationship(Base):
    """Reference lookup: what kind of relationship an edge_type represents
    (planning#142, L1).

    Standalone table keyed by edge_type — deliberately NOT FK'd to/from
    asset_edges in either direction. This is a forward-declaration for the
    edge producers landing in #135/#136/#137/#138/#147; several of its
    seeded edge_types (cname, spf_include, script_include, ...) are not yet
    in asset_edge.EDGE_TYPES because nothing writes them yet. Existing edges
    are entirely untouched by this table.
    """

    __tablename__ = "edge_type_relationships"

    edge_type: Mapped[str] = mapped_column(Text, primary_key=True)
    relationship: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
