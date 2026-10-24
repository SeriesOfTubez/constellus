"""The affiliate tree under an organization root (planning#277 S2).

Lives beside, not inside, `services/org_discovery/`: that package may never
read an entity's name (`test_org_discovery_invariants`), and this is a
display-only read that returns names.

Walks DOWN: the exact inverse of `entity_relationship.parents()`. A child of X
is the subject of a confirmed `subsidiary_of` row whose object is X, or the
object of a confirmed `acquired` row whose subject is X.

A child that has its own `relationship` (it is itself ours / an M&A target) is
a separate root, exactly where `entity_relationship.resolve()` stops an upward
path, so it is neither included nor descended into.

PROPOSED edges are shown one hop out from a confirmed node, as nodes with
`status="proposed"`; they are never walked further and never count toward a
subtree. Rejected edges never appear.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import date

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session, aliased

from app.models.entity_relation import EntityRelation
from app.models.org_entity import OrgEntity
from app.services import read_scope
from app.services.entity_relationship import MAX_DEPTH


class NodeNotInTree(Exception):
    """The requested node is not a confirmed node of this root's tree."""


@dataclass
class TreeNode:
    entity_id: uuid.UUID
    name: str
    parent_id: uuid.UUID | None
    relation: str | None  # "subsidiary_of" | "acquired"; None for the root
    event_date: date | None
    status: str  # "confirmed" | "proposed"
    depth: int


def _edges_from(db: Session, user, node_id: uuid.UUID):
    """(child_id, child entity, relation, event_date, status) for each non-rejected edge that hangs a child under `node_id`, behind the
    entity and relation read hooks."""
    child = aliased(OrgEntity)
    rel = EntityRelation
    rows = db.execute(
        select(
            rel.subject_id, rel.object_id, rel.relation, rel.event_date, rel.status,
        )
        .where(
            rel.status.in_(("confirmed", "proposed")),
            or_(
                and_(rel.relation == "subsidiary_of", rel.object_id == node_id),
                and_(rel.relation == "acquired", rel.subject_id == node_id),
            ),
            read_scope.relation_clause(user, rel),
        )
        .order_by(rel.created_at, rel.id)
    ).all()
    out = []
    for subject_id, object_id, relation, event_date, status in rows:
        cid = subject_id if relation == "subsidiary_of" else object_id
        if cid == node_id:
            continue
        out.append((cid, relation, event_date, status))
    if not out:
        return []
    ents = {
        e.id: e
        for e in db.execute(
            select(child).where(child.id.in_({o[0] for o in out}), read_scope.entity_clause(user, child))
        ).scalars()
    }
    return [(cid, ents[cid], relation, event_date, status) for cid, relation, event_date, status in out if cid in ents]


def org_tree(db: Session, user, root_id: uuid.UUID) -> list[TreeNode]:
    root = db.get(OrgEntity, root_id)
    if root is None:
        return []
    nodes = [TreeNode(root.id, root.legal_name, None, None, None, "confirmed", 0)]
    seen: set[uuid.UUID] = {root.id}
    frontier = [root.id]
    depth = 0
    while frontier and depth < MAX_DEPTH:
        depth += 1
        next_frontier: list[uuid.UUID] = []
        for parent_id in frontier:
            for cid, ent, relation, event_date, status in _edges_from(db, user, parent_id):
                if cid in seen:
                    continue
                if ent.relationship is not None:
                    continue  # a separate root: resolve() stops here too
                if status == "confirmed":
                    seen.add(cid)
                    nodes.append(TreeNode(cid, ent.legal_name, parent_id, relation, event_date, "confirmed", depth))
                    next_frontier.append(cid)
                else:
                    # Shown, never walked, never in the subtree. Not added to
                    # `seen`: a later CONFIRMED path to the same entity wins.
                    nodes.append(TreeNode(cid, ent.legal_name, parent_id, relation, event_date, "proposed", depth))
        frontier = next_frontier
    # An entity reached as proposed first and confirmed later appears once, as confirmed.
    confirmed = {n.entity_id for n in nodes if n.status == "confirmed"}
    out: list[TreeNode] = []
    shown_proposed: set[uuid.UUID] = set()
    for n in nodes:
        if n.status == "proposed":
            if n.entity_id in confirmed or n.entity_id in shown_proposed:
                continue
            shown_proposed.add(n.entity_id)
        out.append(n)
    return out


def subtree_ids(db: Session, user, root_id: uuid.UUID, node_id: uuid.UUID) -> set[uuid.UUID]:
    """`node_id` plus its CONFIRMED descendants. Raises `NodeNotInTree` when
    `node_id` is not a confirmed node of the root's tree."""
    nodes = [n for n in org_tree(db, user, root_id) if n.status == "confirmed"]
    if node_id not in {n.entity_id for n in nodes}:
        raise NodeNotInTree(str(node_id))
    kids: dict[uuid.UUID, list[uuid.UUID]] = {}
    for n in nodes:
        if n.parent_id is not None:
            kids.setdefault(n.parent_id, []).append(n.entity_id)
    found = {node_id}
    stack = [node_id]
    while stack:
        for c in kids.get(stack.pop(), []):
            if c not in found:
                found.add(c)
                stack.append(c)
    return found
