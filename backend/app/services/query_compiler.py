"""Compile a validated query object to a parameterised SELECT and run it (planning#227).

Input is a `query_schema.Query` that `query_schema.validate()` already accepted.
The compiler never builds SQL text: every column comes from the `_FIELD_SQL`
map below (keyed by the registry name, so an unknown name is a KeyError, not a
column), and every value from the query object reaches SQLAlchemy as a bound
parameter. LIKE patterns escape `%`, `_` and `\\` so a value can't widen its
own match.

Default exclusions mirror the existing list endpoints, per entity:
- asset queries hide currently-suppressed assets and third-party context
  assets (surface not_ours), as `GET /api/assets/` does;
- finding rows, at the root or inside `exists: finding`, hide
  `EXCLUDED_VERIFICATIONS`, as `GET /api/findings/` does. The attribution
  rule is that we do not present findings we cannot prove are ours as ours.
`include` lifts each one explicitly.

Every row source passes through `read_scope` (no-op today, planning#261).
"""

from __future__ import annotations

import itertools
import uuid
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Callable

from sqlalchemy import DateTime, Float, Integer, and_, case, cast, exists, false, func, literal, not_, or_, select, true
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session, aliased
from sqlalchemy.sql import column
from sqlalchemy.sql.elements import ColumnElement

from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.engagement import Engagement
from app.models.entity_relation import EntityRelation
from app.models.finding_canonical import EXCLUDED_VERIFICATIONS, FindingCanonical
from app.models.org_entity import OrgEntity
from app.models.scope_candidate import ScopeCandidate
from app.services.org_discovery import strength as strength_sql
from app.models.target import Target
from app.models.target_asset_link import TargetAssetLink
from app.models.user import User
from app.services import entity_relationship, read_scope
from app.services.claims_query import SURFACE_UNKNOWN, asset_ids_with_surface
from app.services.query_schema import (
    ENTITIES,
    FIELDS_BY_NAME,
    AllNode,
    AnyNode,
    ExistsNode,
    NotNode,
    Predicate,
    COUNT_CAP,
    STATEMENT_TIMEOUT_MS,
    Query,
)


@dataclass
class _Ctx:
    """The row sources a field expression may read in the current scope."""
    asset: Any = None
    state: Any = None
    finding: Any = None
    port: Any = None   # the JSONB value column of one open_ports element
    entity: Any = None        # entity root: OrgEntity
    relation: Any = None      # relation root: EntityRelation
    rel_subject: Any = None   # relation root: OrgEntity alias on subject_id
    rel_object: Any = None    # relation root: OrgEntity alias on object_id
    domain: Any = None        # domain root: ScopeCandidate (kind = 'domain')
    dom_strength: Any = None  # domain root: the strength CTE wrapper (outer-joined)
    dom_entity: Any = None    # domain root: OrgEntity alias on affiliated_entity_id (outer join)


def _port_key(*keys: str) -> Callable[[_Ctx], Any]:
    def f(c: _Ctx) -> Any:
        expr = c.port
        for k in keys:
            expr = expr[k]
        return expr
    return f


def _text(getter: Callable[[_Ctx], Any]) -> Callable[[_Ctx], Any]:
    return lambda c: getter(c).astext


# JSON-typed fields (port.*) are compiled with their JSON node kept, so the
# operator layer can guard on jsonb_typeof before casting.
_JSON_FIELDS = {"port.number", "port.cpe", "port.cert_sans"}

_FIELD_SQL: dict[str, Callable[[_Ctx], Any]] = {
    "asset.id": lambda c: c.asset.id,
    "asset.type": lambda c: c.asset.asset_type,
    "asset.value": lambda c: c.asset.value,
    "asset.parent_value": lambda c: c.asset.parent_value,
    "asset.record_type": lambda c: c.asset.record_type,
    "asset.content": lambda c: c.asset.content,
    "asset.first_seen_at": lambda c: c.asset.first_seen_at,
    "asset.last_seen_at": lambda c: c.asset.last_seen_at,
    "asset.suppressed": lambda c: c.asset.suppressed,
    "asset.tags": lambda c: c.asset.tags,
    "asset.surface": lambda c: func.coalesce(c.state.estate, literal(SURFACE_UNKNOWN)),
    "asset.hosting_provider": lambda c: c.state.hosting["provider"].astext,
    "asset.is_datacenter": lambda c: case(
        (func.jsonb_typeof(c.state.hosting["is_datacenter"]) == "boolean",
         c.state.hosting["is_datacenter"].as_boolean()),
        else_=None,
    ),
    "finding.id": lambda c: c.finding.id,
    "finding.title": lambda c: c.finding.title,
    "finding.severity": lambda c: c.finding.severity,
    "finding.state": lambda c: c.finding.state,
    "finding.type": lambda c: c.finding.finding_type,
    "finding.source": lambda c: c.finding.source,
    "finding.category": lambda c: c.finding.category,
    "finding.cve_id": lambda c: c.finding.cve_id,
    "finding.cwe": lambda c: c.finding.cwe,
    "finding.cvss_score": lambda c: c.finding.cvss_score,
    "finding.epss_score": lambda c: c.finding.epss_score,
    "finding.epss_percentile": lambda c: c.finding.epss_percentile,
    "finding.kev": lambda c: c.finding.kev,
    "finding.has_exploit": lambda c: c.finding.has_exploit,
    "finding.ransomware_use": lambda c: c.finding.ransomware_use,
    "finding.risk_score": lambda c: c.finding.risk_score,
    "finding.risk_band": lambda c: c.finding.risk_band,
    "finding.verification": lambda c: c.finding.verification,
    "finding.ssvc_exploitation": lambda c: c.finding.ssvc_exploitation,
    "finding.ssvc_automatable": lambda c: c.finding.ssvc_automatable,
    "finding.ssvc_technical_impact": lambda c: c.finding.ssvc_technical_impact,
    "finding.first_seen_at": lambda c: c.finding.first_seen_at,
    "finding.last_seen_at": lambda c: c.finding.last_seen_at,
    "finding.resolved_at": lambda c: c.finding.resolved_at,
    "finding.tags": lambda c: c.finding.tags,
    "entity.id": lambda c: c.entity.id,
    "entity.name": lambda c: c.entity.legal_name,
    "entity.relationship": lambda c: c.entity.relationship,
    "entity.has_cik": lambda c: c.entity.cik.isnot(None),
    "entity.created_at": lambda c: c.entity.created_at,
    "relation.id": lambda c: c.relation.id,
    "relation.type": lambda c: c.relation.relation,
    "relation.status": lambda c: c.relation.status,
    # A DATE read as UTC midnight, so comparing it with an ISO datetime does
    # not depend on the session time zone.
    "relation.event_date": lambda c: func.timezone("UTC", cast(c.relation.event_date, DateTime)),
    "relation.event_date_precision": lambda c: c.relation.event_date_precision,
    "relation.subject_id": lambda c: c.relation.subject_id,
    "relation.object_id": lambda c: c.relation.object_id,
    "relation.subject_name": lambda c: c.rel_subject.legal_name,
    "relation.object_name": lambda c: c.rel_object.legal_name,
    "domain.id": lambda c: c.domain.id,
    "domain.name": lambda c: c.domain.value,
    "domain.status": lambda c: c.domain.status,
    "domain.proposable": lambda c: c.dom_strength.proposable,
    "domain.root_id": lambda c: c.domain.root_entity_id,
    "domain.entity_id": lambda c: c.domain.affiliated_entity_id,
    "domain.entity_name": lambda c: c.dom_entity.legal_name,
    "port.number": _port_key("port"),
    "port.protocol": _text(_port_key("protocol")),
    "port.service": _text(_port_key("service")),
    "port.version": _text(_port_key("service_version")),
    "port.banner": _text(_port_key("banner_snippet")),
    "port.cpe": _port_key("cpe"),
    "port.jarm": _text(_port_key("jarm")),
    "port.cert_subject_cn": _text(_port_key("cert_summary", "subject_cn")),
    "port.cert_issuer_cn": _text(_port_key("cert_summary", "issuer_cn")),
    "port.cert_issuer_org": _text(_port_key("cert_summary", "issuer_org")),
    "port.cert_sans": _port_key("cert_summary", "sans"),
}


def _like_escape(v: str) -> str:
    return v.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _value(spec_type: str, v: Any) -> Any:
    if spec_type == "datetime":
        return datetime.fromisoformat(v)
    if spec_type == "uuid":
        return uuid.UUID(v)
    return v


def _engagement_member(p: Predicate, ctx: _Ctx) -> ColumnElement[bool]:
    """An asset is IN engagement E iff a `target_asset_links` row links it to a
    target whose `engagement_id` is E (Jason, planning#230). `validate()` allows
    `eq` and `in` only."""
    if p.op == "in":
        member = Target.engagement_id.in_([uuid.UUID(v) for v in p.value])
    else:
        member = Target.engagement_id == uuid.UUID(p.value)
    return exists(
        select(1).select_from(TargetAssetLink)
        .join(Target, Target.id == TargetAssetLink.target_id)
        .where(TargetAssetLink.asset_canonical_id == ctx.asset.id, member)
    )


_cte_seq = itertools.count()


def family_ids_cte(engagement_ids: list[uuid.UUID]):
    """The corporate family of each engagement, as a recursive CTE over
    (engagement_id, entity_id, depth) (planning#230 slice 2).

    Seed: the engagement's subject entity (a NULL subject has no family), depth 0.
    Step: DOWN the CONFIRMED parent edges only, from parent to child: a
    `subsidiary_of` row whose OBJECT is the parent gives its SUBJECT as child; an
    `acquired` row whose SUBJECT is the parent gives its OBJECT as child. Never
    up, never proposed or rejected, and `formerly_named` / `dba` are not family
    edges. The walk does not stop at an entity that has its own `relationship`
    (this is corporate structure, not domain inheritance) and is cut at
    `entity_relationship.MAX_DEPTH`. `UNION` (not `UNION ALL`) dedupes rows, so
    a cycle ends; the depth bound is the backstop."""
    name = f"family_{next(_cte_seq)}"
    seed = select(
        Engagement.id.label("engagement_id"),
        Engagement.subject_entity_id.label("entity_id"),
        literal(0, Integer).label("depth"),
    ).where(Engagement.id.in_(engagement_ids), Engagement.subject_entity_id.isnot(None))
    fam = seed.cte(name, recursive=True)
    edge = EntityRelation
    step = (
        select(fam.c.engagement_id,
               case((edge.relation == "subsidiary_of", edge.subject_id), else_=edge.object_id),
               fam.c.depth + 1)
        .select_from(fam.join(edge, or_(
            and_(edge.relation == "subsidiary_of", edge.object_id == fam.c.entity_id),
            and_(edge.relation == "acquired", edge.subject_id == fam.c.entity_id))))
        .where(edge.status == "confirmed", fam.c.depth + 1 <= entity_relationship.MAX_DEPTH)
    )
    return fam.union(step)


def _uuids(p: Predicate) -> list[uuid.UUID]:
    return [uuid.UUID(v) for v in p.value] if p.op == "in" else [uuid.UUID(p.value)]


def _family_member(*cols: Callable[[_Ctx], Any]) -> Callable[[Predicate, _Ctx], ColumnElement[bool]]:
    """`<col> is in the family of engagement E` for `eq`, or of any listed
    engagement for `in`. With several columns, any one of them may be the member."""
    def member(p: Predicate, ctx: _Ctx) -> ColumnElement[bool]:
        ids = _uuids(p)
        fam = family_ids_cte(ids)
        engagement = fam.c.engagement_id == ids[0] if p.op == "eq" else fam.c.engagement_id.in_(ids)
        which = or_(*(fam.c.entity_id == col(ctx) for col in cols))
        return exists(select(1).select_from(fam).where(which, engagement))
    return member


def _parent_relation_member(p: Predicate, ctx: _Ctx) -> ColumnElement[bool]:
    """A CONFIRMED parent edge of the given type(s) points INTO this entity as
    the child: `subsidiary_of` with subject = the entity, `acquired` with
    object = the entity."""
    types = [p.value] if p.op == "eq" else list(p.value)
    edge = EntityRelation
    parts = []
    if "subsidiary_of" in types:
        parts.append(and_(edge.relation == "subsidiary_of", edge.subject_id == ctx.entity.id))
    if "acquired" in types:
        parts.append(and_(edge.relation == "acquired", edge.object_id == ctx.entity.id))
    return exists(select(1).select_from(edge).where(edge.status == "confirmed", or_(*parts)))


# Fields that are not a scalar column: no `_FIELD_SQL` entry, so they can be
# neither sorted nor output. Compiled by `_predicate` before that lookup.
_MEMBERSHIP_COMPILERS: dict[str, Callable[[Predicate, _Ctx], ColumnElement[bool]]] = {
    "asset.engagement_id": _engagement_member,
    "entity.family_of": _family_member(lambda c: c.entity.id),
    "entity.parent_relation": _parent_relation_member,
    "relation.family_of": _family_member(lambda c: c.relation.subject_id, lambda c: c.relation.object_id),
    "domain.family_of": _family_member(lambda c: c.domain.root_entity_id),
}
_MEMBERSHIP_FIELDS = frozenset(_MEMBERSHIP_COMPILERS)


def _predicate(p: Predicate, ctx: _Ctx) -> ColumnElement[bool]:
    if p.field in _MEMBERSHIP_FIELDS:
        return _MEMBERSHIP_COMPILERS[p.field](p, ctx)
    spec = FIELDS_BY_NAME[p.field]
    col = _FIELD_SQL[p.field](ctx)
    op = p.op

    if spec.type == "string_list":
        # JSONB arrays. A non-array value (shouldn't happen) matches neither
        # `has` nor non-empty; jsonb_array_length would raise on it, so the
        # typeof guard sits inside a CASE (AND does not promise order).
        is_array = func.jsonb_typeof(col) == "array"
        if op == "has":
            return and_(is_array, col.contains(cast(func.jsonb_build_array(literal(p.value)), JSONB)))
        nonempty = case((is_array, func.jsonb_array_length(col) > 0), else_=False)
        return not_(nonempty) if p.value else nonempty

    if p.field in _JSON_FIELDS:  # port.number: numeric JSON only
        col = case((func.jsonb_typeof(col) == "number", col.astext.cast(Float)), else_=None)

    if op == "is_null":
        return col.is_(None) if p.value else col.isnot(None)
    if op in ("in", "not_in"):
        vals = [_value(spec.type, v) for v in p.value]
        return col.in_(vals) if op == "in" else col.not_in(vals)
    v = _value(spec.type, p.value)
    if op == "contains":
        return col.ilike("%" + _like_escape(v) + "%", escape="\\")
    if op == "starts_with":
        return col.ilike(_like_escape(v) + "%", escape="\\")
    return {
        "eq": lambda: col == v, "ne": lambda: col != v,
        "gt": lambda: col > v, "gte": lambda: col >= v,
        "lt": lambda: col < v, "lte": lambda: col <= v,
    }[op]()


def _finding_visible(f: Any, include_excluded: bool) -> ColumnElement[bool]:
    if include_excluded:
        return true()
    return or_(f.verification.is_(None), f.verification.not_in(EXCLUDED_VERIFICATIONS))


def _exists(node: ExistsNode, ctx: _Ctx, q: Query, user: User) -> ColumnElement[bool]:
    rel = node.exists.relation
    if rel == "finding":
        f2 = aliased(FindingCanonical)
        inner = _Ctx(finding=f2)
        conds = [f2.asset_canonical_id == ctx.asset.id,
                 read_scope.finding_clause(user, f2, ctx.asset),
                 _finding_visible(f2, q.include.excluded_verifications)]
    elif rel == "port":
        s2 = aliased(AssetState)
        ports = case((func.jsonb_typeof(s2.open_ports) == "array", s2.open_ports),
                     else_=cast(literal("[]"), JSONB))
        elems = func.jsonb_array_elements(ports).table_valued(column("value", JSONB)).alias()
        inner = _Ctx(port=elems.c.value)
        conds = [s2.asset_canonical_id == ctx.asset.id]
    else:  # pragma: no cover - validate() rejects unknown relations
        raise KeyError(rel)
    if node.exists.where is not None:
        conds.append(_node(node.exists.where, inner, q, user))
    if rel == "finding":
        sub = select(f2.id).where(*conds)
    else:
        sub = select(s2.asset_canonical_id).select_from(s2).join(elems, true()).where(*conds)
    return sub.exists()


def _node(node: Any, ctx: _Ctx, q: Query, user: User) -> ColumnElement[bool]:
    if isinstance(node, AllNode):
        return and_(*(_node(n, ctx, q, user) for n in node.all))
    if isinstance(node, AnyNode):
        return or_(*(_node(n, ctx, q, user) for n in node.any))
    if isinstance(node, NotNode):
        # NULL-safe: "not (x = v)" also matches rows where x is empty.
        return not_(func.coalesce(_node(node.not_, ctx, q, user), false()))
    if isinstance(node, ExistsNode):
        return _exists(node, ctx, q, user)
    return _predicate(node, ctx)


def _base(db: Session, q: Query, user: User):
    """The FROM and WHERE every use of a query shares (rows and count), so
    the two can never disagree about which rows match. Returns
    (select-with-from, conditions, field context, root id column)."""
    state = aliased(AssetState)
    if q.entity == "asset":
        asset = AssetCanonical
        ctx = _Ctx(asset=asset, state=state)
        root_id = asset.id
        from_ = select().select_from(asset).outerjoin(state, state.asset_canonical_id == asset.id)
        conds = [read_scope.asset_clause(user, asset)]
        if not q.include.suppressed:
            conds.append(~asset.suppressed)
        if not q.include.third_party:
            conds.append(asset.id.not_in(asset_ids_with_surface(db, "not_ours")))
    elif q.entity == "entity":
        ent = OrgEntity
        ctx = _Ctx(entity=ent)
        root_id = ent.id
        from_ = select().select_from(ent)
        conds = [read_scope.entity_clause(user, ent)]
    elif q.entity == "relation":
        rel, subj, obj = EntityRelation, aliased(OrgEntity), aliased(OrgEntity)
        ctx = _Ctx(relation=rel, rel_subject=subj, rel_object=obj)
        root_id = rel.id
        from_ = (select().select_from(rel)
                 .join(subj, subj.id == rel.subject_id)
                 .join(obj, obj.id == rel.object_id))
        conds = [read_scope.relation_clause(user, rel),
                 read_scope.entity_clause(user, subj), read_scope.entity_clause(user, obj)]
    elif q.entity == "domain":
        dom, ent = ScopeCandidate, aliased(OrgEntity)
        st = strength_sql.strength_subquery()
        ctx = _Ctx(domain=dom, dom_entity=ent, dom_strength=st)
        root_id = dom.id
        # The affiliated company is NULL until a candidate is claimed, hence
        # the outer join; a domain row is a `kind = 'domain'` candidate.
        from_ = (select().select_from(dom).outerjoin(ent, ent.id == dom.affiliated_entity_id)
                 .outerjoin(st.subquery, st.candidate_id == dom.id))
        conds = [dom.kind == "domain", read_scope.domain_clause(user, dom), read_scope.entity_clause(user, ent)]
    else:
        finding, asset = FindingCanonical, AssetCanonical
        ctx = _Ctx(asset=asset, state=state, finding=finding)
        root_id = finding.id
        from_ = (select().select_from(finding)
                 .join(asset, asset.id == finding.asset_canonical_id)
                 .outerjoin(state, state.asset_canonical_id == asset.id))
        conds = [read_scope.asset_clause(user, asset),
                 read_scope.finding_clause(user, finding, asset),
                 _finding_visible(finding, q.include.excluded_verifications)]
    if q.where is not None:
        conds.append(_node(q.where, ctx, q, user))
    return from_, conds, ctx, root_id


def compile_query(db: Session, q: Query, user: User):
    """Build the SELECT for a validated query. Fetches `limit + 1` rows so the
    caller can tell whether the result was truncated."""
    from_, conds, ctx, root_id = _base(db, q, user)
    cols = [_FIELD_SQL[name](ctx).label(name) for name in ENTITIES[q.entity]["output"]]
    order = []
    for s in q.sort:
        expr = _FIELD_SQL[s.field](ctx)
        order.append((expr.desc() if s.dir == "desc" else expr.asc()).nulls_last())
    order.append(root_id.asc())  # deterministic tiebreak
    return from_.add_columns(*cols).where(*conds).order_by(*order).limit(q.limit + 1)


def _jsonable(v: Any) -> Any:
    if isinstance(v, (datetime, date)):
        return v.isoformat()
    if isinstance(v, uuid.UUID):
        return str(v)
    return v


def run_query(db: Session, q: Query, user: User) -> dict[str, Any]:
    # Defence in depth behind the structural caps: a valid query can still be
    # expensive (many exists blocks, substring scans). Transaction-local, so it
    # ends with this request's transaction and leaks into no other work.
    db.execute(select(func.set_config("statement_timeout", str(STATEMENT_TIMEOUT_MS), True)))
    rows = db.execute(compile_query(db, q, user)).mappings().all()
    truncated = len(rows) > q.limit
    rows = rows[: q.limit]
    return {
        "entity": q.entity,
        "columns": list(ENTITIES[q.entity]["output"]),
        "rows": [{k: _jsonable(v) for k, v in r.items()} for r in rows],
        "row_count": len(rows),
        "truncated": truncated,
    }


def count_query(db: Session, q: Query, user: User) -> dict[str, Any]:
    """Exact number of rows the query matches, ignoring `limit` and `sort`,
    capped at COUNT_CAP: the inner SELECT stops at COUNT_CAP + 1 ids, so a
    huge match costs no more than the cap. `capped` means "more than
    `count`" (planning#228: an answer's "N instances" is a real number, or
    says N+)."""
    db.execute(select(func.set_config("statement_timeout", str(STATEMENT_TIMEOUT_MS), True)))
    from_, conds, _, root_id = _base(db, q, user)
    inner = from_.add_columns(root_id).where(*conds).limit(COUNT_CAP + 1).subquery()
    n = db.execute(select(func.count()).select_from(inner)).scalar_one()
    return {"entity": q.entity, "count": min(n, COUNT_CAP), "capped": n > COUNT_CAP}
