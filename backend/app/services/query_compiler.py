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

import uuid
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Callable

from sqlalchemy import Float, and_, case, cast, exists, false, func, literal, not_, or_, select, true
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session, aliased
from sqlalchemy.sql import column
from sqlalchemy.sql.elements import ColumnElement

from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.finding_canonical import EXCLUDED_VERIFICATIONS, FindingCanonical
from app.models.target import Target
from app.models.target_asset_link import TargetAssetLink
from app.models.user import User
from app.services import read_scope
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


# Fields that are not a scalar column: no `_FIELD_SQL` entry, so they can be
# neither sorted nor output. Compiled by `_predicate` before that lookup.
_MEMBERSHIP_FIELDS = frozenset({"asset.engagement_id"})


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


def _predicate(p: Predicate, ctx: _Ctx) -> ColumnElement[bool]:
    if p.field in _MEMBERSHIP_FIELDS:
        return _engagement_member(p, ctx)
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
