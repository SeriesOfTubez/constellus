"""Attack-surface query language (planning#227): schema, validator, compiler, API.

What these tests pin, in the order the issue's acceptance lists them:
- an invalid object is rejected with a readable, pathed error BEFORE any SQL
  (the API test proves the session is never touched, and that the same stub
  IS touched by a valid query, so "not touched" isn't vacuous);
- read access is parity with `/api/assets/` and `/api/findings/` (Jason,
  2026-10-10), asserted through the API for a viewer and an admin, and every
  row source passes through `read_scope` (patched to deny → no rows);
- no string from the object reaches the SQL text (compiled-SQL check), and
  hostile values match only themselves (DB check).

Rows are synthetic (example.com, RFC 5737) and removed in teardown.
Run with:  scripts/test.sh app/tests/test_query_language.py
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import false, func, inspect, select
from sqlalchemy.dialects import postgresql

from app.api import assets as assets_api
from app.api import findings as findings_api
from app.api import query as query_api
from app.api.deps import get_current_user
from app.core.database import SessionLocal, get_db
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.finding_canonical import FindingCanonical
from app.models.user import User, UserRole
from app.services import query_compiler, query_schema, read_scope
from app.services.query_schema import QueryError, validate


# ── fixture ─────────────────────────────────────────────────────────────────

def _user(role: UserRole = UserRole.VIEWER) -> User:
    return User(id=uuid.uuid4(), email=f"ql-{role.value}@example.invalid",
                full_name="ql", role=role.value, is_active=True)


@pytest.fixture(scope="module")
def surface():
    """Six assets under a unique `.ql-<hex>.example.com` suffix:

    a  claimed_ours; ports 443 (http, nginx, cert) + 22 (ssh); tags [prod];
       findings: critical KEV risk 90, low resolved risk NULL
    b  ports 80 (nginx) + 443 (apache) — nginx and 443 on DIFFERENT entries —
       plus one entry whose "port" is a string;
       finding: critical, rejected_shared_infra (hidden by default)
    c  suppressed (indefinite ignore)
    d  third-party (estate not_ours)
    e  value carries a literal % and _ (LIKE-escape check)
    f  expired ignore → visible by default; open_ports is an object, not an array
    """
    p = f"ql-{uuid.uuid4().hex[:10]}"
    db = SessionLocal()
    now = datetime.now(timezone.utc)
    ids: dict[str, uuid.UUID] = {}

    def asset(key, value, *, atype="dns_record", estate=None, ports=None, tags=None, **kw):
        a = AssetCanonical(asset_type=atype, value=value, tags=tags or [], **kw)
        db.add(a)
        db.flush()
        ids[key] = a.id
        db.add(AssetState(asset_canonical_id=a.id, estate=estate,
                          open_ports=[] if ports is None else ports))
        return a

    def finding(key, asset_key, severity, **kw):
        f = FindingCanonical(asset_canonical_id=ids[asset_key], finding_type="cve", source="nuclei",
                             fingerprint=f"{key}-{p}", severity=severity, title=f"{key} {p}", **kw)
        db.add(f)
        db.flush()
        ids[key] = f.id

    asset("a", f"a.{p}.example.com", estate="claimed_ours", tags=["prod"], ports=[
        {"port": 443, "protocol": "tcp", "service": "http", "service_version": "nginx 1.25",
         "cpe": ["cpe:/a:f5:nginx:1.25"],
         "cert_summary": {"subject_cn": f"a.{p}.example.com", "sans": [f"a.{p}.example.com"],
                          "issuer_org": "Example CA"}},
        {"port": 22, "protocol": "tcp", "service": "ssh"},
    ])
    asset("b", f"b.{p}.example.com", ports=[
        {"port": 80, "protocol": "tcp", "service": "http", "service_version": "nginx"},
        {"port": 443, "protocol": "tcp", "service": "http", "service_version": "apache"},
        {"port": "unknown", "service": "x"},  # malformed number: must not break casts
    ])
    asset("c", f"c.{p}.example.com", ignored=True, ignored_at=now)
    asset("d", f"d.{p}.example.com", estate="not_ours")
    asset("e", f"e_%.{p}.example.com")
    asset("f", f"f.{p}.example.com", ignored=True, ignored_at=now - timedelta(days=2),
          ignore_expires_at=now - timedelta(days=1),
          ports={"unexpected": True})  # malformed: an object, not an array
    finding("fa1", "a", "critical", kev=True, risk_score=90, cve_id="CVE-2099-0001",
            last_seen_at=now - timedelta(days=1))
    finding("fa2", "a", "low", state="resolved", last_seen_at=now - timedelta(days=30))
    finding("fb1", "b", "critical", verification="rejected_shared_infra", risk_score=95)
    db.commit()
    db.close()
    yield p, ids
    db = SessionLocal()
    db.query(AssetCanonical).filter(AssetCanonical.id.in_(
        [ids[k] for k in "abcdef"])).delete(synchronize_session=False)
    db.commit()
    db.close()


def _run(raw: dict, user: User | None = None) -> dict:
    db = SessionLocal()
    try:
        return query_compiler.run_query(db, validate(raw), user or _user())
    finally:
        db.close()


def _scoped(p: str, *extra, entity="asset", **kw) -> dict:
    """A query limited to this fixture's rows (asset.value contains the suffix)."""
    return {"entity": entity, "where": {"all": [
        {"field": "asset.value", "op": "contains", "value": p}, *extra]}, **kw}


def _ids(result: dict, col: str = "asset.id") -> set[str]:
    return {r[col] for r in result["rows"]}


def _keys(ids: dict, *keys: str) -> set[str]:
    return {str(ids[k]) for k in keys}


# ── registry ↔ compiler ─────────────────────────────────────────────────────

def test_every_published_field_compiles_and_nothing_else_does():
    # Membership fields compile in `_predicate`, not as a scalar column.
    assert set(query_schema.FIELDS_BY_NAME) - query_compiler._MEMBERSHIP_FIELDS == set(query_compiler._FIELD_SQL)
    for e in query_schema.ENTITIES.values():
        assert set(e["output"]) <= set(query_schema.FIELDS_BY_NAME)


def test_every_field_and_operator_compiles_against_the_database(surface):
    """Smoke-run one predicate per (field, operator) so a field that compiles
    to invalid SQL fails here rather than in someone's query."""
    p, _ = surface
    samples = {"string": "x", "enum": None, "integer": 1, "number": 0.5, "boolean": True,
               "datetime": "2026-01-01T00:00:00+00:00", "uuid": str(uuid.uuid4()),
               "string_list": "x"}
    for f in query_schema.FIELDS:
        for op in query_schema.operators_for(f):
            v = f.enum[0] if f.type == "enum" else samples[f.type]
            if op in ("is_null", "is_empty"):
                v = True
            elif op in ("in", "not_in"):
                v = [v]
            pred = {"field": f.name, "op": op, "value": v}
            if f.namespace == "port":
                pred = {"exists": {"relation": "port", "where": pred}}
            if f.namespace in ("finding", "entity", "relation", "domain"):
                # these namespaces are each their own root entity's
                _run({"entity": f.namespace, "where": pred, "limit": 1})
            else:
                _run(_scoped(p, pred, limit=1))


# ── validation (no DB) ──────────────────────────────────────────────────────

@pytest.mark.parametrize("raw,path,fragment", [
    ({"entity": "asset", "where": {"field": "asset.nope", "op": "eq", "value": 1}},
     "where.field", "unknown field 'asset.nope'"),
    ({"entity": "asset", "where": {"field": "asset.value; DROP TABLE assets_canonical",
                                   "op": "eq", "value": "x"}},
     "where.field", "unknown field"),
    ({"entity": "finding", "where": {"field": "finding.cvss_score", "op": "gt", "value": "7"}},
     "where.value", "expected a number"),
    ({"entity": "finding", "where": {"field": "finding.risk_score", "op": "eq", "value": True}},
     "where.value", "expected an integer"),
    ({"entity": "finding", "where": {"field": "finding.severity", "op": "eq", "value": "urgent"}},
     "where.value", "'urgent' is not one of"),
    ({"entity": "finding", "where": {"field": "finding.kev", "op": "gt", "value": True}},
     "where.op", "not allowed for boolean"),
    ({"entity": "finding", "where": {"field": "finding.severity", "op": "explode", "value": "x"}},
     "where.op", "Input should be"),
    ({"entity": "finding", "where": {"exists": {"relation": "finding"}}},
     "where.exists.relation", "has no relation 'finding'"),
    ({"entity": "asset", "where": {"exists": {"relation": "edges"}}},
     "where.exists.relation", "Input should be"),
    ({"entity": "asset", "where": {"field": "port.number", "op": "eq", "value": 443}},
     "where.field", "use an exists block"),
    ({"entity": "asset", "where": {"field": "finding.kev", "op": "eq", "value": True}},
     "where.field", "use an exists block"),
    ({"entity": "asset", "where": {"exists": {"relation": "port", "where":
        {"field": "asset.value", "op": "eq", "value": "x"}}}},
     "where.exists.where.field", "only port.* fields"),
    ({"entity": "asset", "where": {"exists": {"relation": "finding", "where":
        {"exists": {"relation": "port"}}}}},
     "where.exists.where.exists", "cannot be nested"),
    ({"entity": "asset", "where": {"all": []}}, "where.all", "at least 1 item"),
    ({"entity": "asset", "where": {"not": {"not": {"not": {"not": {"not": {"not": {
        "field": "asset.value", "op": "eq", "value": "x"}}}}}}}},
     "where.not.not.not.not.not.not", "deeper than"),
    ({"entity": "asset", "where": {"any": [
        {"field": "asset.value", "op": "eq", "value": str(i)} for i in range(41)]}},
     "where", "more than 40 conditions"),
    ({"entity": "asset", "limit": 501}, "limit", "less than or equal to 500"),
    ({"entity": "asset", "limit": 0}, "limit", "greater than or equal to 1"),
    ({"entity": "asset", "sort": [{"field": "asset.tags"}]}, "sort[0].field", "cannot sort"),
    ({"entity": "asset", "sort": [{"field": "finding.risk_score"}]}, "sort[0].field", "cannot sort"),
    ({"entity": "asset", "sort": [{"field": "nope"}]}, "sort[0].field", "unknown field"),
    ({"entity": "asset", "select": ["asset.value"]}, "select", "Extra inputs"),
    ({"entity": "asset", "version": 2}, "version", "Input should be 1"),
    ({"entity": "edge"}, "entity", "Input should be"),
    ({"entity": "asset", "where": {"field": "asset.last_seen_at", "op": "gt",
                                   "value": "2026-01-01T00:00:00"}},
     "where.value", "must include a timezone"),
    ({"entity": "asset", "where": {"field": "asset.id", "op": "eq", "value": "not-a-uuid"}},
     "where.value", "expected a UUID"),
    ({"entity": "finding", "include": {"suppressed": True}}, "include.suppressed", "asset queries only"),
    ({"entity": "asset", "where": {"field": "asset.type", "op": "in", "value": "dns_record"}},
     "where.value", "non-empty list"),
    ({"entity": "asset", "where": {"field": "asset.type", "op": "in", "value": ["dns_record", 3]}},
     "where.value[1]", "expected a string"),
    ({"entity": "asset", "where": {"field": "asset.type", "op": "eq", "value": ["dns_record"]}},
     "where.value", "single value"),
    ({"entity": "asset", "where": {"field": "asset.value", "op": "is_null", "value": "yes"}},
     "where.value", "takes true or false"),
    ({"entity": "asset", "where": {"field": "asset.value", "op": "contains", "value": ""}},
     "where.value", "non-empty string"),
    ({"entity": "asset", "where": {"field": "asset.value", "op": "eq", "value": "x" * 257}},
     "where.value", "at most 256"),
    ({"entity": "asset", "where": {"bogus": 1}}, "where.bogus", "Extra inputs"),
    ({"entity": "asset", "where": "asset.value = 'x'"}, "where", "must be an object"),
])
def test_invalid_query_objects_are_rejected_with_a_path(raw, path, fragment):
    with pytest.raises(QueryError) as exc:
        validate(raw)
    assert any(e["path"] == path and fragment in e["message"] for e in exc.value.errors), exc.value.errors


def test_non_object_query_is_rejected():
    with pytest.raises(QueryError) as exc:
        validate(["entity", "asset"])
    assert exc.value.errors == [{"path": "(query)", "message": "the query must be a JSON object"}]


# ── semantics ───────────────────────────────────────────────────────────────

def test_default_hides_suppressed_and_third_party_but_not_an_expired_ignore(surface):
    p, ids = surface
    assert _ids(_run(_scoped(p))) == _keys(ids, "a", "b", "e", "f")
    assert _ids(_run(_scoped(p, include={"suppressed": True}))) == _keys(ids, "a", "b", "c", "e", "f")
    assert _ids(_run(_scoped(p, include={"third_party": True}))) == _keys(ids, "a", "b", "d", "e", "f")


def test_port_block_conditions_apply_to_one_port_entry(surface):
    p, ids = surface
    nginx_443 = {"exists": {"relation": "port", "where": {"all": [
        {"field": "port.version", "op": "contains", "value": "nginx"},
        {"field": "port.number", "op": "eq", "value": 443}]}}}
    # b has nginx (on 80) and 443 (apache) — on different entries, so no match.
    assert _ids(_run(_scoped(p, nginx_443))) == _keys(ids, "a")
    # Split into two blocks, each may match a different port: b matches too.
    split = [{"exists": {"relation": "port", "where":
                         {"field": "port.version", "op": "contains", "value": "nginx"}}},
             {"exists": {"relation": "port", "where":
                         {"field": "port.number", "op": "eq", "value": 443}}}]
    assert _ids(_run(_scoped(p, *split))) == _keys(ids, "a", "b")


def test_port_json_fields(surface):
    p, ids = surface
    db = SessionLocal()
    try:  # precondition: the malformed rows the guards exist for are really there
        assert db.get(AssetState, ids["f"]).open_ports == {"unexpected": True}
        assert {"port": "unknown", "service": "x"} in db.get(AssetState, ids["b"]).open_ports
    finally:
        db.close()

    def port(pred):
        return _ids(_run(_scoped(p, {"exists": {"relation": "port", "where": pred}})))

    assert port({"field": "port.cpe", "op": "has", "value": "cpe:/a:f5:nginx:1.25"}) == _keys(ids, "a")
    assert port({"field": "port.cert_sans", "op": "has", "value": f"a.{p}.example.com"}) == _keys(ids, "a")
    assert port({"field": "port.cert_issuer_org", "op": "eq", "value": "Example CA"}) == _keys(ids, "a")
    assert port({"field": "port.number", "op": "lt", "value": 50}) == _keys(ids, "a")
    assert port({"field": "port.cpe", "op": "is_empty", "value": False}) == _keys(ids, "a")
    # b's ports carry no cpe key at all: "empty or missing".
    assert port({"field": "port.cpe", "op": "is_empty", "value": True}) == _keys(ids, "a", "b")
    # An asset with no ports has no port to match (exists over zero rows).
    assert _ids(_run(_scoped(p, {"exists": {"relation": "port"}}))) == _keys(ids, "a", "b")


def test_finding_block_hides_excluded_verifications_unless_included(surface):
    p, ids = surface
    crit = {"exists": {"relation": "finding", "where":
                       {"field": "finding.severity", "op": "eq", "value": "critical"}}}
    assert _ids(_run(_scoped(p, crit))) == _keys(ids, "a")
    assert _ids(_run(_scoped(p, crit, include={"excluded_verifications": True}))) == _keys(ids, "a", "b")


def test_finding_root_hides_excluded_verifications_unless_included(surface):
    p, ids = surface
    q = _scoped(p, entity="finding")
    assert _ids(_run(q), "finding.id") == _keys(ids, "fa1", "fa2")
    q["include"] = {"excluded_verifications": True}
    assert _ids(_run(q), "finding.id") == _keys(ids, "fa1", "fa2", "fb1")


def test_boolean_tree_any_and_null_safe_not(surface):
    p, ids = surface
    anyq = _scoped(p, {"any": [{"field": "asset.value", "op": "starts_with", "value": "a."},
                               {"field": "asset.value", "op": "starts_with", "value": "B."}]})
    assert _ids(_run(anyq)) == _keys(ids, "a", "b")
    # surface is NULL-in-storage for b/e/f ("unknown" via coalesce), and
    # hosting_provider is NULL for all: `not (x = v)` must still match them.
    notq = _scoped(p, {"not": {"field": "asset.hosting_provider", "op": "eq", "value": "aws"}})
    assert _ids(_run(notq)) == _keys(ids, "a", "b", "e", "f")
    assert _ids(_run(_scoped(p, {"field": "asset.surface", "op": "eq", "value": "unknown"}))) \
        == _keys(ids, "b", "e", "f")


def test_tags_has_and_is_empty(surface):
    p, ids = surface
    assert _ids(_run(_scoped(p, {"field": "asset.tags", "op": "has", "value": "prod"}))) == _keys(ids, "a")
    assert _ids(_run(_scoped(p, {"field": "asset.tags", "op": "is_empty", "value": True}))) \
        == _keys(ids, "b", "e", "f")


def test_finding_root_sort_limit_truncation_and_asset_fields(surface):
    p, ids = surface
    q = _scoped(p, entity="finding", sort=[{"field": "finding.risk_score", "dir": "desc"}],
                include={"excluded_verifications": True})
    rows = _run(q)["rows"]
    # NULL risk sorts last whichever direction; then id tiebreak.
    assert [r["finding.id"] for r in rows] == [str(ids["fb1"]), str(ids["fa1"]), str(ids["fa2"])]
    assert rows[1]["asset.value"] == f"a.{p}.example.com" and rows[1]["finding.kev"] is True
    q["limit"] = 2
    out = _run(q)
    assert out["row_count"] == 2 and out["truncated"] is True
    q["limit"] = 3
    assert _run(q)["truncated"] is False


def test_datetime_in_and_is_null(surface):
    p, ids = surface
    week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    q = _scoped(p, {"field": "finding.last_seen_at", "op": "gt", "value": week_ago}, entity="finding")
    assert _ids(_run(q), "finding.id") == _keys(ids, "fa1")
    q = _scoped(p, {"field": "finding.state", "op": "in", "value": ["resolved", "suppressed"]},
                entity="finding")
    assert _ids(_run(q), "finding.id") == _keys(ids, "fa2")
    q = _scoped(p, {"field": "finding.cve_id", "op": "is_null", "value": False}, entity="finding")
    assert _ids(_run(q), "finding.id") == _keys(ids, "fa1")


# ── injection ───────────────────────────────────────────────────────────────

HOSTILE = [
    "x' OR '1'='1",
    "'); DROP TABLE assets_canonical; --",
    "\" OR \"\"=\"",
    "a.%' UNION SELECT id::text FROM users --",
    "\\'; SELECT pg_sleep(5); --",
]


def _all_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _all_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _all_strings(v)


@pytest.mark.parametrize("hostile", HOSTILE)
def test_no_value_reaches_the_sql_text(surface, hostile):
    p, _ = surface
    raw = _scoped(p,
                  {"field": "asset.value", "op": "eq", "value": hostile},
                  {"field": "asset.value", "op": "contains", "value": hostile},
                  {"field": "asset.value", "op": "starts_with", "value": hostile},
                  {"field": "asset.type", "op": "not_in", "value": ["service"]},
                  {"field": "asset.content", "op": "in", "value": [hostile, "qq-plain"]},
                  {"field": "asset.tags", "op": "has", "value": hostile},
                  {"exists": {"relation": "port", "where":
                              {"field": "port.banner", "op": "contains", "value": hostile}}},
                  {"exists": {"relation": "finding", "where":
                              {"field": "finding.title", "op": "ne", "value": hostile}}})
    db = SessionLocal()
    try:
        sql = str(query_compiler.compile_query(db, validate(raw), _user())
                  .compile(dialect=postgresql.dialect()))
    finally:
        db.close()
    for s in _all_strings(raw):
        if s in ("asset", "port", "finding"):  # entity/relation names: registry keys
            continue
        if s in query_schema.FIELDS_BY_NAME or s in query_schema.OPERATORS:
            continue  # validated names; asserted separately below
        assert s not in sql, f"value {s!r} appears in the SQL text"
    assert "%(" in sql  # values are placeholders
    # Field names never appear verbatim either: they map to columns.
    assert "asset.value" not in sql.replace('"asset.value"', "")  # only as a quoted output label


@pytest.mark.parametrize("hostile", HOSTILE)
def test_hostile_values_match_only_themselves(surface, hostile):
    p, _ = surface
    for op in ("eq", "contains", "starts_with"):
        assert _run(_scoped(p, {"field": "asset.value", "op": op, "value": hostile}))["rows"] == []
    db = SessionLocal()
    try:
        assert inspect(db.get_bind()).has_table("assets_canonical")
        assert db.query(AssetCanonical).count() >= 6
    finally:
        db.close()


def test_like_wildcards_are_literal(surface):
    p, ids = surface
    assert _ids(_run(_scoped(p, {"field": "asset.value", "op": "contains", "value": "%"}))) == _keys(ids, "e")
    assert _ids(_run(_scoped(p, {"field": "asset.value", "op": "contains", "value": "_"}))) == _keys(ids, "e")
    assert _ids(_run(_scoped(p, {"field": "asset.value", "op": "starts_with", "value": "_"}))) == set()


# ── read scope is applied to every row source ───────────────────────────────

def test_read_scope_asset_clause_gates_both_roots(surface, monkeypatch):
    p, ids = surface
    assert _run(_scoped(p))["rows"]  # reached: rows exist without the patch
    monkeypatch.setattr(read_scope, "asset_clause", lambda user, asset: false())
    assert _run(_scoped(p))["rows"] == []
    assert _run(_scoped(p, entity="finding"))["rows"] == []


def test_read_scope_finding_clause_gates_finding_root_and_exists(surface, monkeypatch):
    p, ids = surface
    crit = {"exists": {"relation": "finding"}}
    assert _ids(_run(_scoped(p, crit))) == _keys(ids, "a")  # reached
    monkeypatch.setattr(read_scope, "finding_clause", lambda user, finding, asset: false())
    assert _run(_scoped(p, entity="finding"))["rows"] == []
    assert _run(_scoped(p, crit))["rows"] == []
    assert _ids(_run(_scoped(p))) == _keys(ids, "a", "b", "e", "f")  # assets unaffected


# ── API ─────────────────────────────────────────────────────────────────────

def _client(as_role: UserRole | None, db_dep=None) -> TestClient:
    app = FastAPI()
    app.include_router(query_api.router, prefix="/api/query")
    app.include_router(assets_api.router, prefix="/api/assets")
    app.include_router(findings_api.router, prefix="/api/findings")

    def _db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = db_dep or _db
    if as_role is not None:
        user = _user(as_role)
        app.dependency_overrides[get_current_user] = lambda: user
    return TestClient(app, raise_server_exceptions=False)


class _TripwireSession:
    """Stands in for the DB session; records any use."""

    def __init__(self):
        self.touched = False

    def __getattr__(self, name):
        self.touched = True
        raise RuntimeError(f"session used: {name}")


def test_api_rejects_invalid_query_before_touching_the_session():
    trip = _TripwireSession()
    client = _client(UserRole.VIEWER, db_dep=lambda: trip)
    r = client.post("/api/query", json={"entity": "asset", "where":
                                        {"field": "asset.nope", "op": "eq", "value": 1}})
    assert r.status_code == 422
    assert r.json()["detail"]["errors"] == [{"path": "where.field", "message": "unknown field 'asset.nope'"}]
    assert trip.touched is False
    # The tripwire works: a VALID query does reach the session.
    r = client.post("/api/query", json={"entity": "asset"})
    assert r.status_code == 500 and trip.touched is True


def test_api_requires_authentication():
    client = _client(None)
    assert client.post("/api/query", json={"entity": "asset"}).status_code in (401, 403)
    assert client.get("/api/query/schema").status_code in (401, 403)


@pytest.mark.parametrize("role", [UserRole.VIEWER, UserRole.ADMIN])
def test_api_parity_with_existing_list_endpoints(surface, role):
    """Read authorisation = parity (2026-10-10): any authenticated user gets
    exactly what GET /api/assets/ and GET /api/findings/ give them."""
    p, ids = surface
    client = _client(role)
    listed = {a["id"] for a in client.get("/api/assets/").json() if p in a["value"]}
    r = client.post("/api/query", json=_scoped(p, limit=500))
    assert r.status_code == 200
    assert _ids(r.json()) == listed == _keys(ids, "a", "b", "e", "f")

    listed_f = {f["id"] for f in client.get("/api/findings/", params={"asset_value": p}).json()}
    r = client.post("/api/query", json=_scoped(p, entity="finding", limit=500))
    assert _ids(r.json(), "finding.id") == listed_f
    # findings list hides excluded verifications only for active states; the
    # query hides them always unless included — equal here because fb1 is open.
    assert listed_f == _keys(ids, "fa1", "fa2")


def test_api_schema_is_published(surface):
    client = _client(UserRole.VIEWER)
    body = client.get("/api/query/schema").json()
    assert {f["name"] for f in body["fields"]} == set(query_schema.FIELDS_BY_NAME)
    assert body["limits"]["max_limit"] == query_schema.MAX_LIMIT
    js = body["query_json_schema"]
    assert set(js["properties"]) == {"version", "entity", "where", "sort", "limit", "include"}
    sev = next(f for f in body["fields"] if f["name"] == "finding.severity")
    assert sev["enum"] == ["critical", "high", "medium", "low", "info"]



def test_query_runs_under_a_statement_timeout(surface):
    p, _ = surface
    db = SessionLocal()
    try:
        assert db.execute(select(func.current_setting("statement_timeout"))).scalar() == "0"
        query_compiler.run_query(db, validate(_scoped(p)), _user())
        # set_config(..., is_local=true): scoped to this transaction only
        assert db.execute(select(func.current_setting("statement_timeout"))).scalar()             == f"{query_schema.STATEMENT_TIMEOUT_MS // 1000}s"
        # After COMMIT a session-level setting would persist on the pooled
        # connection into unrelated work; the local one must not. (A rollback
        # undoes both, so it cannot tell them apart.)
        db.commit()
        assert db.execute(select(func.current_setting("statement_timeout"))).scalar() == "0"
    finally:
        db.close()
