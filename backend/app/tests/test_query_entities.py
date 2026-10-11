"""The `entity`, `relation` and `domain` roots of the query language, and the
corporate-family membership they share (planning#230 slice 2).

Family of engagement E = E's subject entity plus everything reachable DOWN
CONFIRMED parent edges (`child subsidiary_of parent`, `parent acquired child`),
cut at `entity_relationship.MAX_DEPTH`. The fixture tree is documented in
`_ma_world.py`. Synthetic rows only, deleted by id afterwards.

Run with:  backend/scripts/test.ps1 app/tests/test_query_entities.py
"""

import uuid

import pytest
from sqlalchemy import false, text

from app.core.database import SessionLocal
from app.models.entity_relation import EntityRelation
from app.models.user import User, UserRole
from app.services import chat, entity_relationship, query_compiler, query_schema, read_scope
from app.services.query_schema import QueryError, validate
from app.tests._ma_world import MaWorld


def _user() -> User:
    return User(id=uuid.uuid4(), email="qent-viewer@example.invalid", full_name="qent",
                role=UserRole.VIEWER.value, is_active=True)


@pytest.fixture(scope="module")
def w():
    world = MaWorld().build_family()
    yield world
    world.close()


@pytest.fixture
def db():
    s = SessionLocal()
    yield s
    s.close()


def _rows(db, raw: dict) -> list[dict]:
    return query_compiler.run_query(db, validate(raw), _user())["rows"]


def _count(db, raw: dict) -> int:
    return query_compiler.count_query(db, validate(raw), _user())["count"]


def _f(field, op, value):
    return {"field": field, "op": op, "value": value}


def _family_ids(db, eid) -> set[uuid.UUID]:
    rows = _rows(db, {"entity": "entity", "where": _f("entity.family_of", "eq", str(eid)), "limit": 500})
    return {uuid.UUID(r["entity.id"]) for r in rows}


def _oracle_family(db, subject_id, max_depth=None) -> set[uuid.UUID]:
    """The family by a plain Python walk over the raw rows (not the CTE)."""
    max_depth = entity_relationship.MAX_DEPTH if max_depth is None else max_depth
    edges = [(r.relation, r.subject_id, r.object_id) for r in
             db.query(EntityRelation).filter(EntityRelation.status == "confirmed").all()]
    seen, frontier = {subject_id}, {subject_id}
    for _ in range(max_depth):
        nxt = set()
        for rel, s, o in edges:
            if rel == "subsidiary_of" and o in frontier:
                nxt.add(s)
            elif rel == "acquired" and s in frontier:
                nxt.add(o)
        frontier = nxt - seen
        seen |= frontier
    return seen


# ── family ──────────────────────────────────────────────────────────────────

def test_family_is_the_subject_plus_confirmed_descendants_only(db, w):
    got = _family_ids(db, w.E.id)
    assert got == {w.S.id, w.A.id, w.B.id, w.C1.id, w.C2.id, w.C3.id}
    assert got == _oracle_family(db, w.S.id)            # an independent walk agrees
    for outside, why in ((w.P, "proposed"), (w.Q, "proposed acquired"), (w.Z, "proposed dba"), (w.R, "rejected"), (w.U, "parent of S"),
                         (w.F, "formerly_named"), (w.D2, "dba")):
        assert outside.id not in got, why


def test_the_family_walk_does_not_stop_at_an_entity_with_its_own_relationship(db, w):
    # A is the subject of engagement EA, so it has a relationship of its own;
    # the walk still reaches B and the chain below it.
    assert w.A.id in _family_ids(db, w.E.id) and w.C3.id in _family_ids(db, w.E.id)


def test_a_cycle_terminates_and_does_not_duplicate_rows(db, w):
    rows = _rows(db, {"entity": "entity", "where": _f("entity.family_of", "eq", str(w.E.id)), "limit": 500})
    ids = [r["entity.id"] for r in rows]
    assert len(ids) == len(set(ids)) == 6                # B acquired A closes a loop; each entity once


def test_a_chain_longer_than_max_depth_is_cut(db, w, monkeypatch):
    monkeypatch.setattr(entity_relationship, "MAX_DEPTH", 3)   # S(0) A(1) B(2) C1(3) | C2(4) C3(5)
    got = _family_ids(db, w.E.id)
    assert got == {w.S.id, w.A.id, w.B.id, w.C1.id}
    assert got == _oracle_family(db, w.S.id, 3)
    monkeypatch.setattr(entity_relationship, "MAX_DEPTH", 0)
    assert _family_ids(db, w.E.id) == {w.S.id}


def test_an_engagement_with_no_subject_has_an_empty_family(db, w):
    assert _family_ids(db, w.N.id) == set()
    assert _count(db, {"entity": "relation", "where": _f("relation.family_of", "eq", str(w.N.id))}) == 0
    assert _count(db, {"entity": "domain", "where": _f("domain.family_of", "eq", str(w.N.id))}) == 0
    assert _family_ids(db, uuid.uuid4()) == set()        # an unknown engagement likewise


def test_in_takes_the_union_of_families(db, w):
    only_a = {w.A.id, w.B.id, w.C1.id, w.C2.id, w.C3.id}
    assert _family_ids(db, w.EA.id) == only_a
    rows = _rows(db, {"entity": "entity", "limit": 500,
                      "where": _f("entity.family_of", "in", [str(w.N.id), str(w.EA.id)])})
    assert {uuid.UUID(r["entity.id"]) for r in rows} == only_a
    rows = _rows(db, {"entity": "entity", "limit": 500,
                      "where": _f("entity.family_of", "in", [str(w.E.id), str(w.EA.id)])})
    assert {uuid.UUID(r["entity.id"]) for r in rows} == only_a | {w.S.id}


# ── entity fields ───────────────────────────────────────────────────────────

def test_parent_relation_points_into_the_child(db, w):
    fam = _f("entity.family_of", "eq", str(w.E.id))

    def ids(pred):
        rows = _rows(db, {"entity": "entity", "where": {"all": [fam, pred]}, "limit": 500})
        return {uuid.UUID(r["entity.id"]) for r in rows}

    # S is itself a subsidiary of U (S sub U), so a confirmed parent edge points into S too.
    assert ids(_f("entity.parent_relation", "eq", "subsidiary_of")) == {w.A.id, w.S.id}
    # B acquired A (the cycle edge) as well as A acquired B.
    assert ids(_f("entity.parent_relation", "eq", "acquired")) == {w.A.id, w.B.id, w.C1.id, w.C2.id, w.C3.id}
    assert ids(_f("entity.parent_relation", "in", ["subsidiary_of", "acquired"])) == {
        w.S.id, w.A.id, w.B.id, w.C1.id, w.C2.id, w.C3.id}
    # S's formerly_named / dba edges are not parent edges: only `sub U` points into S.
    assert ids(_f("entity.parent_relation", "eq", "acquired")) & {w.S.id} == set()
    # proposed and rejected edges point into nothing:
    outsiders = {"all": [_f("entity.id", "in", [str(w.P.id), str(w.R.id)]),
                         _f("entity.parent_relation", "in", ["subsidiary_of", "acquired"])]}
    assert _count(db, {"entity": "entity", "where": outsiders}) == 0


def test_entity_scalar_fields(db, w):
    fam = _f("entity.family_of", "eq", str(w.E.id))
    own = _rows(db, {"entity": "entity", "limit": 500, "where": {"all": [
        fam, _f("entity.relationship", "is_null", False)]}})
    # S (subject of E) and A (subject of EA) have a relationship; the others do not.
    assert {r["entity.name"] for r in own} == {"Example Holdings S", "Fabrikam A Ltd"}
    assert all(r["entity.relationship"] == "ma_target" for r in own)
    assert _count(db, {"entity": "entity", "where": {"all": [fam, _f("entity.has_cik", "eq", False)]}}) == 6
    assert _count(db, {"entity": "entity", "where": {"all": [fam, _f("entity.has_cik", "eq", True)]}}) == 0
    named = _rows(db, {"entity": "entity", "where": {"all": [fam, _f("entity.name", "starts_with", "Chain")]},
                       "sort": [{"field": "entity.name", "dir": "desc"}]})
    assert [r["entity.name"] for r in named] == ["Chain Gamma", "Chain Beta", "Chain Alpha"]
    assert _count(db, {"entity": "entity", "where": _f("entity.created_at", "gte", "2000-01-01T00:00:00+00:00")}) >= 6


# ── relation ────────────────────────────────────────────────────────────────

def test_relation_family_of_covers_both_endpoints(db, w):
    # An unrelated relation between two outsiders must never appear.
    x, y = w.entity("Outsider X"), w.entity("Outsider Y")
    w.edge(x, y, "acquired")           # swept by the world's close
    if True:
        fam = _f("relation.family_of", "eq", str(w.E.id))

        def rel_ids(*conds):
            rows = _rows(db, {"entity": "relation", "limit": 500, "where": {"all": [fam, *conds]}})
            return {uuid.UUID(r["relation.id"]) for r in rows}, rows

        confirmed, rows = rel_ids(_f("relation.status", "eq", "confirmed"))
        assert len(confirmed) == 9
        by_pair = {(r["relation.subject_name"], r["relation.object_name"], r["relation.type"]) for r in rows}
        # subject in the family, object outside it (S is a subsidiary of U):
        assert ("Example Holdings S", "Parent U", "subsidiary_of") in by_pair
        assert ("Outsider X", "Outsider Y", "acquired") not in by_pair
        proposed, rows = rel_ids(_f("relation.status", "eq", "proposed"))
        # object in the family, subject outside it (P is proposed as a subsidiary of S):
        assert {(r["relation.subject_name"], r["relation.object_name"]) for r in rows} == {
            ("Proposed P", "Example Holdings S"), ("Example Holdings S", "Proposed Q Ltd"),
            ("Example Holdings S", "Proposed Z Trading")}
        assert len(rel_ids(_f("relation.status", "eq", "rejected"))[0]) == 1


def test_relation_fields_names_dates_and_sorting(db, w):
    fam = _f("relation.family_of", "eq", str(w.E.id))
    acq = {"all": [fam, _f("relation.type", "eq", "acquired"), _f("relation.status", "eq", "confirmed")]}
    dated = _rows(db, {"entity": "relation", "where": {"all": [
        *acq["all"], _f("relation.event_date", "gte", "2020-01-01T00:00:00+00:00")]}})
    assert [(r["relation.subject_name"], r["relation.object_name"]) for r in dated] == [
        ("Fabrikam A Ltd", "Fabrikam B Ltd")]
    assert dated[0]["relation.event_date"].startswith("2020-03-01")
    assert dated[0]["relation.object_id"] == str(w.B.id)
    assert dated[0]["relation.event_date_precision"] == "day"
    # The DATE is UTC midnight whatever the session time zone: the boundary
    # instants on either side of it decide inclusion exactly.
    db.execute(text("SET TIME ZONE 'America/Los_Angeles'"))
    at = _f("relation.event_date", "gte", "2020-03-01T00:00:00+00:00")
    after = _f("relation.event_date", "gte", "2020-03-01T00:00:01+00:00")
    assert _count(db, {"entity": "relation", "where": {"all": [*acq["all"], at]}}) == 1
    assert _count(db, {"entity": "relation", "where": {"all": [*acq["all"], after]}}) == 0
    db.execute(text("SET TIME ZONE 'UTC'"))
    assert _count(db, {"entity": "relation", "where": {"all": [
        *acq["all"], _f("relation.event_date", "lt", "2020-01-01T00:00:00+00:00")]}}) == 0
    ordered = _rows(db, {"entity": "relation", "where": acq, "sort": [{"field": "relation.event_date", "dir": "desc"}]})
    assert ordered[0]["relation.event_date"] is not None       # dated first (nulls last)
    assert ordered[-1]["relation.event_date"] is None
    only_s = _rows(db, {"entity": "relation", "where": {"all": [
        _f("relation.subject_id", "eq", str(w.S.id)), _f("relation.type", "in", ["formerly_named", "dba"]),
        _f("relation.status", "eq", "confirmed")]}})
    assert {r["relation.object_name"] for r in only_s} == {"Former Name F", "Trading Name D2"}


# ── domain ──────────────────────────────────────────────────────────────────

def test_domain_family_of(db, w):
    fam = _f("domain.family_of", "eq", str(w.E.id))

    def names(status):
        rows = _rows(db, {"entity": "domain", "limit": 500, "where": {"all": [fam, _f("domain.status", "eq", status)]}})
        return {r["domain.name"] for r in rows}, rows

    accepted, rows = names("accepted")
    assert accepted == {w.dom_s.domain, w.dom_a.domain}        # not U's (a parent), not R's
    assert {r["domain.entity_name"] for r in rows} == {"Example Holdings S", "Fabrikam A Ltd"}
    assert names("proposed")[0] == {w.dom_a2.domain, w.dom_b.domain}
    assert names("rejected")[0] == set()                       # R is not in the family
    assert _count(db, {"entity": "domain", "where": _f("domain.source", "eq", "person")}) >= 6


# ── counts equal independent SQL ────────────────────────────────────────────

def test_counts_equal_independent_sql(db, w):
    fam = _oracle_family(db, w.S.id)
    ids = [str(i) for i in fam]
    sql = lambda q, **p: db.execute(text(q), p).scalar_one()  # noqa: E731
    assert _count(db, {"entity": "entity", "where": _f("entity.family_of", "eq", str(w.E.id))}) == len(fam) == sql(
        "select count(*) from org_entities where id = any(cast(:ids as uuid[]))", ids=ids)
    assert _count(db, {"entity": "relation", "where": {"all": [
        _f("relation.family_of", "eq", str(w.E.id)), _f("relation.status", "eq", "confirmed")]}}) == sql(
        "select count(*) from entity_relations where status = 'confirmed' and "
        "(subject_id = any(cast(:ids as uuid[])) or object_id = any(cast(:ids as uuid[])))", ids=ids)
    for status in ("accepted", "proposed", "rejected"):
        assert _count(db, {"entity": "domain", "where": {"all": [
            _f("domain.family_of", "eq", str(w.E.id)), _f("domain.status", "eq", status)]}}) == sql(
            "select count(*) from candidate_domains where status = :s and entity_id = any(cast(:ids as uuid[]))",
            s=status, ids=ids)


# ── validation ──────────────────────────────────────────────────────────────

MEMBERSHIP = [("entity", "entity.family_of"), ("relation", "relation.family_of"),
              ("domain", "domain.family_of"), ("entity", "entity.parent_relation")]


def _value_for(field):
    return "acquired" if field == "entity.parent_relation" else str(uuid.uuid4())


@pytest.mark.parametrize("root,field", MEMBERSHIP)
@pytest.mark.parametrize("op", ["ne", "not_in", "is_null", "contains", "gt"])
def test_membership_fields_reject_operators_other_than_eq_and_in(root, field, op):
    value = True if op == "is_null" else [_value_for(field)] if op == "not_in" else _value_for(field)
    with pytest.raises(QueryError) as exc:
        validate({"entity": root, "where": _f(field, op, value)})
    assert "not allowed" in str(exc.value)
    for ok in ("eq", "in"):                                   # the precondition: the field is otherwise valid
        validate({"entity": root, "where": _f(field, ok, [_value_for(field)] if ok == "in" else _value_for(field))})


@pytest.mark.parametrize("root,field", MEMBERSHIP)
def test_membership_fields_cannot_be_sorted_or_returned(root, field):
    with pytest.raises(QueryError) as exc:
        validate({"entity": root, "sort": [{"field": field}]})
    assert "cannot sort" in str(exc.value)
    assert field not in query_schema.ENTITIES[root]["output"]
    assert not query_schema.FIELDS_BY_NAME[field].sortable
    assert field not in query_compiler._FIELD_SQL
    assert field in query_compiler._MEMBERSHIP_FIELDS


def test_where_fields_from_a_namespace_the_root_does_not_read_are_rejected():
    cases = [("entity", _f("asset.value", "eq", "x")), ("entity", _f("domain.name", "eq", "x")),
             ("relation", _f("entity.name", "eq", "x")), ("domain", _f("relation.status", "eq", "confirmed")),
             ("asset", _f("entity.name", "eq", "x")), ("finding", _f("domain.name", "eq", "x"))]
    for root, pred in cases:
        with pytest.raises(QueryError) as exc:
            validate({"entity": root, "where": pred})
        assert "cannot be used here" in str(exc.value), (root, pred)
    validate({"entity": "entity", "where": _f("entity.name", "eq", "x")})   # the precondition: own fields pass


def test_the_company_roots_have_no_exists_relations():
    for root in ("entity", "relation", "domain"):
        with pytest.raises(QueryError) as exc:
            validate({"entity": root, "where": {"exists": {"relation": "finding"}}})
        assert f"a {root} query has no relation" in str(exc.value)


def test_the_published_schema_lists_the_new_roots_with_restricted_operators():
    schema = query_schema.published_schema()
    for root in ("entity", "relation", "domain"):
        e = schema["entities"][root]
        assert e["relations"] == [] and e["output"]
        assert all(f.startswith(root + ".") for f in e["fields"])
    fields = {f["name"]: f for f in schema["fields"]}
    for name in ("entity.family_of", "relation.family_of", "domain.family_of", "entity.parent_relation"):
        assert fields[name]["operators"] == ["eq", "in"] and fields[name]["sortable"] is False
    assert schema["entities"]["entity"]["output"] == [
        "entity.id", "entity.name", "entity.relationship", "entity.has_cik"]
    assert fields["entity.relationship"]["enum"] == ["ma_target", "ours"]
    assert fields["relation.type"]["enum"] == ["acquired", "dba", "formerly_named", "subsidiary_of"]
    assert "asset" in schema["entities"] and "finding" in schema["entities"]


# ── read scope ──────────────────────────────────────────────────────────────

def test_read_scope_clauses_are_applied_to_every_root_and_every_joined_alias(db, w, monkeypatch):
    rel_all = {"entity": "relation", "where": _f("relation.family_of", "eq", str(w.E.id))}
    dom_all = {"entity": "domain", "where": _f("domain.family_of", "eq", str(w.E.id))}
    ent_all = {"entity": "entity", "where": _f("entity.family_of", "eq", str(w.E.id))}
    before = (_count(db, ent_all), _count(db, rel_all), _count(db, dom_all))
    assert all(n > 0 for n in before)                          # the precondition: there is something to hide
    for hook, hidden in (("entity_clause", {"entity", "relation", "domain"}),
                         ("relation_clause", {"relation"}), ("domain_clause", {"domain"})):
        monkeypatch.setattr(read_scope, hook, lambda user, row: false())
        got = {name for name, raw in (("entity", ent_all), ("relation", rel_all), ("domain", dom_all))
               if _count(db, raw) == 0}
        assert got == hidden, hook
        monkeypatch.undo()


# ── the chat tool ───────────────────────────────────────────────────────────

def test_chat_run_query_cites_entity_rows_and_no_relation_or_domain_rows(db, w):
    fam = _f("entity.family_of", "eq", str(w.E.id))
    out = chat._tool_run_query(db, {"entity": "entity", "where": fam, "limit": 50}, _user())
    assert out.payload["entity"] == "entity" and out.payload["count"] == 6
    assert out.cite_ids == {str(i) for i in _family_ids(db, w.E.id)}
    out = chat._tool_run_query(db, {"entity": "relation", "where": _f("relation.family_of", "eq", str(w.E.id)),
                                    "limit": 50}, _user())
    assert out.payload["count"] > 0 and out.cite_ids == set()
    out = chat._tool_run_query(db, {"entity": "domain", "where": _f("domain.family_of", "eq", str(w.E.id)),
                                    "limit": 50}, _user())
    assert out.payload["count"] > 0 and out.cite_ids == set()
    # the tool's parameter schema accepts the new roots
    enum = chat.tool_definitions()[0]["function"]["parameters"]["properties"]["entity"]
    assert set(enum["enum"]) == {"asset", "finding", "entity", "relation", "domain"}
