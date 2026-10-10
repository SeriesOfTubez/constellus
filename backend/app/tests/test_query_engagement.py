"""`asset.engagement_id` in the query language (planning#230): an asset is IN
engagement E iff a `target_asset_links` row links it to a target whose
`engagement_id` is E. Membership, not a column: `eq` and `in` only, and it
can be neither sorted by nor returned.

Synthetic rows only, deleted by id afterwards.
Run with:  backend/scripts/test.ps1 app/tests/test_query_engagement.py
"""

import uuid
from datetime import datetime, timezone

import pytest

from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.engagement import Engagement
from app.models.finding_canonical import FindingCanonical
from app.models.target import Target
from app.models.target_asset_link import TargetAssetLink
from app.models.user import User, UserRole
from app.services import query_compiler, query_schema
from app.services.query_schema import QueryError, validate
from app.tests._docaddr import alloc
from app.tests._engagement import make_engagement


def _user() -> User:
    return User(id=uuid.uuid4(), email="qe-viewer@example.invalid", full_name="qe",
                role=UserRole.VIEWER.value, is_active=True)


@pytest.fixture(scope="module")
def world():
    """Engagements E and F. Assets:
    a_e    linked to a target of E
    a_null linked only to a target with engagement_id NULL
    a_both linked to a target of E and a target of F
    a_f    linked to a target of F only
    a_none not linked to anything
    One critical finding on each."""
    db = SessionLocal()
    now = datetime.now(timezone.utc)
    ids: dict[str, uuid.UUID] = {}
    target_ids: list[uuid.UUID] = []
    try:
        e, f = make_engagement(db), make_engagement(db)
        ids["E"], ids["F"] = e.id, f.id
        tag = uuid.uuid4().hex[:8]

        def target(engagement_id) -> uuid.UUID:
            t = Target(id=uuid.uuid4(), type="domain", engagement_id=engagement_id,
                       value=f"qe-{uuid.uuid4().hex[:10]}.example.com")
            db.add(t)
            db.flush()
            target_ids.append(t.id)
            return t.id

        def asset(key: str, *targets: uuid.UUID) -> None:
            a = AssetCanonical(id=uuid.uuid4(), asset_type="ip_address", value=alloc(), tags=[],
                               first_seen_at=now, last_seen_at=now, ignored=False)
            db.add(a)
            db.flush()
            db.add(AssetState(asset_canonical_id=a.id, estate="claimed_ours", open_ports=[],
                              projected_at=now))
            for t in targets:
                db.add(TargetAssetLink(target_id=t, asset_canonical_id=a.id,
                                       first_linked_at=now, last_observed_at=now))
            db.add(FindingCanonical(
                id=uuid.uuid4(), asset_canonical_id=a.id, finding_type="cve", source="test",
                fingerprint=f"qe-{key}-{tag}", severity="critical", title=f"qe {key} {tag}",
                state="open", first_seen_at=now, last_seen_at=now, detail={}, tags=[]))
            ids[key] = a.id

        te, tf, tnull = target(e.id), target(f.id), target(None)
        asset("a_e", te)
        asset("a_null", tnull)
        asset("a_both", te, tf)
        asset("a_f", tf)
        asset("a_none")
        db.commit()
    finally:
        db.close()
    yield ids
    db = SessionLocal()
    try:
        asset_ids = [v for k, v in ids.items() if k.startswith("a_")]
        db.query(FindingCanonical).filter(FindingCanonical.asset_canonical_id.in_(asset_ids)).delete(
            synchronize_session=False)
        db.query(Target).filter(Target.id.in_(target_ids)).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.id.in_(asset_ids)).delete(synchronize_session=False)
        db.query(Engagement).filter(Engagement.id.in_([ids["E"], ids["F"]])).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _run(raw: dict) -> dict:
    db = SessionLocal()
    try:
        return query_compiler.run_query(db, validate(raw), _user())
    finally:
        db.close()


def _members(world, eng: str, *, entity="asset", op="eq") -> set[uuid.UUID]:
    value = str(world[eng]) if op == "eq" else [str(world[k]) for k in eng.split(",")]
    res = _run({"entity": entity, "where": {"field": "asset.engagement_id", "op": op, "value": value},
                "limit": 500})
    col = "asset.id"
    return {uuid.UUID(r[col]) for r in res["rows"]}


def _of(world, *keys: str) -> set[uuid.UUID]:
    return {world[k] for k in keys}


def _mine(world, got: set[uuid.UUID]) -> set[uuid.UUID]:
    """Only this fixture's assets (the table may hold none else, but do not assume)."""
    return got & {v for k, v in world.items() if k.startswith("a_")}


def test_asset_linked_to_a_target_of_the_engagement_is_a_member(world):
    # The reach check: the fixture really has assets in E, so a pass is not vacuous.
    got = _mine(world, _members(world, "E"))
    assert got == _of(world, "a_e", "a_both")


def test_asset_linked_only_to_a_target_without_an_engagement_is_not_a_member(world):
    for eng in ("E", "F"):
        assert world["a_null"] not in _members(world, eng)
        assert world["a_none"] not in _members(world, eng)


def test_asset_linked_to_targets_of_two_engagements_counts_for_both(world):
    assert world["a_both"] in _members(world, "E")
    assert world["a_both"] in _members(world, "F")
    assert _mine(world, _members(world, "F")) == _of(world, "a_f", "a_both")


def test_in_operator(world):
    got = _mine(world, _members(world, "E,F", op="in"))
    assert got == _of(world, "a_e", "a_both", "a_f")


def test_count_query_uses_membership_once_per_asset(world):
    db = SessionLocal()
    try:
        q = validate({"entity": "asset", "where": {"all": [
            {"field": "asset.engagement_id", "op": "in", "value": [str(world["E"]), str(world["F"])]}]}})
        # a_both is in both engagements and must still be counted once.
        assert query_compiler.count_query(db, q, _user())["count"] == 3
    finally:
        db.close()


def test_finding_root_filters_by_its_assets_membership(world):
    res = _run({"entity": "finding", "where": {"field": "asset.engagement_id", "op": "eq",
                                                "value": str(world["E"])}, "limit": 500})
    assert {uuid.UUID(r["asset.id"]) for r in res["rows"]} == _of(world, "a_e", "a_both")
    assert res["row_count"] == 2


def test_ne_and_not_in_are_rejected():
    for op, value in (("ne", str(uuid.uuid4())), ("not_in", [str(uuid.uuid4())]), ("is_null", True)):
        with pytest.raises(QueryError) as exc:
            validate({"entity": "asset", "where": {"field": "asset.engagement_id", "op": op, "value": value}})
        assert exc.value.errors[0]["path"] == "where.op"
        assert "not allowed" in exc.value.errors[0]["message"]


def test_value_must_be_a_uuid():
    with pytest.raises(QueryError) as exc:
        validate({"entity": "asset", "where": {"field": "asset.engagement_id", "op": "eq", "value": "nope"}})
    assert exc.value.errors[0]["path"] == "where.value"


def test_sorting_by_the_field_is_rejected():
    with pytest.raises(QueryError) as exc:
        validate({"entity": "asset", "sort": [{"field": "asset.engagement_id"}]})
    assert exc.value.errors[0]["path"] == "sort[0].field"


def test_field_is_in_no_entitys_output_and_has_no_column():
    for entity in query_schema.ENTITIES.values():
        assert "asset.engagement_id" not in entity["output"]
    assert "asset.engagement_id" not in query_compiler._FIELD_SQL


def test_published_schema_shows_the_restricted_operators():
    field = next(f for f in query_schema.published_schema()["fields"] if f["name"] == "asset.engagement_id")
    assert field["operators"] == ["eq", "in"]
    assert field["sortable"] is False


def test_other_uuid_fields_keep_ne():
    field = next(f for f in query_schema.published_schema()["fields"] if f["name"] == "asset.id")
    assert "ne" in field["operators"]


def test_not_wraps_membership_for_assets_outside_the_engagement(world):
    res = _run({"entity": "asset", "where": {"not": {"field": "asset.engagement_id", "op": "eq",
                                                      "value": str(world["E"])}}, "limit": 500})
    got = _mine(world, {uuid.UUID(r["asset.id"]) for r in res["rows"]})
    assert got == _of(world, "a_null", "a_f", "a_none")
