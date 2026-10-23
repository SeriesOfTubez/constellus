"""The row-level read rule (planning#261), against a real database.

World: see `_scope_world.py`. Users carry assignments only (`user_with`), the
way `get_current_user` sees them. Every set below is restricted to the world's
own ids, so a stray row elsewhere cannot make a pass or a failure.
"""

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.orm import aliased

from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.engagement import Engagement
from app.models.finding_canonical import FindingCanonical
from app.models.target import Target
from app.services import read_scope
from app.tests._scope_world import ScopeWorld
from app.tests._users import user_with


@pytest.fixture(scope="module")
def w():
    world = ScopeWorld().build()
    yield world
    world.close()


@pytest.fixture
def db():
    s = SessionLocal()
    yield s
    s.rollback()
    s.close()


def _users(w):
    e1 = w.E["E1"]
    return {
        "admin": user_with("admin"),
        "viewer": user_with("viewer"),
        "report_admin": user_with("report_admin"),
        "integration_admin": user_with("integration_admin"),
        "viewer+E1": user_with("viewer", engagements={e1: "viewer"}),
        "E1-only": user_with("viewer", engagements={e1: "viewer"}, global_role=False),
    }


def _assets(db, w, user, alias=None) -> set[uuid.UUID]:
    a = alias if alias is not None else AssetCanonical
    rows = db.execute(select(a.id).where(a.id.in_(list(w.a.values())), read_scope.asset_clause(user, a)))
    return {r[0] for r in rows}


def _findings(db, w, user) -> set[uuid.UUID]:
    rows = db.execute(
        select(FindingCanonical.id)
        .join(AssetCanonical, AssetCanonical.id == FindingCanonical.asset_canonical_id)
        .where(FindingCanonical.id.in_(list(w.f.values())),
               read_scope.finding_clause(user, FindingCanonical, AssetCanonical)))
    return {r[0] for r in rows}


ALL = ("a1", "a1L", "a2", "a3", "a0", "aMulti", "aBoth")
OPEN_TO_ALL = ("a3", "a0")
WITH_E1 = ("a3", "a0", "a1", "a1L", "aMulti")


def test_the_world_reaches_what_it_claims(w, db):
    """Reach check: the admin sees all seven, so a smaller set below is the rule, not an empty fixture."""
    assert _assets(db, w, _users(w)["admin"]) == w.ids(*ALL)


@pytest.mark.parametrize("who,expected", [
    ("admin", ALL),
    ("viewer", OPEN_TO_ALL),
    ("report_admin", OPEN_TO_ALL),
    ("integration_admin", OPEN_TO_ALL),
    ("viewer+E1", WITH_E1),
    ("E1-only", WITH_E1),
])
def test_assets_visible_per_user(w, db, who, expected):
    user = _users(w)[who]
    assert _assets(db, w, user) == w.ids(*expected)
    # a finding is readable iff its asset is
    assert _findings(db, w, user) == {w.f[k] for k in expected}


def test_same_result_through_an_alias(w, db):
    for who, expected in (("viewer", OPEN_TO_ALL), ("viewer+E1", WITH_E1), ("admin", ALL)):
        alias = aliased(AssetCanonical)
        assert _assets(db, w, _users(w)[who], alias) == w.ids(*expected), who


def test_correlation_guard_a_domain_leg_does_not_leak_through_an_unrelated_assets_links(w, db):
    """a0 is linked only to T0 (no engagement) and falls under no domain of E1. T1 HAS link rows
    (a1L, aMulti, aBoth). If the link leg of the predicate auto-correlated wrongly ("linked to ANY
    asset" instead of to THIS asset), a0 would count as under E1 and vanish for the viewer."""
    assert w.a["a0"] in _assets(db, w, _users(w)["viewer"])
    assert w.f["a0"] in _findings(db, w, _users(w)["viewer"])


def test_posture_flip_opens_and_closes_by_itself(w, db):
    viewer = _users(w)["viewer"]
    assert _assets(db, w, viewer) == w.ids(*OPEN_TO_ALL)
    e1 = db.get(Engagement, w.E["E1"])
    try:
        e1.posture = "day_0"
        e1.authorised_at = datetime.now(timezone.utc)
        e1.authorisation_reference = "read-scope-flip"
        db.flush()
        assert _assets(db, w, viewer) == w.ids("a3", "a0", "a1", "a1L", "aMulti")
        e1.posture = "pre_close"
        e1.authorised_at = None
        e1.authorisation_reference = None
        e1.authorised_by_id = None
        db.flush()
        assert _assets(db, w, viewer) == w.ids(*OPEN_TO_ALL)
    finally:
        db.rollback()


def _targets(db, w, user) -> set[uuid.UUID]:
    rows = db.execute(select(Target.id).where(Target.id.in_(list(w.T.values())),
                                              read_scope.target_clause(user, Target)))
    return {r[0] for r in rows}


def test_target_clause(w, db):
    users = _users(w)
    assert _targets(db, w, users["admin"]) == set(w.T.values())
    assert _targets(db, w, users["viewer"]) == {w.T["T0"], w.T["T3"]}
    assert _targets(db, w, users["viewer+E1"]) == {w.T["T0"], w.T["T3"], w.T["T1"]}


def test_engagement_visible(w, db):
    users = _users(w)
    e1, e3 = w.E["E1"], w.E["E3"]
    assert read_scope.engagement_visible(db, users["admin"], e1) is True
    assert read_scope.engagement_visible(db, users["viewer"], e1) is False
    assert read_scope.engagement_visible(db, users["viewer+E1"], e1) is True
    assert read_scope.engagement_visible(db, users["viewer"], w.E["E2"]) is False
    assert read_scope.engagement_visible(db, users["viewer"], e3) is True      # day_0 is open
    assert read_scope.engagement_visible(db, users["viewer"], uuid.uuid4()) is True  # the route 404s it itself


# ── nested in the query language ─────────────────────────────────────────────

def test_query_language_exists_finding_block_keeps_the_rule(w, db):
    """`exists finding` nests `finding_clause` inside the compiler's own EXISTS.
    Without `correlate_except` in `read_scope._asset_rule` the targets block
    lost its correlation there and hid EVERY asset from a non-admin as soon as
    any asset sat under a closed engagement."""
    from app.services import query_compiler
    from app.services.query_schema import validate

    users = _users(w)
    world = {str(v) for v in w.a.values()}

    def run(user) -> set[str]:
        q = validate({"entity": "asset", "where": {"exists": {"relation": "finding"}}, "limit": 500})
        return {r["asset.id"] for r in query_compiler.run_query(db, q, user)["rows"]} & world

    assert run(users["admin"]) == world                                         # reached
    assert run(users["viewer"]) == {str(w.a[k]) for k in ("a3", "a0")}
    assert run(users["viewer+E1"]) == {str(w.a[k]) for k in ("a3", "a0", "a1", "a1L", "aMulti")}
