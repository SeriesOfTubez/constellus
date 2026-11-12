"""planning#346: the score ladder. Pure tests on `services/score_ladder.py` with
exact numbers, then the two routes against the test database. The database may
hold other tests' open findings, so route tests compare against a baseline read
taken in the same test (deltas), never absolute totals.
"""

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.main import app
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.finding_canonical import FindingCanonical
from app.models.role_assignment import RoleAssignment
from app.services import risk_scorer, score_ladder
from app.tests._scope_world import ScopeWorld
from app.tests.test_edgar_ingest_api import _cleanup_user, _make_user

client = TestClient(app)

KNOWN = [
    (91, "imminent_compromise", 1), (88, "imminent_compromise", 1), (84, "imminent_compromise", 1),
    (71, "high", 1), (60, "high", 2), (47, "elevated", 1), (10, "low", 3),
]


# ── pure ────────────────────────────────────────────────────────────────────

def test_known_set_levels_and_crossings():
    levels = score_ladder.build_levels(KNOWN)
    expected = [
        (91, "imminent_compromise", 1, 0, 1, 88, "imminent_compromise"),
        (88, "imminent_compromise", 1, 1, 2, 84, "imminent_compromise"),
        (84, "imminent_compromise", 1, 2, 3, 71, "high"),
        (71, "high", 1, 3, 4, 60, "high"),
        (60, "high", 2, 4, 6, 47, "elevated"),
        (47, "elevated", 1, 6, 7, 10, "low"),
        (10, "low", 3, 7, 10, 0, "secure"),
    ]
    keys = ("score", "band", "count", "fixes_before", "fixes_through", "score_after", "band_after")
    assert levels == [dict(zip(keys, row)) for row in expected]
    assert score_ladder.crossings(levels) == [
        {"band": "high", "fixes": 3, "score": 71},
        {"band": "elevated", "fixes": 6, "score": 47},
        {"band": "low", "fixes": 7, "score": 10},
        {"band": "secure", "fixes": 10, "score": 0},
    ]


def test_ties_at_the_top():
    levels = score_ladder.build_levels([(92, "imminent_compromise", 2), (67, "high", 1)])
    assert score_ladder.score_at(levels, 1) == (92, "imminent_compromise")
    assert score_ladder.score_at(levels, 2) == (67, "high")
    assert score_ladder.score_at(levels, 3) == (0, "secure")
    assert score_ladder.score_at(levels, -5) == (92, "imminent_compromise")
    after = score_ladder.summary(score_ladder.without_one(levels, 92))
    assert after["score"] == 92 and after["worst_band_count"] == 1
    assert score_ladder.summary(score_ladder.without_one(levels, 67)) == score_ladder.summary(levels)


def test_unique_worst():
    levels = score_ladder.build_levels([(92, "imminent_compromise", 1), (67, "high", 4)])
    assert score_ladder.summary(without := score_ladder.without_one(levels, 92)) == {
        "score": 67, "band": "high", "worst_band_count": 4}
    assert without[0]["fixes_before"] == 0
    # no level at that score: an equal rebuilt ladder
    assert score_ladder.without_one(levels, 50) == levels


def test_merge_fallback_ignore_and_sort():
    levels = score_ladder.build_levels([
        (30, "low", 1), (30, "elevated", 2),            # same score, two stored bands: worse band wins
        (80, None, 1),                                  # None falls back to band_for_score
        (0, "low", 4), (20, "low", 0), (-3, "low", 2),  # ignored
        (55, "not_a_band", 1),                          # unknown stored band falls back too
    ])
    assert [(lv["score"], lv["band"], lv["count"]) for lv in levels] == [
        (80, "imminent_compromise", 1), (55, "high", 1), (30, "elevated", 3)]
    assert levels[0]["fixes_before"] == 0 and levels[-1]["fixes_through"] == 5


def test_inconsistent_stored_band_gives_no_crossing():
    # 40 stored as "high" under a 60 "elevated": the step down to a higher-ranked band is no crossing
    levels = score_ladder.build_levels([(60, "elevated", 1), (40, "high", 1)])
    assert levels[0]["band_after"] == "high"
    assert score_ladder.crossings(levels) == [{"band": "secure", "fixes": 2, "score": 0}]


def test_empty():
    assert score_ladder.build_levels([]) == []
    assert score_ladder.crossings([]) == []
    assert score_ladder.summary([]) == {"score": 0, "band": "secure", "worst_band_count": 0}
    assert score_ladder.score_at([], 0) == (0, "secure")
    assert score_ladder.without_one([], 5) == []


def test_band_for_score_boundaries():
    for name, (lo, hi) in risk_scorer.BANDS.items():
        assert score_ladder.band_for_score(lo) == name
        assert score_ladder.band_for_score(hi) == name
    assert score_ladder.band_for_score(1) == "low" and score_ladder.band_for_score(24) == "low"
    assert score_ladder.band_for_score(25) == "elevated" and score_ladder.band_for_score(49) == "elevated"
    assert score_ladder.band_for_score(50) == "high" and score_ladder.band_for_score(74) == "high"
    assert score_ladder.band_for_score(75) == "imminent_compromise"
    assert score_ladder.band_for_score(100) == "imminent_compromise"
    assert score_ladder.band_for_score(150) == "imminent_compromise"
    assert score_ladder.band_for_score(0) == "secure" and score_ladder.band_for_score(-1) == "secure"
    assert score_ladder.band_rank("secure") == 0 and score_ladder.band_rank(None) == 0
    assert score_ladder.band_rank("nope") == 0 and score_ladder.band_rank("high") == 50


# ── routes ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def tokens():
    admin, admin_id = _make_user("admin")
    yield {"admin": admin}
    _cleanup_user(admin_id)


@pytest.fixture
def made(tokens):
    """Rows this test creates, deleted by id afterwards. Depends on `tokens` so
    it is torn down before the user is."""
    ids = {"findings": [], "assets": []}

    def asset():
        now = datetime.now(timezone.utc)
        db = SessionLocal()
        try:
            a = AssetCanonical(id=uuid.uuid4(), asset_type="dns_record", value=f"ladder-{uuid.uuid4().hex[:8]}.fabrikam.com",
                               tags=[], first_seen_at=now, last_seen_at=now, ignored=False)
            db.add(a)
            db.flush()
            db.add(AssetState(asset_canonical_id=a.id, estate="claimed_ours", open_ports=[], projected_at=now))
            db.commit()
            ids["assets"].append(a.id)
            return a.id
        finally:
            db.close()

    def finding(asset_id, score, state="open", band="low", verification=None):
        now = datetime.now(timezone.utc)
        db = SessionLocal()
        try:
            f = FindingCanonical(
                id=uuid.uuid4(), asset_canonical_id=asset_id, finding_type="cve", source="test",
                fingerprint=f"ladder-{uuid.uuid4().hex[:8]}", severity="low", title=f"ladder finding {score} {state}",
                state=state, first_seen_at=now, last_seen_at=now, detail={}, tags=[],
                risk_score=score, risk_band=band if score else None, verification=verification)
            db.add(f)
            db.commit()
            ids["findings"].append(f.id)
            return f.id
        finally:
            db.close()

    yield type("Made", (), {"asset": staticmethod(asset), "finding": staticmethod(finding)})
    db = SessionLocal()
    try:
        db.query(FindingCanonical).filter(FindingCanonical.id.in_(ids["findings"])).delete(synchronize_session=False)
        db.query(AssetState).filter(AssetState.asset_canonical_id.in_(ids["assets"])).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.id.in_(ids["assets"])).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _ladder(tokens, who="admin", **params):
    r = client.get("/api/findings/score-ladder", params=params, headers=tokens[who])
    assert r.status_code == 200, r.text
    return r.json()


def _after(tokens, fid, who="admin"):
    return client.get(f"/api/findings/{fid}/score-after", headers=tokens[who])


def _free_score(levels):
    taken = {lv["score"] for lv in levels}
    for s in list(range(1, 25)) + list(range(25, 101)):
        if s not in taken:
            return s
    pytest.skip("every score 1..100 is already used in the test database")


def _count_at(ladder, score):
    return next((lv["count"] for lv in ladder["levels"] if lv["score"] == score), 0)


def _five(tokens, made):
    base = _ladder(tokens)
    s = _free_score(base["levels"])
    a = made.asset()
    ids = {
        "open": made.finding(a, s, "open"),
        "ack": made.finding(a, s, "acknowledged"),
        "resolved": made.finding(a, s, "resolved"),
        "suppressed": made.finding(a, s, "suppressed"),
        "excluded": made.finding(a, s, "open", verification="rejected_shared_infra"),
    }
    return base, s, ids


def test_open_and_acknowledged_are_steps_others_are_not(tokens, made):
    base, s, _ids = _five(tokens, made)
    now = _ladder(tokens)
    assert _count_at(base, s) == 0
    assert _count_at(now, s) == 2                       # reached: open + acknowledged
    assert now["open_count"] == base["open_count"] + 2  # resolved, suppressed, excluded are not
    assert now["rule"] == "worst_open_finding"
    assert now["open_count"] == (now["levels"][-1]["fixes_through"] if now["levels"] else 0)


def test_unscored_open_finding_is_counted_apart(tokens, made):
    base = _ladder(tokens)
    a = made.asset()
    made.finding(a, None, "open")
    made.finding(a, _free_score(base["levels"]), "open")   # a scored one must NOT count as unscored
    now = _ladder(tokens)
    assert now["unscored_count"] == base["unscored_count"] + 1
    assert now["open_count"] == base["open_count"] + 1


def test_first_fixes_score_after_is_the_score_once_that_many_are_fixed(tokens, made):
    base = _ladder(tokens)
    taken = {lv["score"] for lv in base["levels"]}
    free = [s for s in range(100, 0, -1) if s not in taken][:2]
    if len(free) < 2:
        pytest.skip("fewer than two free scores in the test database")
    a = made.asset()
    for s in free:
        made.finding(a, s, "open", band=score_ladder.band_for_score(s))
    data = _ladder(tokens, fixes=20)
    ff = data["first_fixes"]
    assert len({r["risk_score"] for r in ff}) >= 2          # reached: a real step down is in view
    ordered = [lv["score"] for lv in data["levels"] for _ in range(lv["count"])]
    for r in ff:
        expected = ordered[r["rank"]] if r["rank"] < len(ordered) else 0
        assert r["score_after"] == expected
        assert r["risk_score"] == ordered[r["rank"] - 1]


def test_first_fixes(tokens, made):
    _five(tokens, made)
    data = _ladder(tokens, fixes=20)
    ff = data["first_fixes"]
    assert ff and len(ff) <= 20
    assert [r["rank"] for r in ff] == list(range(1, len(ff) + 1))
    scores = [r["risk_score"] for r in ff]
    assert scores == sorted(scores, reverse=True)
    for cur, nxt in zip(ff, ff[1:]):
        assert cur["score_after"] == nxt["risk_score"]
    assert ff[0]["risk_score"] == data["score"]
    assert _ladder(tokens, fixes=0)["first_fixes"] == []
    assert len(_ladder(tokens)["first_fixes"]) == min(3, data["open_count"])
    r = client.get("/api/findings/score-ladder", params={"fixes": 21}, headers=tokens["admin"])
    assert r.status_code == 422


def test_score_after_for_counted_and_uncounted_findings(tokens, made):
    _base, s, ids = _five(tokens, made)
    counted = _after(tokens, ids["open"])
    assert counted.status_code == 200 and counted.json()["counts_toward_score"] is True
    for key in ("resolved", "suppressed", "excluded"):
        body = _after(tokens, ids[key]).json()
        assert body["counts_toward_score"] is False
        assert body["score_after"] == body["score"]
        assert body["worst_band_count_after"] == body["worst_band_count"]
    assert _after(tokens, uuid.uuid4()).status_code == 404


def test_unique_worst_finding_drops_to_the_next_score(tokens, made):
    base = _ladder(tokens)
    if base["score"] >= 100:
        pytest.skip("a finding at risk_score 100 already exists in the test database")
    fid = made.finding(made.asset(), 100, "open", band="imminent_compromise")
    now = _ladder(tokens)
    assert now["score"] == 100                                    # reached
    body = _after(tokens, fid).json()
    assert body["counts_toward_score"] is True
    assert body["score"] == 100 and body["score_after"] == base["score"]
    assert body["band_after"] == base["band"]


@pytest.fixture(scope="module")
def w():
    world = ScopeWorld().build()
    yield world
    world.close()


@pytest.fixture(scope="module")
def scoped_tokens(w):
    admin, admin_id = _make_user("admin")
    viewer, viewer_id = _make_user("viewer")
    scoped, scoped_id = _make_user("viewer")
    db = SessionLocal()
    try:
        db.add(RoleAssignment(user_id=scoped_id, role="viewer", engagement_id=w.E["E1"]))
        db.commit()
    finally:
        db.close()
    yield {"admin": admin, "viewer": viewer, "viewer+E1": scoped}
    for uid in (admin_id, viewer_id, scoped_id):
        _cleanup_user(uid)


def test_read_scope_applies_to_the_ladder_and_score_after(w, scoped_tokens):
    admin = _ladder(scoped_tokens, "admin")
    viewer = _ladder(scoped_tokens, "viewer")
    scoped = _ladder(scoped_tokens, "viewer+E1")
    # every world finding sits at 90; the viewer reads two of seven, viewer+E1 five
    assert _count_at(admin, 90) > _count_at(viewer, 90)           # reached
    assert _count_at(admin, 90) - _count_at(viewer, 90) == 5
    assert _count_at(admin, 90) - _count_at(scoped, 90) == 2
    assert admin["open_count"] - viewer["open_count"] == 5
    hidden = w.f["a1"]
    assert _after(scoped_tokens, hidden, "admin").status_code == 200
    assert _after(scoped_tokens, hidden, "viewer").status_code == 404
    assert _after(scoped_tokens, hidden, "viewer+E1").status_code == 200
