"""`authorise_candidate_browse` (planning#280 S5b-2a): the browse gate for an
unclaimed scope candidate. Synthetic names only.

Run with:  backend/scripts/test.sh app/tests/test_candidate_browse_gate.py
"""

from datetime import datetime, timezone

import pytest
from sqlalchemy import text

from app.core.database import SessionLocal
from app.models.authorisation_decision import AuthorisationDecision
from app.models.observer import Observer
from app.models.page_capture import CAPTURE_STATUSES
from app.services import posture
from app.services.probe_authorisation import authorise_candidate_browse
from app.tests import _decision_log
from app.tests._engagement import make_engagement
from app.tests._org_world import World, hexid


@pytest.fixture
def w():
    mark = _decision_log.watermark()
    world = World()
    try:
        yield world
    finally:
        world.close()
        _decision_log.cleanup_since(mark)


def _dom() -> str:
    return f"gate280-{hexid()}.fabrikam.com"


def _decisions_for(candidate_id) -> list[AuthorisationDecision]:
    db = SessionLocal()
    try:
        return list(
            db.query(AuthorisationDecision).filter(
                AuthorisationDecision.evidence_snapshot["candidate_id"].astext == str(candidate_id)
            )
        )
    finally:
        db.close()


def _decision_count() -> int:
    db = SessionLocal()
    try:
        return db.query(AuthorisationDecision).count()
    finally:
        db.close()


def _deal(w, *postures):
    """An ma_target root with one engagement per posture given."""
    root = w.entity()
    now = datetime.now(timezone.utc)
    for p in postures:
        extra = {"authorised_at": now, "authorisation_reference": "gate280-ref"} if p in ("day_0", "integrated") else {}
        eng = make_engagement(w.db, p, subject_entity_id=root.id, **extra)
        w.engagements.append(eng.id)
    w.db.refresh(root)
    return root


def _denied(w, candidate, root, rule, *, observer_present=False):
    before = _decision_count()
    result = authorise_candidate_browse(w.db, candidate=candidate, root=root)
    assert result.allowed is False and result.rule_fired == rule
    assert _decision_count() == before + 1
    (row,) = _decisions_for(candidate.id)
    assert row.rule_fired == rule and row.allowed is False
    assert row.evidence_snapshot["decision_scope"] == "candidate"
    assert row.evidence_snapshot["domain"] == candidate.value
    assert (row.observer_id is not None) == observer_present


# ── permits ──────────────────────────────────────────────────────────────────


def test_ours_open_domain_is_allowed_and_logs_nothing(w):
    root = w.ours()
    c = w.candidate(root, value=_dom())
    before = _decision_count()
    result = authorise_candidate_browse(w.db, candidate=c, root=root)
    assert result.allowed is True and result.passive_only is False and result.rule_fired is None
    assert result.observer is not None and result.observer.name == "page_capture"
    assert _decision_count() == before


def test_ma_target_pre_close_is_allowed_but_passive_only(w):
    root = _deal(w, "pre_close")
    assert root.relationship == "ma_target"
    c = w.candidate(root, value=_dom())
    result = authorise_candidate_browse(w.db, candidate=c, root=root)
    assert result.allowed is True and result.passive_only is True


@pytest.mark.parametrize("p", ["day_0", "integrated"])
def test_ma_target_non_restricting_posture_is_not_passive_only(w, p):
    root = _deal(w, p)
    c = w.candidate(root, value=_dom())
    result = authorise_candidate_browse(w.db, candidate=c, root=root)
    assert result.allowed is True and result.passive_only is False


@pytest.mark.parametrize(
    "postures", [(), ("abandoned",), ("day_0", "integrated"), ("pre_close", "day_0")],
    ids=["no_engagements", "only_abandoned", "two_live", "two_live_mixed"],
)
def test_ma_target_without_exactly_one_live_engagement_fails_closed(w, postures):
    root = _deal(w, *postures) if postures else w.entity()
    if not postures:
        # No engagement at all: make it an M&A target the way an engagement would, then drop the engagement.
        eng = make_engagement(w.db, "pre_close", subject_entity_id=root.id)
        w.engagements.append(eng.id)
        w.db.refresh(root)
        from app.models.engagement import Engagement
        w.db.query(Engagement).filter(Engagement.id == eng.id).update({"subject_entity_id": None})
        w.db.commit()
        w.db.refresh(root)
        assert root.relationship == "ma_target"
    c = w.candidate(root, value=_dom())
    result = authorise_candidate_browse(w.db, candidate=c, root=root)
    assert result.allowed is True and result.passive_only is True


# ── denials ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("status", ["claimed", "rejected"])
def test_denies_a_candidate_that_is_not_open(w, status):
    root = w.ours()
    c = w.candidate(root, value=_dom())
    # Detached and edited in memory: the DB's CHECKs refuse a bare status flip, and the gate only reads.
    w.db.refresh(c)
    w.db.expunge(c)
    c.status = status
    _denied(w, c, root, "candidate:not_open")


def test_denies_a_non_domain_candidate(w):
    root = w.ours()
    c = w.candidate(root, value=_dom())
    w.db.refresh(c)
    w.db.expunge(c)  # kind is immutable in the DB; the gate only reads the attribute
    c.kind = "asn"
    _denied(w, c, root, "candidate:not_domain")


def test_denies_the_wrong_root(w):
    root, other = w.ours(), w.ours()
    c = w.candidate(root, value=_dom())
    _denied(w, c, other, "candidate:root_mismatch")


def test_denies_a_root_with_no_relationship(w):
    root = w.ours()
    c = w.candidate(root, value=_dom())
    w.db.refresh(root)
    w.db.expunge(root)  # a candidate cannot be made under a relationship-less root; edit a detached copy
    root.relationship = None
    _denied(w, c, root, "candidate:no_relationship")


def test_denies_when_the_observer_is_unseeded(w):
    root = w.ours()
    c = w.candidate(root, value=_dom())
    # Renamed rather than deleted: same "not found" to the gate, and the seeded row (which
    # migration 0091 owns) is put back by the finally.
    w.db.query(Observer).filter(Observer.name == "page_capture").update({"name": "page_capture_gate280_hidden"})
    w.db.commit()
    try:
        _denied(w, c, root, "observer:unseeded", observer_present=False)
    finally:
        w.db.rollback()
        w.db.query(Observer).filter(Observer.name == "page_capture_gate280_hidden").update({"name": "page_capture"})
        w.db.commit()
    assert w.db.query(Observer).filter(Observer.name == "page_capture").count() == 1


def test_denies_when_the_observer_noise_class_is_not_browse(w):
    root = w.ours()
    c = w.candidate(root, value=_dom())
    w.db.query(Observer).filter(Observer.name == "page_capture").update({"noise_class": "silent"})
    w.db.commit()
    try:
        _denied(w, c, root, "observer:noise_mismatch", observer_present=True)
    finally:
        w.db.rollback()
        w.db.query(Observer).filter(Observer.name == "page_capture").update({"noise_class": "browse"})
        w.db.commit()


def test_denies_when_browse_is_removed_from_the_passive_only_permitted_set(w, monkeypatch):
    root = _deal(w, "pre_close")
    c = w.candidate(root, value=_dom())
    monkeypatch.setattr(posture, "PASSIVE_ONLY_PERMITTED_NOISE", posture.PASSIVE_ONLY_PERMITTED_NOISE - {"browse"})
    _denied(w, c, root, "posture:passive_only", observer_present=True)


# ── the seeded row ───────────────────────────────────────────────────────────


def test_the_seeded_observer_row_and_status_vocabulary():
    db = SessionLocal()
    try:
        o = db.query(Observer).filter(Observer.name == "page_capture").one()
        assert (o.kind, o.trust, o.addressing, o.noise_class, o.confirms_relations) == (
            "scan", "observed", "name", "browse", False,
        )
        definition = db.execute(
            text("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'ck_page_captures_status'")
        ).scalar_one()
        import re
        assert set(re.findall(r"'([a-z_]+)'", definition)) == set(CAPTURE_STATUSES)
    finally:
        db.close()
