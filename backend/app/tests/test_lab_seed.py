"""`scripts/lab_seed.py` (planning#327): the kind lab seed and its database guard.
Synthetic names only. The script is loaded by path (it is never part of the image).

Run with:  backend/scripts/test.sh app/tests/test_lab_seed.py
"""

import importlib.util
import uuid
from pathlib import Path

import pytest

from app.core.database import SessionLocal
from app.models.engagement import Engagement
from app.models.org_entity import RELATIONSHIP_MA_TARGET, RELATIONSHIP_OURS, OrgEntity
from app.models.scope_candidate import ScopeCandidate
from app.models.target import Target
from app.models.user import UserRole
from app.services.org_discovery import candidates as cand_svc
from app.services.probe_authorisation import authorise_candidate_browse
from app.tests import _decision_log
from app.tests._org_world import World

_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "lab_seed.py"
_spec = importlib.util.spec_from_file_location("lab_seed_under_test", _SCRIPT)
lab_seed = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lab_seed)

MARKER = lab_seed.LAB_MARKER


@pytest.fixture
def w():
    mark = _decision_log.watermark()
    world = World()
    try:
        yield world
    finally:
        # The seed made an entity by name; World finds it by name and removes everything under it.
        world.entity_names.append(lab_seed.ORG_NAME)
        world.close()
        _decision_log.cleanup_since(mark)
        check = SessionLocal()
        try:
            assert check.query(OrgEntity).filter(OrgEntity.legal_name == lab_seed.ORG_NAME).count() == 0
            assert check.query(ScopeCandidate).filter(ScopeCandidate.value == lab_seed.DOMAIN).count() == 0
        finally:
            check.close()


def _counts() -> tuple[int, int]:
    db = SessionLocal()
    try:
        return (
            db.query(OrgEntity).filter(OrgEntity.legal_name == lab_seed.ORG_NAME).count(),
            db.query(ScopeCandidate).filter(ScopeCandidate.value == lab_seed.DOMAIN).count(),
        )
    finally:
        db.close()


def _entity(w) -> OrgEntity:
    return w.db.query(OrgEntity).filter(OrgEntity.legal_name == lab_seed.ORG_NAME).one()


@pytest.mark.parametrize(
    "name,comment,refused",
    [
        ("constellus_lab", MARKER, False),
        ("constellus", MARKER, True),
        ("constellus_test", MARKER, True),
        ("constellus_lab", None, True),
        ("constellus_lab", MARKER + " ", True),
        ("constellus_lab", "other", True),
        (None, MARKER, True),
    ],
)
def test_lab_db_refusal_table(name, comment, refused):
    reason = lab_seed.lab_db_refusal(name, comment)
    assert (reason is not None) == refused


def test_check_lab_db_refuses_the_test_database():
    db = SessionLocal()
    try:
        with pytest.raises(lab_seed.LabSeedRefused) as exc:
            lab_seed.check_lab_db(db)
    finally:
        db.close()
    # The name is in the reason, so the query ran and returned the real database name.
    assert "constellus_test" in str(exc.value)


def test_main_refuses_on_the_test_database_and_writes_nothing(monkeypatch, capsys):
    called = []
    monkeypatch.setattr(lab_seed, "seed", lambda *a, **k: called.append(1))
    before = _counts()
    rc = lab_seed.main(["lab_seed.py", "lab-admin@example.com"])
    out = capsys.readouterr()
    assert rc == 2
    assert out.out == ""
    assert "lab_seed: refused:" in out.err and "constellus_test" in out.err
    assert called == []
    assert _counts() == before == (0, 0)


def test_seed_creates_the_minimum_and_is_idempotent(w):
    admin = w.user()
    cid = lab_seed.seed(w.db, admin.email)
    w.db.expire_all()
    entity = _entity(w)
    assert entity.relationship == RELATIONSHIP_OURS
    candidate = w.db.get(ScopeCandidate, cid)
    assert candidate.value == lab_seed.DOMAIN and candidate.kind == "domain" and candidate.status == "open"

    result = authorise_candidate_browse(w.db, candidate=candidate, root=entity)
    assert result.allowed is True and result.passive_only is False

    assert w.db.query(Engagement).filter(Engagement.subject_entity_id == entity.id).count() == 0
    assert w.db.query(Target).filter(Target.entity_id == entity.id).count() == 0

    assert _counts() == (1, 1)
    assert lab_seed.seed(w.db, admin.email) == cid
    assert _counts() == (1, 1)


def test_seed_refuses_an_ma_target_and_changes_nothing(w):
    entity = w.entity(legal_name=lab_seed.ORG_NAME)
    w.deal(entity)
    admin = w.user()
    with pytest.raises(lab_seed.LabSeedRefused):
        lab_seed.seed(w.db, admin.email)
    w.db.expire_all()
    assert _entity(w).relationship == RELATIONSHIP_MA_TARGET
    assert _counts() == (1, 0)


def test_seed_refuses_a_rejected_candidate(w):
    admin = w.user()
    cid = lab_seed.seed(w.db, admin.email)
    cand_svc.reject(w.db, candidate_id=cid, user=admin, reason="lab seed test")
    w.db.expire_all()
    assert w.db.get(ScopeCandidate, cid).status == "rejected"
    with pytest.raises(lab_seed.LabSeedRefused):
        lab_seed.seed(w.db, admin.email)
    assert _counts() == (1, 1)


def test_seed_refuses_an_unknown_email(w):
    with pytest.raises(lab_seed.LabSeedRefused):
        lab_seed.seed(w.db, f"nobody-{uuid.uuid4().hex[:8]}@example.com")
    assert _counts() == (0, 0)


def test_seed_refuses_two_companies_with_the_seed_name(w):
    admin = w.user()
    first, second = w.entity(legal_name=lab_seed.ORG_NAME), w.entity(legal_name=lab_seed.ORG_NAME)
    with pytest.raises(lab_seed.LabSeedRefused):
        lab_seed.seed(w.db, admin.email)
    for e in (first, second):
        w.db.refresh(e)
        assert e.relationship is None
    assert _counts() == (2, 0)


def test_seed_refuses_a_non_admin(w):
    user = w.user(role=UserRole.VIEWER.value)
    with pytest.raises(lab_seed.LabSeedRefused):
        lab_seed.seed(w.db, user.email)
    assert _counts() == (0, 0)
