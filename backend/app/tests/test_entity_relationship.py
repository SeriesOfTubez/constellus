"""A mapped company's relationship to us (planning#240, slice 1).

`app.services.entity_relationship` (the three states, the inheritance walk,
the AI scope), migration 0068's CHECKs, `candidates.claim` on top of
the walk, and the API: `PUT /entities/{id}/relationship`,
`GET /entities/{id}/destination`, and the engagement routes that keep
`ma_target` ⇔ subject-of-an-engagement.

Every company here is invented (`make_entity`'s random names).

Run with:  scripts/test.ps1 app/tests/test_entity_relationship.py
"""

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError

from app.core.auth import create_access_token
from app.core.database import SessionLocal
from app.main import app
from app.models.audit import AuditLog
from app.models.engagement import Engagement
from app.models.org_entity import OrgEntity
from app.models.scan import ScanRun
from app.models.target import Target
from app.models.user import User, UserRole
from app.services.org_discovery import candidates as cd
from app.tests import _scope_candidates
from app.services import entity_graph
from app.services import entity_relationship as er
from app.services import llm_connector
from app.tests._engagement import cleanup_engagement, make_engagement
from app.tests._entity_graph import (
    cleanup_entity,
    cleanup_evidence,
    cleanup_observer,
    cleanup_relation,
    make_entity,
    make_evidence,
    make_observer,
)

client = TestClient(app)


def _hex() -> str:
    return uuid.uuid4().hex[:10]


class _World:
    def __init__(self):
        self.db = SessionLocal()
        self.entities: list[uuid.UUID] = []
        self.engagements: list[uuid.UUID] = []
        self.relations: list[uuid.UUID] = []
        self.evidence: list[uuid.UUID] = []
        self.users: list[uuid.UUID] = []
        self.observer = make_observer(self.db)

    def user(self, role: str = UserRole.ADMIN.value) -> User:
        u = User(
            id=uuid.uuid4(), email=f"er240-{_hex()}@example.invalid", full_name="er240 test",
            role=role, is_active=True,
        )
        self.db.add(u)
        self.db.commit()
        self.users.append(u.id)
        return u

    def headers(self, role: str) -> dict:
        u = self.user(role)
        return {"Authorization": f"Bearer {create_access_token(str(u.id), role)}"}

    def entity(self) -> OrgEntity:
        e = make_entity(self.db)
        self.entities.append(e.id)
        return e

    def engagement(self, posture: str = "pre_close", subject: OrgEntity | None = None) -> Engagement:
        extra = {}
        if posture in ("day_0", "integrated"):
            extra = {"authorised_at": datetime.now(timezone.utc), "authorisation_reference": "er240-ref"}
        e = make_engagement(self.db, posture, subject_entity_id=subject.id if subject else None, **extra)
        self.engagements.append(e.id)
        return e

    def ours(self, entity: OrgEntity) -> OrgEntity:
        er.set_ours(self.db, entity_id=entity.id, reference="er240 ref", user=self.user())
        self.db.refresh(entity)
        return entity

    def edge(self, subject: OrgEntity, obj: OrgEntity, relation: str, *, confirm: bool = True):
        ev = make_evidence(self.db, content=f"er240 {_hex()}".encode(), source_url=f"https://example.test/{_hex()}")
        self.evidence.append(ev.id)
        rel = entity_graph.assert_relation(
            self.db, subject_id=subject.id, object_id=obj.id, relation=relation, observer_id=self.observer.id,
            evidence_id=ev.id, quote="er240", event_date=None, event_date_precision="unknown",
        )
        self.relations.append(rel.id)
        if confirm:
            entity_graph.decide(self.db, relation_id=rel.id, status="confirmed", user=self.user())
        return rel

    def child_of(self, parent: OrgEntity, *, via: str = "subsidiary_of", confirm: bool = True) -> OrgEntity:
        """A new entity under `parent`, in this codebase's direction
        convention: `child subsidiary_of parent`, `parent acquired child`."""
        child = self.entity()
        if via == "subsidiary_of":
            self.edge(child, parent, "subsidiary_of", confirm=confirm)
        else:
            self.edge(parent, child, "acquired", confirm=confirm)
        return child

    def candidate(self, root: OrgEntity, via: OrgEntity | None = None):
        """An open candidate under `root`, raised by a Strong signal that runs
        through `via` (default the root itself)."""
        candidate, _evidence = _scope_candidates.make_candidate(
            self.db, root_id=root.id, via_id=(via or root).id, track=self.evidence
        )
        return candidate

    def close(self):
        db = self.db
        db.rollback()
        _scope_candidates.purge(db, entity_ids=self.entities)
        db.query(Target).filter(Target.entity_id.in_(self.entities)).delete(synchronize_session=False)
        db.query(ScanRun).filter(ScanRun.created_by_id.in_(self.users)).delete(synchronize_session=False)
        db.commit()
        # Engagements created through the API are found by subject.
        api_made = [
            e.id for e in db.query(Engagement).filter(Engagement.subject_entity_id.in_(self.entities)).all()
        ]
        for eid in set(self.engagements) | set(api_made):
            cleanup_engagement(db, eid)
        for rid in self.relations:
            cleanup_relation(db, rid)
        for eid in self.entities:
            cleanup_entity(db, eid)
        for fid in self.evidence:
            cleanup_evidence(db, fid)
        cleanup_observer(db, self.observer.id)
        db.query(AuditLog).filter(AuditLog.user_id.in_(self.users)).delete(synchronize_session=False)
        db.query(User).filter(User.id.in_(self.users)).delete(synchronize_session=False)
        db.commit()
        db.close()


@pytest.fixture
def w():
    world = _World()
    yield world
    world.close()


# ── 1. migration 0068's CHECKs ──────────────────────────────────────────────


@pytest.mark.parametrize("fields", [
    # unset carrying a live-looking authorisation (the NULL-CHECK trap)
    {"relationship": None, "ours_authorised_at": "now", "ours_reference": "ref"},
    # ma_target carrying one
    {"relationship": "ma_target", "ours_authorised_at": "now", "ours_reference": "ref"},
    # ours with no reference / a blank one / no time
    {"relationship": "ours", "ours_authorised_at": "now", "ours_reference": None},
    {"relationship": "ours", "ours_authorised_at": "now", "ours_reference": "   "},
    {"relationship": "ours", "ours_authorised_at": None, "ours_reference": "ref"},
    # not in the vocabulary
    {"relationship": "partner", "ours_authorised_at": None, "ours_reference": None},
])
def test_checks_refuse_inconsistent_rows(w, fields):
    e = w.entity()
    for k, v in fields.items():
        setattr(e, k, datetime.now(timezone.utc) if v == "now" else v)
    with pytest.raises(IntegrityError):
        w.db.commit()
    w.db.rollback()


def test_checks_admit_the_three_consistent_states(w):
    e = w.entity()
    assert e.relationship is None
    e.relationship, e.ours_authorised_at, e.ours_reference = "ours", datetime.now(timezone.utc), "ref"
    w.db.commit()
    e.relationship, e.ours_authorised_at, e.ours_reference = "ma_target", None, None
    w.db.commit()


# ── 2. the inheritance walk (item 3) ────────────────────────────────────────


def test_unset_resolves_to_unset(w):
    assert er.resolve(w.db, w.entity().id).status == "unset"


@pytest.mark.parametrize("via", ["subsidiary_of", "acquired"])
def test_ours_inherits_down_both_parent_edges(w, via):
    parent = w.ours(w.entity())
    child = w.child_of(parent, via=via)
    grandchild = w.child_of(child, via=via)
    for e in (parent, child, grandchild):
        res = er.resolve(w.db, e.id)
        assert (res.status, res.estate, [s.entity_id for s in res.stops]) == ("ours", True, [parent.id])


@pytest.mark.parametrize("via", ["subsidiary_of", "acquired"])
def test_a_proposed_edge_carries_nothing(w, via):
    parent = w.ours(w.entity())
    child = w.child_of(parent, via=via, confirm=False)
    assert er.resolve(w.db, child.id).status == "unset"


@pytest.mark.parametrize("via", ["subsidiary_of", "acquired"])
def test_inheritance_never_walks_up_from_parent_to_child(w, via):
    """Carve-out: an engagement whose subject is a DIVISION must not receive
    the parent's domains (the old either-direction C3 hop did)."""
    parent = w.entity()
    division = w.child_of(parent, via=via)
    eng = w.engagement("pre_close", subject=division)
    assert er.resolve(w.db, division.id).engagements == [eng]
    assert er.resolve(w.db, parent.id).status == "unset"
    # The division's organization cannot take a signal that runs through
    # its PARENT: the parent is not in the division's tree.
    with pytest.raises(cd.CandidateInvalid, match="tree"):
        w.candidate(division, via=parent)
    del eng


def test_the_nearest_relationship_wins_on_a_path(w):
    grand = w.ours(w.entity())
    parent = w.child_of(grand)
    eng = w.engagement("pre_close", subject=parent)
    child = w.child_of(parent)
    res = er.resolve(w.db, child.id)
    assert (res.status, res.estate, [e.id for e in res.engagements]) == ("engagement", False, [eng.id])


def test_different_answers_on_two_paths_are_ambiguous(w):
    ours_parent = w.ours(w.entity())
    target_parent = w.entity()
    eng = w.engagement("pre_close", subject=target_parent)
    child = w.child_of(ours_parent)
    w.edge(child, target_parent, "subsidiary_of")
    res = er.resolve(w.db, child.id)
    assert (res.status, res.estate, [e.id for e in res.engagements]) == ("ambiguous", True, [eng.id])


def test_two_live_engagements_are_ambiguous_and_abandoned_ones_are_not_live(w):
    subject = w.entity()
    a = w.engagement("pre_close", subject=subject)
    w.engagement("abandoned", subject=subject)
    assert er.resolve(w.db, subject.id).status == "engagement"
    b = w.engagement("day_0", subject=subject)
    res = er.resolve(w.db, subject.id)
    assert (res.status, {e.id for e in res.engagements}) == ("ambiguous", {a.id, b.id})


def test_an_abandoned_stop_blocks_and_is_not_walked_past(w):
    grand = w.ours(w.entity())
    parent = w.child_of(grand)
    w.engagement("abandoned", subject=parent)
    child = w.child_of(parent)
    res = er.resolve(w.db, child.id)
    assert (res.status, res.estate) == ("abandoned", False)


def test_a_cycle_terminates_unset(w):
    a, b = w.entity(), w.entity()
    w.edge(a, b, "subsidiary_of")
    w.edge(b, a, "subsidiary_of")
    assert er.resolve(w.db, a.id).status == "unset"


# ── 3. the AI scope (item 5) ────────────────────────────────────────────────


def test_ai_scope_follows_the_same_walk(w):
    unset = w.entity()
    assert er.ai_scope(w.db, unset.id) == (None, True)

    ours = w.ours(w.entity())
    assert er.ai_scope(w.db, w.child_of(ours).id) == (None, False)

    subject = w.entity()
    eng = w.engagement("day_0", subject=subject)
    assert er.ai_scope(w.db, w.child_of(subject).id) == (eng, False)

    # Conflict (ours on one path, an engagement on another) → strict.
    child = w.child_of(ours)
    w.edge(child, subject, "subsidiary_of")
    assert er.ai_scope(w.db, child.id) == (None, True)


def test_ai_scope_prefers_a_restricting_engagement(w):
    subject = w.entity()
    pre = w.engagement("pre_close", subject=subject)
    day0 = w.engagement("day_0", subject=subject)
    day0.created_at = datetime(2099, 1, 1, tzinfo=timezone.utc)
    w.db.commit()
    assert er.ai_scope(w.db, subject.id) == (pre, False)


def test_force_strict_only_raises_the_policy():
    from app.core.config import settings

    prior = settings.llm_data_policy
    try:
        settings.llm_data_policy = "dev_permissive"
        assert llm_connector.effective_data_policy(None) == "dev_permissive"
        assert llm_connector.effective_data_policy(None, force_strict=True) == "strict"
        settings.llm_data_policy = "strict"
        assert llm_connector.effective_data_policy(None, force_strict=False) == "strict"
    finally:
        settings.llm_data_policy = prior


# ── 4. the writers ──────────────────────────────────────────────────────────


def test_set_ours_records_who_when_and_reference(w):
    e = w.entity()
    admin = w.user()
    with pytest.raises(er.RelationshipInvalid):
        er.set_ours(w.db, entity_id=e.id, reference="  ", user=admin)
    entity, previous = er.set_ours(w.db, entity_id=e.id, reference=" contract 7 ", user=admin)
    assert (previous, entity.relationship, entity.ours_authorised_by_id, entity.ours_reference) == (
        None, "ours", admin.id, "contract 7",
    )
    assert entity.ours_authorised_at is not None


def test_an_engagement_subject_cannot_become_ours(w):
    e = w.entity()
    w.engagement("pre_close", subject=e)
    with pytest.raises(er.RelationshipConflict, match="subject of an engagement"):
        er.set_ours(w.db, entity_id=e.id, reference="ref", user=w.user())


def test_set_ma_target_creates_a_pre_close_engagement_and_clears_ours(w):
    e = w.ours(w.entity())
    entity, previous, eng, created = er.set_ma_target(
        w.db, entity_id=e.id, user=w.user(), new_engagement_name=f"er240-{_hex()}", may_clear_ours=True,
    )
    w.engagements.append(eng.id)
    assert (previous, entity.relationship, created, eng.posture, eng.subject_entity_id) == (
        "ours", "ma_target", True, "pre_close", e.id,
    )
    assert (entity.ours_authorised_at, entity.ours_reference, entity.ours_authorised_by_id) == (None, None, None)


def test_set_ma_target_refuses_another_subjects_or_an_abandoned_engagement(w):
    e, other = w.entity(), w.entity()
    taken = w.engagement("pre_close", subject=other)
    with pytest.raises(er.RelationshipConflict, match="different subject"):
        er.set_ma_target(w.db, entity_id=e.id, user=w.user(), engagement_id=taken.id, may_clear_ours=True)
    dead = w.engagement("abandoned")
    with pytest.raises(er.RelationshipConflict, match="abandoned"):
        er.set_ma_target(w.db, entity_id=e.id, user=w.user(), engagement_id=dead.id, may_clear_ours=True)
    free = w.engagement("pre_close")
    entity, _, eng, created = er.set_ma_target(
        w.db, entity_id=e.id, user=w.user(), engagement_id=free.id, may_clear_ours=False,
    )
    assert (entity.relationship, eng.subject_entity_id, created) == ("ma_target", e.id, False)


def test_only_an_admin_may_move_a_company_off_ours(w):
    e = w.ours(w.entity())
    with pytest.raises(er.RelationshipForbidden):
        er.set_ma_target(
            w.db, entity_id=e.id, user=w.user(), new_engagement_name=f"er240-{_hex()}", may_clear_ours=False,
        )
    with pytest.raises(er.RelationshipForbidden):
        er.clear(w.db, entity_id=e.id, may_clear_ours=False)
    w.db.refresh(e)
    assert e.relationship == "ours"
    entity, previous = er.clear(w.db, entity_id=e.id, may_clear_ours=True)
    assert (previous, entity.relationship, entity.ours_reference) == ("ours", None, None)


def test_clear_is_refused_while_a_subject(w):
    e = w.entity()
    w.engagement("pre_close", subject=e)
    with pytest.raises(er.RelationshipConflict, match="detach or delete"):
        er.clear(w.db, entity_id=e.id, may_clear_ours=True)


# ── 5. claim on top of the walk ─────────────────────────────────────────────


def test_claim_into_our_estate_creates_an_engagementless_target(w):
    root = w.ours(w.entity())
    child = w.child_of(root, via="acquired")
    c = w.candidate(root, via=child)
    result = cd.claim(w.db, candidate_id=c.id, user=w.user())
    # Attributed to the company the signal ran through; destination from the ROOT.
    assert (result.target.engagement_id, result.target.entity_id, result.candidate.engagement_id) == (
        None, child.id, None,
    )
    assert (result.candidate.accepted_into, result.created) == ("estate", True)


def test_an_estate_target_is_a_conflict_for_an_engagement_claim(w):
    subject = w.entity()
    eng = w.engagement("pre_close", subject=subject)
    c = w.candidate(subject)
    owned = Target(id=uuid.uuid4(), type="domain", value=c.value, entity_id=subject.id)
    w.db.add(owned)
    w.db.commit()
    with pytest.raises(cd.CandidateConflict, match="outside this destination"):
        cd.claim(w.db, candidate_id=c.id, user=w.user())
    w.db.refresh(owned)
    assert owned.engagement_id is None
    del eng


# ── 6. the API ──────────────────────────────────────────────────────────────


def _put(entity_id, headers, **body):
    return client.put(f"/api/entities/{entity_id}/relationship", json=body, headers=headers)


def test_api_roles(w):
    e = w.entity()
    viewer, integ, admin = (
        w.headers(UserRole.VIEWER.value), w.headers(UserRole.INTEGRATION_ADMIN.value), w.headers(UserRole.ADMIN.value),
    )
    assert _put(e.id, viewer, relationship="ma_target", new_engagement_name=f"er240-{_hex()}").status_code == 403
    assert _put(e.id, integ, relationship="ours", reference="ref").status_code == 403
    assert _put(e.id, admin, relationship="ours", reference="").status_code == 422
    r = _put(e.id, admin, relationship="ours", reference="ref 1")
    assert (r.status_code, r.json()["relationship"], r.json()["ours_reference"]) == (200, "ours", "ref 1")
    # integration_admin may not move a company off ours, by either route.
    assert _put(e.id, integ, relationship=None).status_code == 403
    assert _put(e.id, integ, relationship="ma_target", new_engagement_name=f"er240-{_hex()}").status_code == 403
    w.db.refresh(e)
    assert e.relationship == "ours"
    other = w.entity()
    r = _put(other.id, integ, relationship="ma_target", new_engagement_name=f"er240-{_hex()}")
    assert (r.status_code, r.json()["relationship"]) == (200, "ma_target")
    assert _put(other.id, admin, relationship="partner").status_code == 422


def test_api_relationship_change_is_audited_with_its_reference(w):
    e = w.entity()
    admin_headers = w.headers(UserRole.ADMIN.value)
    assert _put(e.id, admin_headers, relationship="ours", reference="ticket 42").status_code == 200
    row = (
        w.db.query(AuditLog).filter(AuditLog.user_id.in_(w.users)).order_by(AuditLog.occurred_at.desc()).first()
    )
    detail = row.detail["changes"]
    assert detail["relationship"] == {"from": None, "to": "ours"}
    assert detail["reference"] == "ticket 42"


def test_api_destination(w):
    parent = w.entity()
    eng = w.engagement("pre_close", subject=parent)
    child = w.child_of(parent)
    r = client.get(f"/api/entities/{child.id}/destination", headers=w.headers(UserRole.VIEWER.value))
    body = r.json()
    assert (r.status_code, body["status"], [e["id"] for e in body["engagements"]]) == (
        200, "engagement", [str(eng.id)],
    )
    assert [(s["entity_id"], s["depth"]) for s in body["stops"]] == [(str(parent.id), 1)]


def test_engagement_subject_routes_keep_the_invariant(w):
    admin = w.headers(UserRole.ADMIN.value)
    first, second, ours = w.entity(), w.entity(), w.ours(w.entity())
    eng = w.engagement("pre_close")
    r = client.patch(f"/api/engagements/{eng.id}", json={"subject_entity_id": str(ours.id)}, headers=admin)
    assert r.status_code == 409
    assert client.patch(f"/api/engagements/{eng.id}", json={"subject_entity_id": str(first.id)}, headers=admin).status_code == 200
    w.db.refresh(first)
    assert first.relationship == "ma_target"
    # Re-pointing leaves the old subject with no engagement → back to unset.
    assert client.patch(f"/api/engagements/{eng.id}", json={"subject_entity_id": str(second.id)}, headers=admin).status_code == 200
    w.db.refresh(first)
    w.db.refresh(second)
    assert (first.relationship, second.relationship) == (None, "ma_target")
    # Deleting the last engagement → unset.
    assert client.delete(f"/api/engagements/{eng.id}", headers=admin).status_code == 200
    w.engagements.remove(eng.id)
    w.db.refresh(second)
    assert second.relationship is None


def test_an_integrated_engagement_is_never_flipped_to_ours(w):
    """Item 6."""
    admin = w.headers(UserRole.ADMIN.value)
    subject = w.entity()
    eng = w.engagement("day_0", subject=subject)
    r = client.post(f"/api/engagements/{eng.id}/transition", json={"to": "integrated"}, headers=admin)
    assert r.status_code == 200
    w.db.refresh(subject)
    assert subject.relationship == "ma_target"
    assert er.resolve(w.db, subject.id).engagements[0].id == eng.id


# ── planning#277 S1a: engagements.deal_reference ────────────────────────────


def test_relationship_route_stores_the_reference_on_a_new_engagement_only(w):
    admin = w.headers(UserRole.ADMIN.value)
    e = w.entity()
    r = _put(e.id, admin, relationship="ma_target", new_engagement_name=f"er277-{_hex()}", reference="DEAL-0001")
    assert r.status_code == 200
    eng = w.db.query(Engagement).filter(Engagement.subject_entity_id == e.id).one()
    assert eng.deal_reference == "DEAL-0001"
    assert eng.deal_reference_by_id is not None and eng.deal_reference_at is not None
    assert eng.authorised_at is None  # untouched: the CHECK ties these to posture

    # An existing engagement is linked, never overwritten.
    other = w.entity()
    existing = w.engagement()
    r = _put(other.id, admin, relationship="ma_target", engagement_id=str(existing.id), reference="DEAL-0002")
    assert r.status_code == 200
    w.db.refresh(existing)
    assert existing.subject_entity_id == other.id  # the path was reached
    assert (existing.deal_reference, existing.deal_reference_by_id, existing.deal_reference_at) == (None, None, None)

    # With a pre-set value on the existing engagement, it stays.
    third = w.entity()
    kept = w.engagement()
    kept.deal_reference, kept.deal_reference_at = "DEAL-ORIGINAL", datetime.now(timezone.utc)
    w.db.commit()
    r = _put(third.id, admin, relationship="ma_target", engagement_id=str(kept.id), reference="DEAL-0003")
    assert r.status_code == 200
    w.db.refresh(kept)
    assert kept.subject_entity_id == third.id and kept.deal_reference == "DEAL-ORIGINAL"


def test_post_engagements_with_and_without_deal_reference(w):
    admin = w.headers(UserRole.ADMIN.value)
    r = client.post("/api/engagements/", json={"name": f"er277-{_hex()}", "deal_reference": "  DEAL-0001 "}, headers=admin)
    assert r.status_code == 201
    w.engagements.append(uuid.UUID(r.json()["id"]))
    body = r.json()
    assert body["deal_reference"] == "DEAL-0001" and body["deal_reference_at"] is not None
    assert body["deal_reference_by"] is not None and body["deal_reference_by"].endswith("@example.invalid")

    got = client.get(f"/api/engagements/{body['id']}", headers=admin).json()
    assert (got["deal_reference"], got["deal_reference_at"], got["deal_reference_by"]) == (
        body["deal_reference"], body["deal_reference_at"], body["deal_reference_by"],
    )
    listed = [x for x in client.get("/api/engagements/", headers=admin).json() if x["id"] == body["id"]]
    assert len(listed) == 1 and listed[0]["deal_reference"] == "DEAL-0001"
    assert listed[0]["deal_reference_by"] == body["deal_reference_by"]

    for extra in ({}, {"deal_reference": None}, {"deal_reference": "   "}):
        r = client.post("/api/engagements/", json={"name": f"er277-{_hex()}", **extra}, headers=admin)
        assert r.status_code == 201
        w.engagements.append(uuid.UUID(r.json()["id"]))
        assert (r.json()["deal_reference"], r.json()["deal_reference_at"], r.json()["deal_reference_by"]) == (None, None, None)


@pytest.mark.parametrize("ref,at", [("DEAL-0001", None), (None, "now"), ("   ", "now"), ("", "now")])
def test_deal_reference_check_refuses_inconsistent_rows(w, ref, at):
    eng = w.engagement()
    eng.deal_reference = ref
    eng.deal_reference_at = datetime.now(timezone.utc) if at == "now" else None
    with pytest.raises(IntegrityError):
        w.db.commit()
    w.db.rollback()


def test_deal_reference_check_admits_set_together_and_unset(w):
    eng = w.engagement()
    eng.deal_reference, eng.deal_reference_at = "DEAL-0001", datetime.now(timezone.utc)
    w.db.commit()
    eng.deal_reference, eng.deal_reference_at = None, None
    w.db.commit()
