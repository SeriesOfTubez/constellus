"""Role assignments (planning#261): `Grants`, the flush hook that mirrors
`users.role`, and the engagement assignment API with real tokens.
"""

import json
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.core.database import SessionLocal
from app.core.permissions import ROLE_PERMISSIONS, Grants, Permission, compute_grants
from app.main import app
from app.models.role_assignment import RoleAssignment
from app.models.user import User, UserRole
from app.services import saml
from app.tests._scope_world import ScopeWorld
from app.tests._users import user_with
from app.tests.test_edgar_ingest_api import _cleanup_user, _make_user

client = TestClient(app)


# ── Grants ──────────────────────────────────────────────────────────────────

def test_global_viewer_reads_but_does_not_update():
    g = compute_grants(user_with("viewer"))
    assert g.allows(Permission.ASSETS_READ) and not g.allows(Permission.ASSETS_UPDATE)


def test_engagement_only_principal_gets_reads_only_and_no_admin_surface():
    g = compute_grants(user_with("viewer", engagements={uuid.uuid4(): "viewer"}, global_role=False))
    assert g.allows(Permission.ASSETS_READ)
    assert not g.allows(Permission.ASSETS_UPDATE)
    assert not g.allows(Permission.ENGAGEMENTS_READ_ASSIGNMENTS)


def test_an_engagement_admin_assignment_still_grants_reads_only():
    g = compute_grants(user_with("viewer", engagements={uuid.uuid4(): "admin"}, global_role=False))
    assert g.allows(Permission.ASSETS_READ) and not g.allows(Permission.ASSETS_UPDATE)
    assert not g.allows(Permission.ENGAGEMENTS_MANAGE_ASSIGNMENTS)


def test_an_engagement_assignment_opens_data_only_if_its_role_holds_the_read(monkeypatch):
    """Every built-in role holds assets.read today, so this needs a role that
    does not (a custom role, planning#243 slice 2)."""
    from app.core import permissions
    e = uuid.uuid4()
    monkeypatch.setitem(permissions.ROLE_PERMISSIONS, "no_asset_read", frozenset({Permission.FINDINGS_READ}))
    g = Grants(global_role="viewer", engagement_roles={e: "no_asset_read"})
    assert g.readable_engagements(Permission.ASSETS_READ) == frozenset()
    assert g.readable_engagements(Permission.FINDINGS_READ) == frozenset({e})   # reached


def test_unknown_role_holds_nothing():
    g = Grants(global_role="nobody")
    assert not any(g.allows(p) for p in Permission)


def test_read_restricted_is_admin_only():
    assert Grants(global_role="admin").allows(Permission.ENGAGEMENTS_READ_RESTRICTED)
    assert not Grants(global_role="integration_admin").allows(Permission.ENGAGEMENTS_READ_RESTRICTED)
    assert Grants(global_role="admin").reads_all_restricted
    assert not Grants(global_role="integration_admin").reads_all_restricted


# ── the flush hook ──────────────────────────────────────────────────────────

@pytest.fixture
def made():
    ids: list[uuid.UUID] = []
    yield ids
    for uid in ids:
        _cleanup_user(uid)


def _persist(made, role) -> uuid.UUID:
    db = SessionLocal()
    try:
        u = User(id=uuid.uuid4(), email=f"ra261-{uuid.uuid4().hex[:8]}@example.invalid", full_name="ra261",
                 role=role, is_active=True)
        db.add(u)
        made.append(u.id)
        db.commit()
        return u.id
    finally:
        db.close()


def _assignments(uid) -> list[tuple[str, uuid.UUID | None]]:
    db = SessionLocal()
    try:
        return sorted(((a.role, a.engagement_id) for a in db.query(RoleAssignment)
                       .filter(RoleAssignment.user_id == uid).all()), key=lambda t: t[0])
    finally:
        db.close()


def test_new_user_gets_exactly_one_global_assignment(made):
    uid = _persist(made, "report_admin")
    assert _assignments(uid) == [("report_admin", None)]


def test_role_given_as_an_enum_member_is_stored_as_its_value(made):
    uid = _persist(made, UserRole.ADMIN)
    assert _assignments(uid) == [("admin", None)]


def test_changing_the_role_updates_the_same_row(made):
    uid = _persist(made, "viewer")
    db = SessionLocal()
    try:
        before = db.execute(select(RoleAssignment.id).where(RoleAssignment.user_id == uid)).scalar_one()
        u = db.get(User, uid)
        u.role = "integration_admin"
        db.commit()
        rows = db.query(RoleAssignment).filter(RoleAssignment.user_id == uid).all()
        assert [(r.id, r.role) for r in rows] == [(before, "integration_admin")]
    finally:
        db.close()


def test_role_change_leaves_an_engagement_assignment_alone(made):
    w = ScopeWorld().build()
    try:
        uid = _persist(made, "viewer")
        db = SessionLocal()
        try:
            db.add(RoleAssignment(user_id=uid, role="viewer", engagement_id=w.E["E1"]))
            db.commit()
            db.get(User, uid).role = "report_admin"
            db.commit()
        finally:
            db.close()
        assert sorted(_assignments(uid), key=str) == sorted(
            [("report_admin", None), ("viewer", w.E["E1"])], key=str)
    finally:
        w.close()


def test_saml_jit_user_gets_a_viewer_global_assignment(made):
    db = SessionLocal()
    try:
        email = f"jit261-{uuid.uuid4().hex[:8]}@example.invalid"
        user = saml.find_or_link_sso_user(db, email, f"sub-{uuid.uuid4().hex}", jit_provisioning=True)
        made.append(user.id)
        assert user.role in ("viewer", UserRole.VIEWER)
    finally:
        db.close()
    assert _assignments(made[-1]) == [("viewer", None)]


def test_a_check_constraint_refuses_an_assignment_with_no_principal():
    db = SessionLocal()
    try:
        db.add(RoleAssignment(role="viewer", engagement_id=None))
        with pytest.raises(IntegrityError):
            db.commit()
    finally:
        db.rollback()
        db.close()


# ── through the API ─────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def world():
    w = ScopeWorld().build()
    yield w
    w.close()


@pytest.fixture
def people():
    ids: list[uuid.UUID] = []

    def make(role):
        headers, uid = _make_user(role)
        ids.append(uid)
        return headers, uid

    yield make
    for uid in ids:
        _cleanup_user(uid)


def test_patching_a_role_is_reflected_on_the_next_request(people):
    admin, _ = people("admin")
    viewer_h, viewer_id = people("viewer")
    url = f"/api/engagements/{uuid.uuid4()}/assignments"
    assert client.get(url, headers=viewer_h).status_code == 403
    r = client.patch(f"/api/users/{viewer_id}", json={"role": "admin"}, headers=admin)
    assert r.status_code == 200, r.text
    # the same token, the new role: admin passes the permission gate and reaches the 404
    assert client.get(url, headers=viewer_h).status_code == 404
    assert _assignments(viewer_id) == [("admin", None)]


def test_assignment_api_admin_put_get_delete_and_viewer_403(world, people):
    admin, _ = people("admin")
    viewer_h, viewer_id = people("viewer")
    e1 = world.E["E1"]
    url = f"/api/engagements/{e1}/assignments"
    one = f"{url}/{viewer_id}"

    # the viewer is refused all three
    assert client.get(url, headers=viewer_h).status_code == 403
    assert client.put(one, json={"role": "viewer"}, headers=viewer_h).status_code == 403
    assert client.delete(one, headers=viewer_h).status_code == 403
    assert _assignments(viewer_id) == [("viewer", None)]  # and nothing changed

    r = client.put(one, json={"role": "viewer"}, headers=admin)
    assert r.status_code == 200, r.text
    assert r.json()["user_id"] == str(viewer_id) and r.json()["role"] == "viewer"
    listed = client.get(url, headers=admin).json()
    assert [(x["user_id"], x["role"]) for x in listed] == [(str(viewer_id), "viewer")]
    # PUT again changes the one row rather than adding a second
    assert client.put(one, json={"role": "report_admin"}, headers=admin).status_code == 200
    assert [x["role"] for x in client.get(url, headers=admin).json()] == ["report_admin"]
    assert sorted(_assignments(viewer_id), key=str) == sorted(
        [("viewer", None), ("report_admin", e1)], key=str)

    assert client.delete(one, headers=admin).status_code == 200
    assert client.get(url, headers=admin).json() == []
    # never the global one
    assert _assignments(viewer_id) == [("viewer", None)]
    # no engagement assignment left to delete: 404, and still the global one
    assert client.delete(one, headers=admin).status_code == 404
    assert _assignments(viewer_id) == [("viewer", None)]


def test_assignment_api_validation_and_404s(world, people):
    admin, _ = people("admin")
    _, viewer_id = people("viewer")
    e1 = world.E["E1"]
    assert client.put(f"/api/engagements/{e1}/assignments/{viewer_id}", json={"role": "emperor"},
                      headers=admin).status_code == 422
    assert client.put(f"/api/engagements/{e1}/assignments/{viewer_id}", json={}, headers=admin).status_code == 422
    assert client.put(f"/api/engagements/{uuid.uuid4()}/assignments/{viewer_id}", json={"role": "viewer"},
                      headers=admin).status_code == 404
    assert client.put(f"/api/engagements/{e1}/assignments/{uuid.uuid4()}", json={"role": "viewer"},
                      headers=admin).status_code == 404
    assert client.get(f"/api/engagements/{uuid.uuid4()}/assignments", headers=admin).status_code == 404
    assert client.delete(f"/api/engagements/{uuid.uuid4()}/assignments/{viewer_id}",
                         headers=admin).status_code == 404
    assert _assignments(viewer_id) == [("viewer", None)]  # nothing was written


def test_an_engagement_assignment_opens_the_asset_to_the_viewer(world, people):
    admin, _ = people("admin")
    viewer_h, viewer_id = people("viewer")
    a1 = world.a["a1"]
    assert client.get(f"/api/assets/{a1}", headers=admin).status_code == 200   # reached
    assert client.get(f"/api/assets/{a1}", headers=viewer_h).status_code == 404
    r = client.put(f"/api/engagements/{world.E['E1']}/assignments/{viewer_id}", json={"role": "viewer"},
                   headers=admin)
    assert r.status_code == 200
    assert client.get(f"/api/assets/{a1}", headers=viewer_h).status_code == 200
    assert client.delete(f"/api/engagements/{world.E['E1']}/assignments/{viewer_id}", headers=admin).status_code == 200
    assert client.get(f"/api/assets/{a1}", headers=viewer_h).status_code == 404


def test_every_known_role_is_accepted_by_put(world, people):
    admin, _ = people("admin")
    _, uid = people("viewer")
    for role in ROLE_PERMISSIONS:
        r = client.put(f"/api/engagements/{world.E['E1']}/assignments/{uid}", json={"role": role}, headers=admin)
        assert r.status_code == 200, (role, r.text)
