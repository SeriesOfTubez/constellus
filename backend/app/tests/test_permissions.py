"""The permission catalogue (planning#243 slice 1): zero access change.

`require_role` was replaced by `require_permission(Permission.X)`. The claim
under test is that NO route's allowed-role set moved. Three layers hold it:

1. **Parity** — the (route -> allowed roles) mapping, recomputed from the
   catalogue, equals `fixtures/route_access_baseline.json`, which was
   generated from the pre-refactor `require_role` code BEFORE any route was
   touched. A route added or removed fails too: the baseline is a full
   inventory, so adding a route is a deliberate baseline edit.
2. **Sweep** — every non-public route carries exactly one
   `require_permission`; the public set is an explicit literal; `require_role`
   and inline `.role` comparisons are gone from `app/api/`.
3. **In-body checks** — the four decisions that depend on request content
   (not just the route) are exercised with real users through the real app.

Mutation targets: drop a permission from an `ROLE_PERMISSIONS` entry
(parity fails), make `has_permission` always True (in-body + unknown-role
tests fail), make `require_permission` pass everything (in-body tests fail).
"""

import importlib
import json
import pkgutil
import re
import uuid
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

import app.api as api_pkg
from app.api import deps
from app.api.deps import get_current_user, require_permission
from app.core.database import SessionLocal
from app.core.permissions import ROLE_PERMISSIONS, Permission, has_permission
from app.main import app
from app.models.engagement import EngagementPosture
from app.models.org_entity import OrgEntity
from app.models.target import Target, TargetType
from app.models.user import User, UserRole
from app.tests import _docaddr
from app.tests._route_access import iter_app_routes, walk
from app.tests._users import user_with
from app.tests._engagement import cleanup_engagement, make_engagement
from app.tests._entity_graph import cleanup_entity, make_entity
from app.tests.test_edgar_ingest_api import _cleanup_user, _make_user

ADMIN = UserRole.ADMIN.value
INTEGRATION_ADMIN = UserRole.INTEGRATION_ADMIN.value
VIEWER = UserRole.VIEWER.value
ALL_ROLES = sorted(r.value for r in UserRole)

BASELINE = json.loads(
    (Path(__file__).parent / "fixtures" / "route_access_baseline.json").read_text()
)
API_DIR = Path(api_pkg.__path__[0])

# Routes callable with no credentials at all, and why.
PUBLIC_ROUTES = {
    "GET /api/auth/saml/login",   # starts the SSO redirect; there is no session yet
    "GET /api/health",            # liveness probe for the orchestrator
    "GET /api/settings/branding",  # the login page needs name and logo before sign-in
    "GET /api/system/status",     # reports whether first-run setup is still needed
    "POST /api/auth/login",       # exchanges credentials for a token
    "POST /api/auth/refresh",     # exchanges a refresh token for an access token
    "POST /api/auth/saml/acs",    # the IdP posts the assertion here
    "POST /api/auth/setup",       # creates the first admin; refuses once one exists
}

# Held by read_scope through `Grants`, not by an API `has_permission` call.
SERVICE_SIDE = {Permission.ENGAGEMENTS_READ_RESTRICTED}

# Left in the catalogue on purpose when the stale `domains` router was deleted
# (planning#284 slice A): removing a permission touches the role and route
# baselines, which is a separate change. No route uses them; a follow-up should
# delete them and this set together.
ORPHANED_DOMAINS = {
    Permission.DOMAINS_READ, Permission.DOMAINS_CREATE,
    Permission.DOMAINS_VERIFY, Permission.DOMAINS_DELETE,
}

# Decisions taken inside a handler on request content (not by the route's
# dependency). Each must appear in `app/api/` as `has_permission(..., X)`.
IN_BODY = {
    Permission.TARGETS_SET_ENTITY,
    Permission.TARGETS_WIDEN_ENGAGEMENT,
    Permission.USERS_READ_ANY,
    Permission.ENTITIES_MARK_OURS,
}

def _permissions_in(route) -> list[Permission]:
    return [n.call.permission for n in walk(route.dependant) if hasattr(n.call, "permission")]


def _is_public(route) -> bool:
    return not any(n.call is get_current_user for n in walk(route.dependant))


def route_roles(route):
    """Allowed roles for a route, computed from the catalogue."""
    if _is_public(route):
        return "public"
    perms = _permissions_in(route)
    assert len(perms) == 1, f"{route.path}: {len(perms)} require_permission dependencies"
    return sorted(r for r in ALL_ROLES if perms[0] in ROLE_PERMISSIONS[r])


def _module_routes():
    """(module, APIRoute) for every router in `app/api/`, mounted or not."""
    for info in pkgutil.iter_modules(api_pkg.__path__):
        router = getattr(importlib.import_module(f"app.api.{info.name}"), "router", None)
        for route in getattr(router, "routes", []):
            if isinstance(route, APIRoute):
                yield info.name, route


# ═════════════════════════ 1. parity ═════════════════════════════════════════

def test_every_route_admits_exactly_the_roles_the_baseline_recorded():
    now = {f"{m} {p}": route_roles(r) for m, p, r in iter_app_routes()}
    assert len(now) == len(BASELINE) > 150, "the inventory looks truncated"
    diffs = [
        f"{k}: baseline={BASELINE.get(k, '<absent>')} now={now.get(k, '<absent>')}"
        for k in sorted(set(now) | set(BASELINE))
        if now.get(k) != BASELINE.get(k)
    ]
    assert not diffs, "route access changed:\n" + "\n".join(diffs)


def test_no_router_is_defined_but_unmounted():
    # The stale `domains` router (never mounted; its table dropped in 0006) was
    # deleted in planning#284, so the mounted inventory sees every router. A
    # new unmounted router would escape the parity baseline; refuse it.
    mounted = {r.endpoint for _, _, r in iter_app_routes()}
    routes = list(_module_routes())
    assert routes, "no routers found: the discovery itself is broken"
    unmounted = [f"{module}.{route.name}" for module, route in routes if route.endpoint not in mounted]
    assert unmounted == []


# ═════════════════════════ 2. sweep ══════════════════════════════════════════

def test_public_routes_are_exactly_the_declared_set():
    public = {f"{m} {p}" for m, p, r in iter_app_routes() if _is_public(r)}
    assert public == PUBLIC_ROUTES


def test_every_authenticated_route_has_exactly_one_permission_dependency():
    checked = 0
    for _, route in _module_routes():
        if _is_public(route):
            continue
        checked += 1
        assert len(_permissions_in(route)) == 1, f"{route.path} ({route.name})"
    assert checked > 150


def test_require_role_is_gone_and_no_handler_compares_a_role():
    assert not hasattr(deps, "require_role")
    pattern = re.compile(r"\brequire_role\b|\.role\s*(==|!=)|\.role\s+not\s+in\b")
    offenders = [
        f"{f.name}:{n}: {line.strip()}"
        for f in sorted(API_DIR.glob("*.py"))
        for n, line in enumerate(f.read_text().splitlines(), 1)
        if pattern.search(line)
    ]
    assert not offenders, offenders


# ═════════════════════════ 3. catalogue hygiene ══════════════════════════════

def test_every_permission_is_used_and_every_value_is_well_formed():
    used = {p for _, r in _module_routes() for p in _permissions_in(r)} | IN_BODY | SERVICE_SIDE | ORPHANED_DOMAINS
    assert used == set(Permission), f"unused: {sorted(set(Permission) - used)}"
    for p in Permission:
        assert re.fullmatch(r"[a-z_]+\.[a-z_]+", p.value), p.value


def test_in_body_permissions_are_really_checked_in_the_api_code():
    source = "\n".join(f.read_text() for f in API_DIR.glob("*.py"))
    for p in IN_BODY:
        assert re.search(rf"has_permission\([^)]*Permission\.{p.name}\b", source), p


def test_service_side_permissions_are_really_checked_in_the_grants():
    source = (API_DIR.parent / "core" / "permissions.py").read_text()
    for p in SERVICE_SIDE:
        assert f"Permission.{p.name}" in source, p


def test_in_body_permissions_are_admin_only():
    for p in IN_BODY | SERVICE_SIDE:
        holders = sorted(r for r, held in ROLE_PERMISSIONS.items() if p in held)
        assert holders == [ADMIN], (p, holders)


def test_the_table_covers_exactly_the_known_roles_and_admin_holds_everything():
    assert sorted(ROLE_PERMISSIONS) == ALL_ROLES
    assert ROLE_PERMISSIONS[ADMIN] == frozenset(Permission)


def test_viewer_holds_every_read_the_baseline_let_it_do():
    viewer_reads = set()
    for m, p, r in iter_app_routes():
        if BASELINE[f"{m} {p}"] != "public" and VIEWER in BASELINE[f"{m} {p}"]:
            (perm,) = _permissions_in(r)
            if perm.value.endswith(".read"):
                viewer_reads.add(perm)
    assert len(viewer_reads) >= 15
    assert viewer_reads <= ROLE_PERMISSIONS[VIEWER]


def test_an_unknown_role_holds_nothing():
    for role in ("nobody", "", None, "ADMIN", "Admin"):
        ghost = user_with(role)
        assert not any(has_permission(ghost, p) for p in Permission), role


def test_has_permission_accepts_the_enum_member_as_well_as_its_value():
    assert has_permission(user_with(UserRole.ADMIN), Permission.USERS_CREATE)
    assert has_permission(user_with("admin"), Permission.USERS_CREATE)
    assert not has_permission(user_with(UserRole.VIEWER), Permission.USERS_CREATE)


def test_require_permission_tags_and_enforces():
    dep = require_permission(Permission.USERS_CREATE)
    assert dep.permission is Permission.USERS_CREATE
    admin = user_with(ADMIN)
    assert dep(current_user=admin) is admin
    with pytest.raises(HTTPException) as exc:
        dep(current_user=user_with(VIEWER))
    assert exc.value.status_code == 403 and exc.value.detail == "Insufficient permissions"


# ═════════════════════════ 4. in-body checks ═════════════════════════════════
#
# Each check is a decision the route dependency cannot make: whether a given
# request touches attribution / widens an engagement / names another user /
# marks a company ours. For each: ADMIN gets PAST the check (and the request
# provably got that far), the lesser role gets that check's 403 detail.

class _World:
    """Real users, one target, one entity, torn down by id."""

    def __init__(self):
        self.users: list[uuid.UUID] = []
        self.target_ids: list[uuid.UUID] = []
        self.entity_ids: list[uuid.UUID] = []
        self.engagement_ids: list[uuid.UUID] = []
        self.client = TestClient(app)

    def user(self, role: str) -> tuple[dict, uuid.UUID]:
        headers, uid = _make_user(role)
        self.users.append(uid)
        return headers, uid

    def target(self, **kw) -> uuid.UUID:
        db = SessionLocal()
        try:
            t = Target(id=uuid.uuid4(), type=TargetType.IP, value=_docaddr.alloc(),
                       verified=False, token=uuid.uuid4().hex, aggressiveness="polite", **kw)
            db.add(t)
            db.commit()
            tid = t.id
        finally:
            db.close()
        self.target_ids.append(tid)
        return tid

    def entity(self) -> uuid.UUID:
        db = SessionLocal()
        try:
            eid = make_entity(db).id
        finally:
            db.close()
        self.entity_ids.append(eid)
        return eid

    def engagement(self, posture: str) -> uuid.UUID:
        db = SessionLocal()
        try:
            gid = make_engagement(db, posture).id
        finally:
            db.close()
        self.engagement_ids.append(gid)
        return gid

    def close(self):
        db = SessionLocal()
        try:
            # Entities hold an FK to the authorising user: free them first.
            db.query(Target).filter(Target.id.in_(self.target_ids)).delete(synchronize_session=False)
            db.commit()
            for gid in self.engagement_ids:
                cleanup_engagement(db, gid)
            for eid in self.entity_ids:
                cleanup_entity(db, eid)
        finally:
            db.close()
        for uid in self.users:
            _cleanup_user(uid)


@pytest.fixture
def world():
    w = _World()
    yield w
    w.close()


def _target_state(target_id):
    db = SessionLocal()
    try:
        t = db.get(Target, target_id)
        return t.entity_id, t.engagement_id
    finally:
        db.close()


def test_setting_a_targets_entity_is_admin_only(world):
    entity_id = world.entity()
    target_id = world.target()
    admin_h, _ = world.user(ADMIN)
    integ_h, _ = world.user(INTEGRATION_ADMIN)

    r = world.client.patch(f"/api/targets/{target_id}", json={"entity_id": str(entity_id)}, headers=integ_h)
    assert r.status_code == 403 and r.json()["detail"] == "setting a target's entity requires ADMIN", r.text
    assert _target_state(target_id)[0] is None, "the refused request must not have written"

    r = world.client.patch(f"/api/targets/{target_id}", json={"entity_id": str(entity_id)}, headers=admin_h)
    assert r.status_code == 200, r.text
    # Reached: the write behind the check happened.
    assert _target_state(target_id)[0] == entity_id


def test_widening_a_targets_engagement_is_admin_only(world):
    restricting = world.engagement(EngagementPosture.PRE_CLOSE.value)
    admin_h, _ = world.user(ADMIN)
    integ_h, _ = world.user(INTEGRATION_ADMIN)
    detail = "widening a target's engagement membership requires ADMIN"

    target_id = world.target(engagement_id=restricting)
    r = world.client.patch(f"/api/targets/{target_id}", json={"clear_engagement": True}, headers=integ_h)
    assert r.status_code == 403 and r.json()["detail"] == detail, r.text
    assert _target_state(target_id)[1] == restricting

    # ADMIN passes the role check and is stopped LATER, by the reference rule:
    # 422 with that rule's detail proves the request got past the 403 gate.
    r = world.client.patch(f"/api/targets/{target_id}", json={"clear_engagement": True}, headers=admin_h)
    assert r.status_code == 422 and "authorisation_reference" in r.json()["detail"], r.text

    r = world.client.patch(
        f"/api/targets/{target_id}",
        json={"clear_engagement": True, "authorisation_reference": "TEST-REF-1"}, headers=admin_h,
    )
    assert r.status_code == 200, r.text
    assert _target_state(target_id)[1] is None


def test_viewing_another_user_needs_users_read_any_but_own_profile_is_open(world):
    viewer_h, viewer_id = world.user(VIEWER)
    admin_h, admin_id = world.user(ADMIN)

    r = world.client.get(f"/api/users/{admin_id}", headers=viewer_h)
    assert r.status_code == 403 and r.json()["detail"] == "Insufficient permissions", r.text

    r = world.client.get(f"/api/users/{viewer_id}", headers=viewer_h)
    assert r.status_code == 200 and r.json()["id"] == str(viewer_id), r.text

    r = world.client.get(f"/api/users/{viewer_id}", headers=admin_h)
    assert r.status_code == 200 and r.json()["id"] == str(viewer_id), r.text


def test_marking_a_company_ours_is_admin_only_though_the_route_admits_integration_admin(world):
    entity_id = world.entity()
    admin_h, _ = world.user(ADMIN)
    integ_h, _ = world.user(INTEGRATION_ADMIN)
    body = {"relationship": "ours", "reference": "TEST-REF-2"}

    r = world.client.put(f"/api/entities/{entity_id}/relationship", json=body, headers=integ_h)
    assert r.status_code == 403 and r.json()["detail"] == "only an admin can mark a company as ours", r.text

    r = world.client.put(f"/api/entities/{entity_id}/relationship", json=body, headers=admin_h)
    assert r.status_code == 200 and r.json()["relationship"] == "ours", r.text
    db = SessionLocal()
    try:
        assert db.get(OrgEntity, entity_id).relationship == "ours"
    finally:
        db.close()
