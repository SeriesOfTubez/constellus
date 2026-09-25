"""RBAC and authentication wiring for the API routes (planning#162 items 1 & 2).

## Why this file does not follow the suite's API-test convention

Every other API test here calls the router function directly and passes
`_=None` for the auth dependency (`test_claims_api.py` states the pattern,
`test_third_party_capture.py` uses it). **That convention cannot test this
defect.** `_=None` supplies the parameter by hand, so FastAPI never resolves
the `Depends(...)` at all — `patch_target(..., _=None)` returns 200 for a
VIEWER both before and after the fix. A test written to the local idiom
here would be worthless: it would pass against the bug.

The defect is that a route *declared the wrong dependency*, so the test has
to go through the layer that resolves dependencies. This file therefore
introduces `TestClient` with `dependency_overrides` — the first in the
suite, and what #167 ("zero auth-RBAC tests, no TestClient anywhere") asks
for regardless. `httpx==0.28.1` was already a dependency.

Mutation-proved: restore `_=Depends(get_current_user)` on `patch_target`
and `test_viewer_cannot_patch_a_target` fails (200, not 403); drop
`_=Depends(get_current_user)` from `monitoring_status` and
`test_monitoring_status_requires_authentication` fails (200, not 401/403).

## No rows are written

The tests PATCH a random UUID that matches no target, so ADMIN reaches the
handler and gets a 404 — which is the point: it proves the route is
reachable for an admin and that the VIEWER's 403 comes from the guard
rather than from the route being broken for everyone. Nothing is inserted,
so there is nothing to clean up on the dev DB (see `_decision_log`'s
docstring for why that matters here).

Run with:  pytest app/tests/test_api_rbac.py
"""

import uuid

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import system, targets
from app.api.deps import get_current_user
from app.core.database import SessionLocal, get_db
from app.models.user import User, UserRole


def _user(role: UserRole) -> User:
    """An unpersisted User. `require_role` and `get_current_user` only read
    attributes, so there is no reason to write a row to the dev DB."""
    return User(
        id=uuid.uuid4(),
        email=f"rbac-test-{role.value}@example.invalid",
        full_name=f"RBAC test {role.value}",
        role=role.value,
        is_active=True,
    )


def _client(as_role: UserRole | None) -> TestClient:
    """A minimal app carrying the REAL routers, so the route's declared
    dependencies are the thing under test. `as_role=None` leaves
    `get_current_user` un-overridden — i.e. a genuinely anonymous caller,
    which is what item 2 is about."""
    app = FastAPI()
    app.include_router(targets.router, prefix="/api/targets")
    app.include_router(system.router, prefix="/api/system")

    def _db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _db
    if as_role is not None:
        user = _user(as_role)
        app.dependency_overrides[get_current_user] = lambda: user
    return TestClient(app)


# ── item 1: PATCH /api/targets/{id} is ADMIN-only ────────────────────────────

def test_viewer_cannot_patch_a_target():
    """The defect: `TargetPatch` carries `aggressiveness`, which governs how
    hard we probe someone else's infrastructure, and this route was the only
    one on the object not requiring ADMIN."""
    r = _client(UserRole.VIEWER).patch(
        f"/api/targets/{uuid.uuid4()}", json={"aggressiveness": "aggressive"}
    )
    assert r.status_code == 403, f"VIEWER got {r.status_code}, expected 403: {r.text}"


def test_viewer_cannot_set_engagement_id():
    """planning#211 — `engagement_id` (replacing the old posture boolean) governs
    whether this system probes a counterparty it may hold no authorisation
    to probe at all, on the same ADMIN-gated route as `aggressiveness`
    above. Same guard, same defect shape if this route ever regressed to
    bare `get_current_user`: the local `_=None` convention would pass this
    test even against the bug (this file's own docstring), which is why it
    belongs here."""
    r = _client(UserRole.VIEWER).patch(
        f"/api/targets/{uuid.uuid4()}", json={"engagement_id": str(uuid.uuid4())}
    )
    assert r.status_code == 403, f"VIEWER got {r.status_code}, expected 403: {r.text}"


def test_report_admin_cannot_patch_a_target():
    """REPORT_ADMIN is an admin of reports, not of scan posture. The bulk
    routes admit (ADMIN, INTEGRATION_ADMIN) only; this must match them
    rather than admitting anything whose name contains "admin"."""
    r = _client(UserRole.REPORT_ADMIN).patch(
        f"/api/targets/{uuid.uuid4()}", json={"aggressiveness": "aggressive"}
    )
    assert r.status_code == 403, f"REPORT_ADMIN got {r.status_code}, expected 403: {r.text}"


def test_admin_reaches_the_patch_handler():
    """404 (target not found), not 403 — so the VIEWER's 403 above is the
    guard talking, not a route that stopped working for everyone."""
    for role in (UserRole.ADMIN, UserRole.INTEGRATION_ADMIN):
        r = _client(role).patch(
            f"/api/targets/{uuid.uuid4()}", json={"notes": "rbac test"}
        )
        assert r.status_code == 404, f"{role.value} got {r.status_code}, expected 404: {r.text}"


def test_patch_target_matches_its_bulk_siblings():
    """The policy, asserted once rather than per-route: every route that can
    change a target's aggressiveness or delete it admits exactly the same
    role pair. A new one added under a different guard fails here."""
    import inspect

    def _guard_roles(fn):
        """The roles a route's `require_role(...)` dependency was built with,
        read off the closure of the factory's inner function."""
        found = []
        for p in inspect.signature(fn).parameters.values():
            dep = getattr(p.default, "dependency", None)
            if dep is None or dep.__qualname__ != "require_role.<locals>.dependency":
                continue
            cells = dict(zip(dep.__code__.co_freevars, (c.cell_contents for c in dep.__closure__)))
            found.append(tuple(cells["roles"]))
        return found

    pair = (UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)
    for fn in (
        targets.patch_target,
        targets.bulk_set_aggressiveness,
        targets.bulk_recheck_targets,
        targets.bulk_delete_targets,
        targets.delete_target,
    ):
        assert _guard_roles(fn) == [pair], (
            f"{fn.__name__} is not guarded by require_role{pair} — it guards with "
            f"{_guard_roles(fn)}. Every route that changes scan posture on a target "
            "must admit the same roles (planning#162 item 1)."
        )


# ── item 2: GET /api/system/monitoring-status requires authentication ────────

def test_monitoring_status_requires_authentication():
    r = _client(None).get("/api/system/monitoring-status")
    assert r.status_code in (401, 403), (
        f"anonymous caller got {r.status_code}, expected 401/403: {r.text}"
    )


def test_monitoring_status_readable_by_any_authenticated_role():
    """Authentication, not a role gate — it drives a UI widget."""
    r = _client(UserRole.VIEWER).get("/api/system/monitoring-status")
    assert r.status_code == 200, f"VIEWER got {r.status_code}, expected 200: {r.text}"


def test_status_stays_open():
    """`/status` must remain anonymous: the first-run bootstrap has to be
    readable before any user exists."""
    r = _client(None).get("/api/system/status")
    assert r.status_code == 200, f"/status got {r.status_code}, expected 200: {r.text}"
