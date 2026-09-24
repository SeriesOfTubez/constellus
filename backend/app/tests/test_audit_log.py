"""The audit trail: coverage by construction, not by discipline (planning#194).

`audit_logs` shipped with every column and index it needs and no writer, so
nothing recorded who deleted a target, changed a role or raised a scan tier.
These tests hold the three claims the fix rests on:

1. **Coverage is by construction.** `AuditMiddleware` records every mutating
   request that carried an authenticated principal, so the set of audited
   endpoints is exactly the set of authenticated ones. The enumeration test
   below therefore does not check "is this endpoint audited" (it always is)
   — it checks the only way coverage can actually be lost: a new mutating
   endpoint that is NOT authenticated, and so has no principal to attribute
   the action to. That test fails on a newly added endpoint rather than
   letting it go quietly unaudited.
2. **`detail` never becomes a credential store.** Nothing from a request
   body is recorded by default, and everything that does reach `detail`
   passes through the key-name denylist.
3. **The trail cannot be erased through the API.** planning#162's point:
   `DELETE /api/logs/` truncates `system_logs`, an admin acts and removes
   the only trace. Asserted structurally here — the audit router exposes no
   mutating route at all, and nothing outside `services/audit.py` writes or
   deletes `AuditLog`.

## Why real tokens rather than `dependency_overrides`

Overriding `get_current_user` would replace the very code that stashes the
principal, so every assertion below would hold even if that stash were
deleted — the test would be blind to the defect it exists to catch. These
tests mint a real access token for a real user row and let the whole
dependency chain run.

Mutation-proved: delete `request.state.audit_actor_id = user.id` from
`api/deps.py` and the end-to-end tests fail (no row written); remove an
entry from `UNAUDITED_ENDPOINTS` and the enumeration test fails.

## Dev-DB hygiene

The suite runs against the dev database. This file creates two users, one
target and whatever audit rows its own requests produce, and deletes all of
them by id in `finally`. Nothing is deleted table-wide — in particular
`DELETE /api/logs/` is deliberately NOT called, because on this database
that would wipe the real system log; claim 3 is asserted by structure
instead of by firing the endpoint.

Run with:  pytest app/tests/test_audit_log.py
"""

import importlib
import inspect
import pkgutil
import uuid

import app.api as api_pkg
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app.api import audit as audit_api
from app.api.deps import get_current_user
from app.core.auth import create_access_token
from app.core.database import SessionLocal
from app.main import app
from app.models.audit import AuditLog
from app.models.target import Target, TargetType
from app.models.user import User, UserRole
from app.services import audit
from app.tests import _docaddr

MUTATING = {"POST", "PUT", "PATCH", "DELETE"}


# ── helpers ──────────────────────────────────────────────────────────────────

def _api_routes():
    """Every route defined in `app/api/`, keyed the way the opt-out list is.

    Enumerated from the router modules rather than from `app.routes`: the
    mounted tree nests routers behind private FastAPI internals, and this
    way a new router module that nobody has registered in `main.py` yet is
    still checked.
    """
    for mod_info in pkgutil.iter_modules(api_pkg.__path__):
        module = importlib.import_module(f"app.api.{mod_info.name}")
        router = getattr(module, "router", None)
        if router is None:
            continue
        for route in router.routes:
            if isinstance(route, APIRoute):
                yield mod_info.name, route


def _is_authenticated(dependant, _seen=None) -> bool:
    """True if `get_current_user` is anywhere in the route's dependency tree
    — directly, or under `require_role`, which depends on it."""
    _seen = _seen if _seen is not None else set()
    if id(dependant) in _seen:
        return False
    _seen.add(id(dependant))
    if dependant.call is get_current_user:
        return True
    return any(_is_authenticated(d, _seen) for d in dependant.dependencies)


class _Fixture:
    """Two real users and one real target, torn down by id."""

    def __init__(self):
        marker = uuid.uuid4().hex[:8]
        self.admin = User(
            id=uuid.uuid4(), email=f"audit-admin-{marker}@example.invalid",
            full_name="Audit test admin", role=UserRole.ADMIN.value, is_active=True,
        )
        self.viewer = User(
            id=uuid.uuid4(), email=f"audit-viewer-{marker}@example.invalid",
            full_name="Audit test viewer", role=UserRole.VIEWER.value, is_active=True,
        )
        # Drawn from `_docaddr`'s pool (planning#199) — collision-free by
        # construction, not merely low-probability.
        self.target = Target(
            id=uuid.uuid4(), type=TargetType.IP, value=_docaddr.alloc(),
            verified=False, token=uuid.uuid4().hex, aggressiveness="polite",
        )
        # Scalars captured BEFORE the commit expires the instances. The
        # session is closed immediately after, and a detached ORM object
        # raises on attribute access — the same trap that the middleware
        # itself fell into (see `api/deps.py`'s note on stashing the id).
        self.admin_id, self.admin_email, self.admin_role = (
            self.admin.id, self.admin.email, self.admin.role
        )
        self.viewer_id, self.viewer_role = self.viewer.id, self.viewer.role
        self.target_id, self.target_value = self.target.id, self.target.value

        db = SessionLocal()
        try:
            db.add_all([self.admin, self.viewer, self.target])
            db.commit()
        finally:
            db.close()

    def headers(self, which: str) -> dict:
        actor_id, role = (
            (self.admin_id, self.admin_role) if which == "admin"
            else (self.viewer_id, self.viewer_role)
        )
        return {"Authorization": f"Bearer {create_access_token(str(actor_id), role)}"}

    def rows(self) -> list[AuditLog]:
        db = SessionLocal()
        try:
            return (
                db.query(AuditLog)
                .filter(AuditLog.user_id.in_([self.admin_id, self.viewer_id]))
                .order_by(AuditLog.occurred_at)
                .all()
            )
        finally:
            db.close()

    def teardown(self) -> None:
        db = SessionLocal()
        try:
            db.query(AuditLog).filter(
                AuditLog.user_id.in_([self.admin_id, self.viewer_id])
            ).delete(synchronize_session=False)
            db.query(Target).filter(Target.id == self.target_id).delete(synchronize_session=False)
            db.query(User).filter(
                User.id.in_([self.admin_id, self.viewer_id])
            ).delete(synchronize_session=False)
            db.commit()
        finally:
            db.close()


# ── 1. coverage ──────────────────────────────────────────────────────────────

def test_every_mutating_endpoint_is_authenticated_or_explicitly_opted_out():
    """The gap that matters. An audited endpoint is an authenticated one, so
    the thing to guard is a mutating endpoint added with no principal."""
    unguarded = [
        f"{module}:{route.name}"
        for module, route in _api_routes()
        if (route.methods & MUTATING) and not _is_authenticated(route.dependant)
    ]
    missing = sorted(set(unguarded) - set(audit.UNAUDITED_ENDPOINTS))
    assert not missing, (
        f"{len(missing)} mutating endpoint(s) change state with no authenticated "
        f"principal, so nothing can attribute the action to anyone: {missing}. "
        "Either guard the endpoint (get_current_user / require_role), which "
        "audits it by construction, or add it to "
        "services/audit.UNAUDITED_ENDPOINTS with a justification."
    )


def test_opt_out_entries_still_name_real_endpoints():
    """Keeps the opt-out list from rotting into a list of ghosts that quietly
    excuse nothing while a renamed endpoint goes unaudited."""
    real = {f"{module}:{route.name}" for module, route in _api_routes()}
    stale = sorted(set(audit.UNAUDITED_ENDPOINTS) - real)
    assert not stale, f"opt-out entries name endpoints that no longer exist: {stale}"
    for key, reason in audit.UNAUDITED_ENDPOINTS.items():
        assert len(reason.strip()) > 20, f"{key} is opted out without a real justification"


# ── 2. secrets ───────────────────────────────────────────────────────────────

def test_scrub_redacts_secret_shaped_keys_at_any_depth():
    dirty = {
        "api_key": "sk-live-abcdef",
        "config": {
            "host": "example.invalid",
            "client_secret": "hunter2",
            "nested": [{"password": "hunter2"}, {"harmless": "keep me"}],
        },
        "targets": ["198.51.100.4"],
        "AUTHORIZATION": "Bearer abc",
    }
    clean = audit.scrub(dirty)
    flat = repr(clean)
    for leaked in ("sk-live-abcdef", "hunter2", "Bearer abc"):
        assert leaked not in flat, f"{leaked!r} survived scrubbing: {clean}"
    assert clean["api_key"] == audit.REDACTED
    assert clean["config"]["client_secret"] == audit.REDACTED
    assert clean["config"]["nested"][0]["password"] == audit.REDACTED
    # ...and the audit trail is still worth reading afterwards.
    assert clean["config"]["host"] == "example.invalid"
    assert clean["config"]["nested"][1]["harmless"] == "keep me"
    assert clean["targets"] == ["198.51.100.4"]


def test_scrub_caps_unbounded_values():
    clean = audit.scrub({"note": "x" * 50_000})
    assert len(clean["note"]) < 3_000, "an unbounded string reached the audit row"


# ── 3. the trail cannot be erased through the API ────────────────────────────

def test_audit_router_exposes_no_mutating_route():
    """planning#162: an admin who can truncate the trail has no trail. There
    is no write or delete path — reads only."""
    methods = {m for r in audit_api.router.routes for m in getattr(r, "methods", set())}
    assert not (methods & MUTATING), (
        f"the audit API exposes mutating routes {sorted(methods & MUTATING)} — "
        "audit_logs is append-only and must have no API delete path"
    )


def test_clearing_the_system_log_cannot_touch_the_audit_trail():
    """`DELETE /api/logs/` is scoped to `system_logs`, and the hourly
    retention sweep is too. Asserted at the source rather than by calling
    the endpoint: on this database that call would wipe the real system log
    (see this file's docstring)."""
    from app.api import logs as logs_api
    import app.main as main_module

    clear_src = inspect.getsource(logs_api.clear_logs)
    assert "SystemLog" in clear_src and "AuditLog" not in clear_src, (
        "DELETE /api/logs/ reaches beyond system_logs"
    )
    assert "AuditLog" not in inspect.getsource(main_module._purge_old_logs), (
        "the log retention sweep deletes audit rows — audit_logs is append-only"
    )


def test_only_the_audit_service_writes_the_audit_table():
    """One writer, one choke point. A second writer somewhere in a handler
    is how coverage turns back into an opt-in list."""
    import pathlib

    backend = pathlib.Path(__file__).resolve().parents[2]
    expected = {
        "app/models/audit.py",        # the definition
        "app/models/__init__.py",     # the export
        "app/services/audit.py",      # the one writer
        "app/api/audit.py",           # the read surface
    }
    referencing = {
        path.relative_to(backend).as_posix()
        for path in (backend / "app").rglob("*.py")
        if "tests" not in path.parts and "AuditLog" in path.read_text(encoding="utf-8")
    }
    assert referencing == expected, (
        "AuditLog is referenced somewhere new: "
        f"unexpected={sorted(referencing - expected)} missing={sorted(expected - referencing)}. "
        "There is one writer (services/audit.py) on purpose — a second one in a "
        "handler is how coverage turns back into an opt-in list."
    )


# ── 4. end to end, through the real dependency chain ─────────────────────────

def test_a_successful_mutation_is_recorded_with_actor_action_and_resource():
    fx = _Fixture()
    try:
        client = TestClient(app)
        r = client.patch(
            f"/api/targets/{fx.target_id}",
            json={"aggressiveness": "aggressive"},
            headers=fx.headers("admin"),
        )
        assert r.status_code == 200, r.text

        rows = fx.rows()
        assert len(rows) == 1, f"expected exactly one audit row, got {len(rows)}"
        row = rows[0]
        assert row.user_id == fx.admin_id
        assert row.action == "patch_target"
        assert row.resource_type == "targets"
        assert row.resource_id == str(fx.target_id)
        assert row.ip_address, "no source IP recorded"
        assert row.detail["method"] == "PATCH"
        assert row.detail["status_code"] == 200
        # before/after — the part a generic middleware cannot know, supplied
        # by the handler through record_detail().
        assert row.detail["changes"]["aggressiveness"] == {"from": "polite", "to": "aggressive"}
    finally:
        fx.teardown()


def test_engagement_patch_sets_clears_and_is_audited():
    """planning#211 (re-key of planning#193's posture-boolean coverage). Same
    route, same audit machinery already proved above for `aggressiveness` —
    a target's engagement membership governs whether this system probes a
    counterparty it may hold no authorisation to probe AT ALL, which is a
    strictly higher-stakes toggle, so "who changed it, and when" is exactly
    the question this trail exists to answer.

    Covers attach (no engagement -> pre_close, NOT a widening, so ADMIN or
    INTEGRATION_ADMIN would do — this fixture uses admin like the rest of
    the file) then detach (pre_close -> none, WHICH IS a widening and so
    requires `authorisation_reference`) in one fixture, since the two
    produce distinguishable `{from, to}` shapes and the two-row assertion
    below is itself part of what's being pinned.
    """
    from app.models.engagement import Engagement

    fx = _Fixture()
    engagement = Engagement(id=uuid.uuid4(), name=f"audit-test-engagement-{uuid.uuid4().hex[:8]}", posture="pre_close")
    db = SessionLocal()
    try:
        db.add(engagement)
        db.commit()
        engagement_id = engagement.id
    finally:
        db.close()

    try:
        client = TestClient(app)

        r = client.patch(
            f"/api/targets/{fx.target_id}",
            json={"engagement_id": str(engagement_id)},
            headers=fx.headers("admin"),
        )
        assert r.status_code == 200, r.text
        assert r.json()["engagement"]["id"] == str(engagement_id)

        r = client.patch(
            f"/api/targets/{fx.target_id}",
            json={"clear_engagement": True, "authorisation_reference": "audit-test widening reference"},
            headers=fx.headers("admin"),
        )
        assert r.status_code == 200, r.text
        assert r.json()["engagement"] is None

        rows = fx.rows()
        assert len(rows) == 2, f"expected two audit rows (attach, then detach), got {len(rows)}"
        assert rows[0].detail["changes"]["engagement"] == {"from": None, "to": str(engagement_id)}
        assert rows[1].detail["changes"]["engagement"] == {
            "from": str(engagement_id), "to": None,
            "reference": "audit-test widening reference",
        }
    finally:
        fx.teardown()
        db = SessionLocal()
        try:
            db.query(Engagement).filter(Engagement.id == engagement_id).delete(synchronize_session=False)
            db.commit()
        finally:
            db.close()


def test_no_request_body_is_recorded_by_default():
    """The audit row is built from the route, not from what the caller sent.
    A body echoed into `detail` is how an audit table becomes a store of
    whatever anyone POSTed."""
    fx = _Fixture()
    try:
        client = TestClient(app)
        client.patch(
            f"/api/targets/{fx.target_id}",
            json={"notes": "a-very-distinctive-note-body"},
            headers=fx.headers("admin"),
        )
        rows = fx.rows()
        assert len(rows) == 1
        assert "a-very-distinctive-note-body" not in repr(rows[0].detail), (
            f"the request body reached the audit row: {rows[0].detail}"
        )
        # The fact of the change is recorded; its free-text content is not.
        assert rows[0].detail["changes"]["notes"] == {"changed": True}
    finally:
        fx.teardown()


def test_a_rejected_attempt_is_recorded_too():
    """A VIEWER's 403 is exactly what an audit trail is read for. The status
    code in `detail` is what separates it from a success."""
    fx = _Fixture()
    try:
        client = TestClient(app)
        r = client.patch(
            f"/api/targets/{fx.target_id}",
            json={"aggressiveness": "aggressive"},
            headers=fx.headers("viewer"),
        )
        assert r.status_code == 403, r.text

        rows = fx.rows()
        assert len(rows) == 1, f"a denied attempt left no trace: {rows}"
        assert rows[0].user_id == fx.viewer_id
        assert rows[0].detail["status_code"] == 403
    finally:
        fx.teardown()


def test_an_anonymous_request_records_nothing():
    """No principal, nothing happened, nobody did it — and an unauthenticated
    caller must not be able to append rows to the audit table."""
    fx = _Fixture()
    try:
        before = len(fx.rows())
        client = TestClient(app)
        r = client.patch(
            f"/api/targets/{fx.target_id}", json={"aggressiveness": "aggressive"}
        )
        assert r.status_code in (401, 403), r.text
        assert len(fx.rows()) == before
    finally:
        fx.teardown()


def test_a_read_is_not_recorded():
    """Only state-mutating requests. Auditing GETs would bury the actions
    that matter under page views."""
    fx = _Fixture()
    try:
        client = TestClient(app)
        r = client.get(f"/api/targets/{fx.target_id}", headers=fx.headers("admin"))
        assert r.status_code == 200, r.text
        assert fx.rows() == []
    finally:
        fx.teardown()


# ── 5. the read surface ──────────────────────────────────────────────────────

def test_the_read_endpoint_returns_the_row_and_names_the_actor():
    fx = _Fixture()
    try:
        client = TestClient(app)
        client.patch(
            f"/api/targets/{fx.target_id}",
            json={"aggressiveness": "aggressive"},
            headers=fx.headers("admin"),
        )
        r = client.get(
            f"/api/audit/?user_id={fx.admin_id}", headers=fx.headers("admin")
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert len(body) == 1, body
        assert body[0]["action"] == "patch_target"
        assert body[0]["user_email"] == fx.admin_email
        assert body[0]["resource_id"] == str(fx.target_id)
    finally:
        fx.teardown()


def test_the_read_endpoint_is_admin_only():
    """Reading the record of what the admins did is a supervisory act, so it
    is narrower than the (ADMIN, INTEGRATION_ADMIN) pair used to administer."""
    fx = _Fixture()
    try:
        client = TestClient(app)
        r = client.get("/api/audit/", headers=fx.headers("viewer"))
        assert r.status_code == 403, r.text
    finally:
        fx.teardown()


def test_reading_the_audit_log_is_not_itself_audited():
    """Sanity check on the mutating-only rule: a supervisor reading the trail
    must not append to it, or the table grows by being looked at."""
    fx = _Fixture()
    try:
        client = TestClient(app)
        client.get("/api/audit/", headers=fx.headers("admin"))
        client.get("/api/audit/facets", headers=fx.headers("admin"))
        assert fx.rows() == []
    finally:
        fx.teardown()


# ── 6. failure isolation ─────────────────────────────────────────────────────

def test_an_audit_write_failure_does_not_break_the_request():
    """An audit trail that can take the API down gets switched off within a
    week. The failure is logged at ERROR and swallowed."""
    fx = _Fixture()
    original = audit.write
    try:
        def _explode(**kwargs):
            raise RuntimeError("simulated audit DB failure")

        audit.write = _explode
        client = TestClient(app)
        r = client.patch(
            f"/api/targets/{fx.target_id}",
            json={"aggressiveness": "aggressive"},
            headers=fx.headers("admin"),
        )
        assert r.status_code == 200, (
            f"a failed audit write broke the request it was recording: {r.text}"
        )
    finally:
        audit.write = original
        fx.teardown()
