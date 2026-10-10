"""planning#224 item 3 — the admin LLM config API (`app/api/llm.py`).

`GET/PUT /api/llm/role-bindings` (ADMIN only; PUT validates every role and
audits old -> new), and `GET /api/llm/models` + `POST /api/llm/models/refresh`
(the cached guardrail allow-list). The refresh test drives the module
`_transport` seam so no network call happens (TestClient runs the handler
in-process).

Run with:  backend/scripts/test.ps1 app/tests/test_llm_api.py
"""

import json
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient

from app.core.auth import create_access_token
from app.core.database import SessionLocal
from app.main import app
from app.models.app_settings import AppSetting
from app.models.audit import AuditLog
from app.models.user import User
from app.services import app_settings, connector_config as connector_config_svc
from app.services import llm_connector as llmc

client = TestClient(app)

_NO_ROW = object()
_CACHE_KEY = "llm.allowed_models_cache"
_BIND_KEY = "llm.role_bindings"
_TEST_API_KEY = "sk-or-test-224-api"


def _make_user(role: str):
    db = SessionLocal()
    try:
        user = User(
            id=uuid.uuid4(), email=f"llm224api-{uuid.uuid4().hex[:8]}@example.invalid",
            full_name="llm224 api test user", role=role, is_active=True,
        )
        db.add(user)
        db.commit()
        uid = user.id
    finally:
        db.close()
    return {"Authorization": f"Bearer {create_access_token(str(uid), role)}"}, uid


def _cleanup_user(uid):
    if uid is None:
        return
    db = SessionLocal()
    try:
        db.query(AuditLog).filter(AuditLog.user_id == uid).delete(synchronize_session=False)
        db.query(User).filter(User.id == uid).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _snapshot_setting(db, key):
    row = db.get(AppSetting, key)
    return row.value if row else _NO_ROW


def _restore_setting(db, key, snapshot):
    if snapshot is _NO_ROW:
        row = db.get(AppSetting, key)
        if row is not None:
            db.delete(row)
            db.commit()
    else:
        app_settings.set_value(db, key, snapshot)


def _configure_openrouter(db, *, api_key=_TEST_API_KEY, enabled=True):
    existing = connector_config_svc.get_one(db, "openrouter")
    snapshot = _NO_ROW if existing is None else {
        "enabled": existing.enabled, "config_encrypted": existing.config_encrypted,
    }
    connector_config_svc.upsert_config(db, "openrouter", {"api_key": api_key} if api_key else {})
    connector_config_svc.set_enabled(db, "openrouter", enabled)
    return snapshot


def _restore_openrouter(snapshot):
    from app.models.connector_config import ConnectorConfig
    db = SessionLocal()
    try:
        if snapshot is _NO_ROW:
            db.query(ConnectorConfig).filter(ConnectorConfig.connector_id == "openrouter").delete()
            db.commit()
        else:
            row = connector_config_svc.get_one(db, "openrouter")
            if row is not None:
                row.enabled = snapshot["enabled"]
                row.config_encrypted = snapshot["config_encrypted"]
                db.commit()
    finally:
        db.close()


def _valid_bindings():
    return {
        "classify": {"models": ["vendor/a", "vendor/b"], "max_tokens": 1024, "temperature": 0},
        "extract":  {"models": ["vendor/b", "vendor/c"], "max_tokens": 4096, "temperature": 0},
        "research": {"models": ["vendor/c"], "max_tokens": 8192, "temperature": 0.2},
        "judge":    {"models": ["vendor/a"], "max_tokens": 4096, "temperature": 0},
        "narrate":  {"models": ["vendor/b"], "max_tokens": 2048, "temperature": 0.4},
    }


# ── role-bindings ────────────────────────────────────────────────────────

def test_get_role_bindings_admin_ok_viewer_403():
    admin_h, admin_id = _make_user("admin")
    viewer_h, viewer_id = _make_user("viewer")
    try:
        r = client.get("/api/llm/role-bindings", headers=admin_h)
        assert r.status_code == 200
        assert set(r.json()["bindings"]) == {"classify", "extract", "research", "judge", "narrate"}

        assert client.get("/api/llm/role-bindings", headers=viewer_h).status_code == 403
    finally:
        _cleanup_user(admin_id)
        _cleanup_user(viewer_id)


def test_put_role_bindings_persists_and_audits():
    admin_h, admin_id = _make_user("admin")
    db = SessionLocal()
    snap_bind = _snapshot_setting(db, _BIND_KEY)
    try:
        r = client.put("/api/llm/role-bindings", headers=admin_h, json={"bindings": _valid_bindings()})
        assert r.status_code == 200, r.text
        assert r.json()["bindings"]["classify"]["models"] == ["vendor/a", "vendor/b"]

        # persisted so the call path loads it
        bindings = llmc.load_bindings(db)
        assert bindings[llmc.Role.CLASSIFY].models == ["vendor/a", "vendor/b"]

        # audited with the from/to ladders
        row = (
            db.query(AuditLog)
            .filter(AuditLog.user_id == admin_id)
            .order_by(AuditLog.occurred_at.desc())
            .first()
        )
        changes = (row.detail or {}).get("changes", {})
        assert "role_bindings" in changes
        assert changes["role_bindings"]["to"]["classify"]["models"] == ["vendor/a", "vendor/b"]
    finally:
        _restore_setting(db, _BIND_KEY, snap_bind)
        db.close()
        _cleanup_user(admin_id)


def test_put_missing_role_is_422():
    admin_h, admin_id = _make_user("admin")
    db = SessionLocal()
    snap_bind = _snapshot_setting(db, _BIND_KEY)
    try:
        bad = _valid_bindings()
        del bad["judge"]
        r = client.put("/api/llm/role-bindings", headers=admin_h, json={"bindings": bad})
        assert r.status_code == 422
        assert "judge" in r.text
        # unchanged
        assert _snapshot_setting(db, _BIND_KEY) == snap_bind
    finally:
        _restore_setting(db, _BIND_KEY, snap_bind)
        db.close()
        _cleanup_user(admin_id)


def test_put_invalid_binding_is_422():
    admin_h, admin_id = _make_user("admin")
    db = SessionLocal()
    snap_bind = _snapshot_setting(db, _BIND_KEY)
    try:
        bad = _valid_bindings()
        bad["classify"]["temperature"] = 5  # out of [0, 2]
        assert client.put("/api/llm/role-bindings", headers=admin_h, json={"bindings": bad}).status_code == 422

        bad2 = _valid_bindings()
        bad2["classify"]["models"] = []  # empty ladder
        assert client.put("/api/llm/role-bindings", headers=admin_h, json={"bindings": bad2}).status_code == 422
    finally:
        _restore_setting(db, _BIND_KEY, snap_bind)
        db.close()
        _cleanup_user(admin_id)


# ── models cache ─────────────────────────────────────────────────────────

def test_get_models_cold_cache_returns_null_fetched_at():
    admin_h, admin_id = _make_user("admin")
    db = SessionLocal()
    snap_cache = _snapshot_setting(db, _CACHE_KEY)
    try:
        _restore_setting(db, _CACHE_KEY, _NO_ROW)
        r = client.get("/api/llm/models", headers=admin_h)
        assert r.status_code == 200
        assert r.json() == {"fetched_at": None, "models": []}
    finally:
        _restore_setting(db, _CACHE_KEY, snap_cache)
        db.close()
        _cleanup_user(admin_id)


def test_refresh_models_populates_cache():
    admin_h, admin_id = _make_user("admin")
    db = SessionLocal()
    snap_cache = _snapshot_setting(db, _CACHE_KEY)
    snap_or = _configure_openrouter(db)
    try:
        def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"data": [
                {"id": "vendor/a", "context_length": 1000, "supported_parameters": ["response_format"], "pricing": {}},
                {"id": "vendor/b", "context_length": 2000, "supported_parameters": [], "pricing": {}},
            ]})

        llmc._transport = httpx.MockTransport(_handler)
        try:
            r = client.post("/api/llm/models/refresh", headers=admin_h)
        finally:
            llmc._transport = None

        assert r.status_code == 200, r.text
        body = r.json()
        assert body["fetched_at"] is not None
        assert {m["id"] for m in body["models"]} == {"vendor/a", "vendor/b"}
        # readable back through the GET
        g = client.get("/api/llm/models", headers=admin_h)
        assert {m["id"] for m in g.json()["models"]} == {"vendor/a", "vendor/b"}
    finally:
        _restore_setting(db, _CACHE_KEY, snap_cache)
        _restore_openrouter(snap_or)
        db.close()
        _cleanup_user(admin_id)


def test_refresh_models_not_configured_is_409():
    admin_h, admin_id = _make_user("admin")
    db = SessionLocal()
    snap_or = _configure_openrouter(db, api_key=None, enabled=False)
    try:
        r = client.post("/api/llm/models/refresh", headers=admin_h)
        assert r.status_code == 409
    finally:
        _restore_openrouter(snap_or)
        db.close()
        _cleanup_user(admin_id)
