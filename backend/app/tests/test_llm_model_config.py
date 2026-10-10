"""planning#224 items 1 + 4 — the guardrail allow-list cache and
skip-before-send, at the `llm_connector` level.

Item 1: `refresh_allowed_models` fetches `/models/user` (through the
injectable `_transport` seam — no network), caches it in `app_settings`
with a timestamp, and `load_allowed_models`/`allowed_model_ids` read it
back; a cold or corrupt cache reads as "unknown", never an empty set.

Item 4: the call path SKIPS a bound model that is not on the allow-list —
no request sent (asserted on the transport, R7), one `guardrail_blocked`
ledger row per skip — and raises `GuardrailBlocked` (distinct from the
data-policy `NoCompliantEndpoint`) with zero requests when every bound
model is blocked. A cold cache skips nothing (fail-open).

Run with:  backend/scripts/test.ps1 app/tests/test_llm_model_config.py
"""

import copy
import json
import uuid
from datetime import datetime, timezone

import httpx
import pytest

from app.core.config import settings
from app.core.database import SessionLocal
from app.models.app_settings import AppSetting
from app.models.llm_call import LlmCall
from app.services import app_settings, connector_config as connector_config_svc
from app.services import llm_connector as llmc

_TEST_API_KEY = "sk-or-test-224"
_NO_ROW = object()
_CACHE_KEY = "llm.allowed_models_cache"


# ── helpers ───────────────────────────────────────────────────────────────

class _ScriptedTransport:
    """Serves scripted `httpx.Response`s in order, recording every request
    so a test can assert on what was actually SENT (R7)."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.requests: list[httpx.Request] = []

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if not self._responses:
            raise AssertionError(f"ran out of scripted responses after {len(self.requests)} request(s)")
        return self._responses.pop(0)

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)


def _ok_response(*, content="ok", model="fixture/model-b") -> httpx.Response:
    return httpx.Response(200, json={
        "id": "gen-224", "model": model, "provider": "Fixture",
        "choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    })


def _models_user_response(ids, *, status=200) -> httpx.Response:
    if status != 200:
        return httpx.Response(status, json={"error": {"message": "nope"}})
    return httpx.Response(200, json={"data": [
        {"id": i, "context_length": 128000, "supported_parameters": ["response_format"],
         "pricing": {"prompt": "0", "completion": "0"}}
        for i in ids
    ]})


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


def _set_cache(db, ids, *, fetched_at=None):
    app_settings.set_value(db, _CACHE_KEY, json.dumps({
        "fetched_at": (fetched_at or datetime.now(timezone.utc)).isoformat(),
        "models": [{"id": i, "context_length": 1000, "supported_parameters": [], "pricing": {}} for i in ids],
    }))


def _set_classify_binding(db, models):
    custom = copy.deepcopy(app_settings._LLM_ROLE_BINDINGS_DEFAULT)
    custom["classify"] = {"models": models, "max_tokens": 512, "temperature": 0}
    app_settings.set_value(db, "llm.role_bindings", json.dumps(custom))


def _cleanup(task):
    db = SessionLocal()
    try:
        db.query(LlmCall).filter(LlmCall.task == task).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


# ── item 1: cache fetch / read-back ──────────────────────────────────────

def test_refresh_fetches_models_user_and_caches_with_timestamp():
    db = SessionLocal()
    snap_or = _configure_openrouter(db)
    snap_cache = _snapshot_setting(db, _CACHE_KEY)
    try:
        scripted = _ScriptedTransport([_models_user_response(["vendor/a", "vendor/b"])])
        llmc._transport = scripted.transport
        try:
            result = llmc.refresh_allowed_models(db)
        finally:
            llmc._transport = None

        # fetched /models/user with the key, as a GET
        assert len(scripted.requests) == 1
        req = scripted.requests[0]
        assert req.method == "GET"
        assert str(req.url) == llmc._MODELS_USER_URL
        assert req.headers["Authorization"] == f"Bearer {_TEST_API_KEY}"

        assert result.ids == {"vendor/a", "vendor/b"}
        # persisted + readable back as the same thing
        reread = llmc.load_allowed_models(db)
        assert reread is not None
        assert reread.ids == {"vendor/a", "vendor/b"}
        assert llmc.allowed_model_ids(db) == {"vendor/a", "vendor/b"}
        # faithful wire fields kept for the UI slice
        assert reread.entries[0]["supported_parameters"] == ["response_format"]
    finally:
        _restore_setting(db, _CACHE_KEY, snap_cache)
        _restore_openrouter(snap_or)
        db.close()


def test_cold_and_corrupt_cache_read_as_none_not_empty():
    db = SessionLocal()
    snap_cache = _snapshot_setting(db, _CACHE_KEY)
    try:
        # cold
        _restore_setting(db, _CACHE_KEY, _NO_ROW)
        assert llmc.load_allowed_models(db) is None
        assert llmc.allowed_model_ids(db) is None
        # corrupt is None, NOT an empty allow-list (which would block everything)
        app_settings.set_value(db, _CACHE_KEY, "{not json")
        assert llmc.load_allowed_models(db) is None
        assert llmc.allowed_model_ids(db) is None
    finally:
        _restore_setting(db, _CACHE_KEY, snap_cache)
        db.close()


def test_refresh_not_configured_raises_without_request():
    db = SessionLocal()
    snap_or = _configure_openrouter(db, api_key=None, enabled=False)
    try:
        scripted = _ScriptedTransport([])  # must never be used
        llmc._transport = scripted.transport
        try:
            with pytest.raises(llmc.LLMNotConfigured):
                llmc.refresh_allowed_models(db)
        finally:
            llmc._transport = None
        assert scripted.requests == []
    finally:
        _restore_openrouter(snap_or)
        db.close()


def test_refresh_failure_preserves_last_good_cache():
    db = SessionLocal()
    snap_or = _configure_openrouter(db)
    snap_cache = _snapshot_setting(db, _CACHE_KEY)
    try:
        _set_cache(db, ["vendor/keep"])
        # 401 -> not configured; cache untouched
        scripted = _ScriptedTransport([_models_user_response([], status=401)])
        llmc._transport = scripted.transport
        try:
            with pytest.raises(llmc.LLMNotConfigured):
                llmc.refresh_allowed_models(db)
        finally:
            llmc._transport = None
        assert llmc.allowed_model_ids(db) == {"vendor/keep"}

        # 500 -> upstream error; cache still untouched
        scripted2 = _ScriptedTransport([_models_user_response([], status=500)])
        llmc._transport = scripted2.transport
        try:
            with pytest.raises(llmc.LLMUpstreamError):
                llmc.refresh_allowed_models(db)
        finally:
            llmc._transport = None
        assert llmc.allowed_model_ids(db) == {"vendor/keep"}
    finally:
        _restore_setting(db, _CACHE_KEY, snap_cache)
        _restore_openrouter(snap_or)
        db.close()


def test_refresh_rejects_shape_drift_but_caches_a_real_empty_list():
    """A body with no `data` list must NOT be cached as an empty allow-list
    (that would block every call); a genuine `data: []` IS cached."""
    db = SessionLocal()
    snap_or = _configure_openrouter(db)
    snap_cache = _snapshot_setting(db, _CACHE_KEY)
    try:
        _set_cache(db, ["vendor/keep"])
        for body in ({"models": [{"id": "vendor/x"}]}, [{"id": "vendor/x"}], {"data": None}):
            scripted = _ScriptedTransport([httpx.Response(200, json=body)])
            llmc._transport = scripted.transport
            try:
                with pytest.raises(llmc.LLMUpstreamError):
                    llmc.refresh_allowed_models(db)
            finally:
                llmc._transport = None
            assert len(scripted.requests) == 1  # the fetch was reached
            assert llmc.allowed_model_ids(db) == {"vendor/keep"}

        scripted = _ScriptedTransport([_models_user_response([])])
        llmc._transport = scripted.transport
        try:
            llmc.refresh_allowed_models(db)
        finally:
            llmc._transport = None
        assert llmc.allowed_model_ids(db) == set()
    finally:
        _restore_setting(db, _CACHE_KEY, snap_cache)
        _restore_openrouter(snap_or)
        db.close()


# ── item 4: skip-before-send + distinct error ────────────────────────────

def test_blocked_primary_is_skipped_without_a_request_fallback_serves():
    """model-a is NOT on the allow-list, model-b is: model-a must be skipped
    with NO request sent, model-b served, and a guardrail_blocked ledger row
    recorded for model-a."""
    task = f"llm224-skip-{uuid.uuid4().hex[:8]}"
    db = SessionLocal()
    snap_or = _configure_openrouter(db)
    snap_bind = _snapshot_setting(db, "llm.role_bindings")
    snap_cache = _snapshot_setting(db, _CACHE_KEY)
    prior_policy = settings.llm_data_policy
    try:
        settings.llm_data_policy = "dev_permissive"
        _set_classify_binding(db, ["fixture/model-a", "fixture/model-b"])
        _set_cache(db, ["fixture/model-b"])  # only the fallback is allowed

        scripted = _ScriptedTransport([_ok_response(model="fixture/model-b")])
        llmc._transport = scripted.transport
        try:
            result = llmc.complete(
                db, role=llmc.Role.CLASSIFY, messages=[{"role": "user", "content": "hi"}],
                target_id=None, engagement_id=None, task=task,
            )
        finally:
            llmc._transport = None

        # exactly ONE request, and it was for the allowed model
        assert len(scripted.requests) == 1
        assert json.loads(scripted.requests[0].content)["model"] == "fixture/model-b"
        assert result.model == "fixture/model-b"

        rows = db.query(LlmCall).filter(LlmCall.task == task).all()
        blocked = [r for r in rows if r.status == "guardrail_blocked"]
        assert [r.requested_model for r in blocked] == ["fixture/model-a"]
        assert any(r.status == "ok" and r.requested_model == "fixture/model-b" for r in rows)
    finally:
        settings.llm_data_policy = prior_policy
        _cleanup(task)
        _restore_setting(db, _CACHE_KEY, snap_cache)
        _restore_setting(db, "llm.role_bindings", snap_bind)
        _restore_openrouter(snap_or)
        db.close()


def test_all_models_blocked_raises_guardrail_blocked_with_zero_requests():
    task = f"llm224-allblk-{uuid.uuid4().hex[:8]}"
    db = SessionLocal()
    snap_or = _configure_openrouter(db)
    snap_bind = _snapshot_setting(db, "llm.role_bindings")
    snap_cache = _snapshot_setting(db, _CACHE_KEY)
    prior_policy = settings.llm_data_policy
    try:
        settings.llm_data_policy = "dev_permissive"
        _set_classify_binding(db, ["fixture/model-a", "fixture/model-b"])
        _set_cache(db, ["vendor/something-else"])  # neither bound model allowed

        scripted = _ScriptedTransport([])  # must never be touched
        llmc._transport = scripted.transport
        try:
            with pytest.raises(llmc.GuardrailBlocked) as exc:
                llmc.complete(
                    db, role=llmc.Role.CLASSIFY, messages=[{"role": "user", "content": "hi"}],
                    target_id=None, engagement_id=None, task=task,
                )
        finally:
            llmc._transport = None

        assert scripted.requests == []
        # distinct from the data-policy failure, and names the blocked models
        assert not isinstance(exc.value, llmc.NoCompliantEndpoint)
        assert "guardrail" in str(exc.value).lower()
        rows = db.query(LlmCall).filter(LlmCall.task == task, LlmCall.status == "guardrail_blocked").all()
        assert len(rows) == 1
    finally:
        settings.llm_data_policy = prior_policy
        _cleanup(task)
        _restore_setting(db, _CACHE_KEY, snap_cache)
        _restore_setting(db, "llm.role_bindings", snap_bind)
        _restore_openrouter(snap_or)
        db.close()


def test_cold_cache_skips_nothing_fail_open():
    """With no allow-list cached, a model that WOULD be blocked is still
    attempted — the fail-open contract. Proves the skip is driven by the
    cache, not unconditional."""
    task = f"llm224-failopen-{uuid.uuid4().hex[:8]}"
    db = SessionLocal()
    snap_or = _configure_openrouter(db)
    snap_bind = _snapshot_setting(db, "llm.role_bindings")
    snap_cache = _snapshot_setting(db, _CACHE_KEY)
    prior_policy = settings.llm_data_policy
    try:
        settings.llm_data_policy = "dev_permissive"
        _set_classify_binding(db, ["fixture/model-a", "fixture/model-b"])
        _restore_setting(db, _CACHE_KEY, _NO_ROW)  # cold

        scripted = _ScriptedTransport([_ok_response(model="fixture/model-a")])
        llmc._transport = scripted.transport
        try:
            result = llmc.complete(
                db, role=llmc.Role.CLASSIFY, messages=[{"role": "user", "content": "hi"}],
                target_id=None, engagement_id=None, task=task,
            )
        finally:
            llmc._transport = None

        assert len(scripted.requests) == 1
        assert json.loads(scripted.requests[0].content)["model"] == "fixture/model-a"
        assert result.model == "fixture/model-a"
        assert db.query(LlmCall).filter(LlmCall.task == task, LlmCall.status == "guardrail_blocked").count() == 0
    finally:
        settings.llm_data_policy = prior_policy
        _cleanup(task)
        _restore_setting(db, _CACHE_KEY, snap_cache)
        _restore_setting(db, "llm.role_bindings", snap_bind)
        _restore_openrouter(snap_or)
        db.close()
