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
from app.services import app_settings, connector_instances as connector_instances_svc
from app.tests import connector_helpers as ch
from app.services import llm_connector as llmc
from app.tests.llm_fixtures import TEST_ROLE_BINDINGS

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


def _zdr_row(model_id, *, provider="FixtureCloud", params=("max_tokens", "temperature")):
    # The real `/api/v1/endpoints/zdr` row shape (recorded 2026-10-09),
    # trimmed to the fields that vary; one row per provider endpoint.
    return {
        "name": f"{provider} | {model_id}", "model_id": model_id, "model_name": model_id,
        "context_length": 128000,
        "pricing": {"prompt": "0.00000003", "completion": "0.00000015", "discount": 0},
        "provider_name": provider, "tag": provider.lower(), "quantization": "fp8",
        "max_completion_tokens": 32768, "max_prompt_tokens": None,
        "supported_parameters": list(params), "status": 0, "uptime_last_1d": 100,
    }


def _zdr_response(rows, *, status=200) -> httpx.Response:
    if status != 200:
        return httpx.Response(status, json={"error": {"message": "nope"}})
    return httpx.Response(200, json={"data": rows})


def _key_response(*, status=200, data=None) -> httpx.Response:
    if status != 200:
        return httpx.Response(status, json={"error": {"message": "nope"}})
    # The real `/api/v1/key` shape: `data` with label/limit/limit_remaining/
    # usage/is_free_tier (label is a masked key fragment we never pass on).
    return httpx.Response(200, json={"data": data if data is not None else {
        "label": "sk-or-v1-abc...xyz", "limit": 2, "limit_remaining": 1.25, "usage": 0.75,
        "is_free_tier": False, "limit_reset": "weekly",
    }})


def _configure_openrouter(db, *, api_key=_TEST_API_KEY, enabled=True):
    existing = connector_instances_svc.single(db, "openrouter")
    snapshot = _NO_ROW if existing is None else {
        "enabled": existing.enabled, "config_encrypted": existing.config_encrypted,
    }
    ch.set_config(db, "openrouter", {"api_key": api_key} if api_key else {})
    ch.set_enabled(db, "openrouter", enabled)
    return snapshot


def _restore_openrouter(snapshot):
    from app.models.connector_instance import ConnectorInstance
    db = SessionLocal()
    try:
        if snapshot is _NO_ROW:
            db.query(ConnectorInstance).filter(ConnectorInstance.type == "openrouter").delete()
            db.commit()
        else:
            row = connector_instances_svc.single(db, "openrouter")
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
    custom = copy.deepcopy(TEST_ROLE_BINDINGS)
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
        scripted = _ScriptedTransport([
            _models_user_response(["vendor/a", "vendor/b"]),
            _zdr_response([
                _zdr_row("vendor/a", provider="P1", params=("max_tokens", "response_format")),
                _zdr_row("vendor/a", provider="P2"),
                _zdr_row("vendor/not-allowed", provider="P1", params=("response_format",)),
            ]),
        ])
        llmc._transport = scripted.transport
        try:
            result = llmc.refresh_allowed_models(db)
        finally:
            llmc._transport = None

        # fetched /models/user with the key, as a GET, then the public ZDR
        # catalogue WITHOUT the key
        assert len(scripted.requests) == 2
        zdr_req = scripted.requests[1]
        assert str(zdr_req.url) == llmc._ZDR_ENDPOINTS_URL
        assert "Authorization" not in zdr_req.headers
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
        # ZDR endpoint counts per allowed model: (total, accepting response_format);
        # an allowed model with no ZDR endpoint reads 0, not unknown
        by_id = {e["id"]: e for e in reread.entries}
        assert (by_id["vendor/a"]["zdr_endpoints"], by_id["vendor/a"]["zdr_structured_endpoints"]) == (2, 1)
        assert (by_id["vendor/b"]["zdr_endpoints"], by_id["vendor/b"]["zdr_structured_endpoints"]) == (0, 0)
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

        scripted = _ScriptedTransport([_models_user_response([]), _zdr_response([])])
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


def test_zdr_catalogue_failure_still_caches_the_allow_list_with_unknown_counts():
    """The ZDR counts are display-only: a failed catalogue read must not
    fail the refresh (the call path needs the allow-list), and reads as
    unknown (None), never as 0 ZDR endpoints."""
    db = SessionLocal()
    snap_or = _configure_openrouter(db)
    snap_cache = _snapshot_setting(db, _CACHE_KEY)
    try:
        for zdr in (_zdr_response([], status=503), httpx.Response(200, json={"rows": []})):
            scripted = _ScriptedTransport([_models_user_response(["vendor/a"]), zdr])
            llmc._transport = scripted.transport
            try:
                llmc.refresh_allowed_models(db)
            finally:
                llmc._transport = None
            assert len(scripted.requests) == 2  # the catalogue fetch was reached
            entry = llmc.load_allowed_models(db).entries[0]
            assert entry["id"] == "vendor/a"
            assert entry["zdr_endpoints"] is None and entry["zdr_structured_endpoints"] is None
    finally:
        _restore_setting(db, _CACHE_KEY, snap_cache)
        _restore_openrouter(snap_or)
        db.close()


def test_rejected_allow_list_does_not_fetch_the_zdr_catalogue():
    db = SessionLocal()
    snap_or = _configure_openrouter(db)
    snap_cache = _snapshot_setting(db, _CACHE_KEY)
    try:
        scripted = _ScriptedTransport([httpx.Response(200, json={"models": []})])
        llmc._transport = scripted.transport
        try:
            with pytest.raises(llmc.LLMUpstreamError):
                llmc.refresh_allowed_models(db)
        finally:
            llmc._transport = None
        assert [str(r.url) for r in scripted.requests] == [llmc._MODELS_USER_URL]
    finally:
        _restore_setting(db, _CACHE_KEY, snap_cache)
        _restore_openrouter(snap_or)
        db.close()


# ── item 7: key status ───────────────────────────────────────────────────

def test_key_status_reads_numbers_and_drops_the_label():
    db = SessionLocal()
    snap_or = _configure_openrouter(db)
    try:
        scripted = _ScriptedTransport([_key_response()])
        llmc._transport = scripted.transport
        try:
            status = llmc.key_status(db)
        finally:
            llmc._transport = None
        assert len(scripted.requests) == 1
        assert str(scripted.requests[0].url) == llmc._KEY_URL
        assert scripted.requests[0].headers["Authorization"] == f"Bearer {_TEST_API_KEY}"
        assert status == {"limit": 2.0, "limit_remaining": 1.25, "usage": 0.75, "is_free_tier": False}

        # no limit on the key = null limit / remaining, not 0
        scripted = _ScriptedTransport([_key_response(data={"limit": None, "limit_remaining": None, "usage": 3})])
        llmc._transport = scripted.transport
        try:
            status = llmc.key_status(db)
        finally:
            llmc._transport = None
        assert (status["limit"], status["limit_remaining"], status["usage"]) == (None, None, 3.0)
    finally:
        _restore_openrouter(snap_or)
        db.close()


def test_key_status_errors_are_typed():
    db = SessionLocal()
    snap_or = _configure_openrouter(db)
    try:
        for resp, exc_type in (
            (_key_response(status=401), llmc.LLMNotConfigured),
            (_key_response(status=500), llmc.LLMUpstreamError),
            (httpx.Response(200, json={"limit": 2}), llmc.LLMUpstreamError),
            (httpx.Response(200, json=[1, 2]), llmc.LLMUpstreamError),
        ):
            scripted = _ScriptedTransport([resp])
            llmc._transport = scripted.transport
            try:
                with pytest.raises(exc_type):
                    llmc.key_status(db)
            finally:
                llmc._transport = None
            assert len(scripted.requests) == 1
    finally:
        _restore_openrouter(snap_or)
        db.close()

    db = SessionLocal()
    snap_or = _configure_openrouter(db, enabled=False)
    try:
        scripted = _ScriptedTransport([])
        llmc._transport = scripted.transport
        try:
            with pytest.raises(llmc.LLMNotConfigured):
                llmc.key_status(db)
        finally:
            llmc._transport = None
        assert scripted.requests == []
    finally:
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
