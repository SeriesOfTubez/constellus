"""Coverage for app.services.llm_connector (planning#140 slice 1) — the
OpenRouter connector, its ledger, and its data policy.

This is the load-bearing test file for R1 (no silent fallback to a non-
compliant endpoint), R3 (pre-close posture forces strict regardless of the
deployment policy), R4 (the ledger never stores prompt/response content),
R5 (the API key comes from `connector_configs` only) and R6 (`target_id`/
`source_text` have no default). Every test spies on the TRANSPORT
(`httpx.MockTransport`, via `_ScriptedTransport` below) and asserts on the
actual REQUEST BODIES it received, never on a wrapper — R7.

Dev-DB caveat, same as every other test file in this suite that writes
real rows: no dedicated per-test transaction/rollback. Every row this file
creates is synthetic (`Target.value` under `.example.test`, `LlmCall.task`
labelled `llm140-<test>-<uuid suffix>`) and deleted by hand in a `finally`
block. Ledger rows are deleted BEFORE targets, by `task` label (unique per
test) rather than by the `ledger_ids` a call returns — a raised exception
never returns `ledger_ids` at all, and several tests deliberately expect
one. The `openrouter` `connector_configs` row is snapshotted and restored
rather than deleted, per this suite's convention for singleton rows a real
deployment might already have configured.

Run with:  backend/scripts/test.ps1 app/tests/test_llm_connector.py
       or: pytest app/tests/test_llm_connector.py
"""

import copy
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import httpx
import pytest
from pydantic import BaseModel, ValidationError
from sqlalchemy import inspect as sa_inspect

from app.connectors.openrouter import OpenRouterConnector
from app.core import secrets as secrets_mod
from app.core.config import Settings, settings
from app.core.database import SessionLocal
from app.models.app_settings import AppSetting
from app.models.connector_config import ConnectorConfig
from app.models.llm_call import LlmCall
from app.models.target import Target
from app.services import app_settings
from app.services import connector_config as connector_config_svc
from app.services import llm_connector as llmc
from app.services.llm_grounding import Grounded

_TEST_API_KEY = "sk-or-v1-test-key-not-real"

# A span/quote/value fixture shared by every test that needs a structured
# result to ground successfully, so tests that aren't ABOUT grounding
# correctness don't each have to hand-craft one.
_GROUND_SPAN = "Example Holdings reported a headline result this quarter."
_GROUND_QUOTE = "reported a headline result"

_NO_ROW = object()


class _Fact(BaseModel):
    headline: Grounded[str]


# ── fixtures / helpers ──────────────────────────────────────────────────────

class _ScriptedTransport:
    """Serves a scripted sequence of `httpx.Response`s in order and records
    every `httpx.Request` it received, so tests can assert on what was
    actually SENT (R7 — spy on the transport, not a wrapper)."""

    def __init__(self, responses: list[httpx.Response]):
        self._responses = list(responses)
        self.requests: list[httpx.Request] = []

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if not self._responses:
            raise AssertionError(
                f"_ScriptedTransport ran out of scripted responses after {len(self.requests)} request(s)"
            )
        return self._responses.pop(0)

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)


def _ok_response(
    *, content: str | None = None, model: str = "deepseek/deepseek-v4-flash",
    provider: str = "DeepSeek", gen_id: str = "gen-test-1", prompt_tokens: int = 10,
    completion_tokens: int = 5, cached_tokens: int | None = None, cost: float | None = None,
) -> httpx.Response:
    if content is None:
        content = "ok"
    usage: dict = {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens}
    if cached_tokens is not None:
        usage["prompt_tokens_details"] = {"cached_tokens": cached_tokens}
    if cost is not None:
        usage["cost"] = cost
    body = {
        "id": gen_id,
        "model": model,
        "provider": provider,
        "choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
        "usage": usage,
    }
    return httpx.Response(200, json=body)


def _error_response(status: int, *, message: str = "error", headers: dict | None = None) -> httpx.Response:
    return httpx.Response(status, json={"error": {"message": message}}, headers=headers or {})


def _make_target(db, *, suffix: str, pre_close: bool) -> Target:
    t = Target(id=uuid.uuid4(), type="domain", value=f"llm140-{suffix}.example.test", ma_pre_close=pre_close)
    db.add(t)
    db.commit()
    return t


def _configure_openrouter(db, *, api_key: str | None = _TEST_API_KEY, enabled: bool = True):
    """Snapshot the existing `openrouter` connector_configs row (or record
    that none existed) and (re)configure it for the test. Returns the
    snapshot for `_restore_openrouter`."""
    existing = connector_config_svc.get_one(db, "openrouter")
    snapshot = _NO_ROW if existing is None else {
        "enabled": existing.enabled, "config_encrypted": existing.config_encrypted,
    }
    connector_config_svc.upsert_config(db, "openrouter", {"api_key": api_key} if api_key else {})
    connector_config_svc.set_enabled(db, "openrouter", enabled)
    return snapshot


def _restore_openrouter(snapshot) -> None:
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


def _snapshot_app_setting(db, key: str):
    row = db.get(AppSetting, key)
    return row.value if row else _NO_ROW


def _restore_app_setting(db, key: str, snapshot) -> None:
    if snapshot is _NO_ROW:
        row = db.get(AppSetting, key)
        if row is not None:
            db.delete(row)
            db.commit()
    else:
        app_settings.set_value(db, key, snapshot)


def _insert_ledger_row(*, cost_usd: Decimal | None, task: str, created_at: datetime | None = None) -> None:
    db = SessionLocal()
    try:
        db.add(LlmCall(
            role="classify", task=task, target_id=None, passive_only=False, data_policy="strict",
            requested_model="fixture/seed-model", tier=1, attempt=1, status="ok",
            cost_usd=cost_usd, created_at=created_at or datetime.now(timezone.utc),
        ))
        db.commit()
    finally:
        db.close()


def _cleanup(task: str) -> None:
    db = SessionLocal()
    try:
        db.query(LlmCall).filter(LlmCall.task == task).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _delete_target(target: Target | None) -> None:
    if target is None:
        return
    db = SessionLocal()
    try:
        db.query(Target).filter(Target.id == target.id).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


# ── 1. strict policy, ordinary target ───────────────────────────────────────

def test_strict_policy_ordinary_target_every_request_carries_zdr():
    """R1: under strict (the default), every request body carries
    zdr=true + data_collection=deny — read off the ACTUAL request the
    transport received."""
    suffix = uuid.uuid4().hex[:10]
    task = f"llm140-t1-{suffix}"
    db = SessionLocal()
    snapshot = _configure_openrouter(db)
    prior_policy = settings.llm_data_policy
    try:
        settings.llm_data_policy = "strict"
        scripted = _ScriptedTransport([_ok_response()])
        llmc._transport = scripted.transport
        try:
            llmc.complete(
                db, role=llmc.Role.CLASSIFY, messages=[{"role": "user", "content": "hi"}],
                target_id=None, task=task,
            )
        finally:
            llmc._transport = None

        assert len(scripted.requests) == 1
        body = json.loads(scripted.requests[0].content)
        assert body["provider"]["zdr"] is True
        assert body["provider"]["data_collection"] == "deny"
    finally:
        settings.llm_data_policy = prior_policy
        _cleanup(task)
        _restore_openrouter(snapshot)
        db.close()


# ── 2. dev_permissive policy, ordinary target ───────────────────────────────

def test_dev_permissive_ordinary_target_no_zdr_key_at_all():
    suffix = uuid.uuid4().hex[:10]
    task = f"llm140-t2-{suffix}"
    db = SessionLocal()
    snapshot = _configure_openrouter(db)
    prior_policy = settings.llm_data_policy
    try:
        settings.llm_data_policy = "dev_permissive"
        scripted = _ScriptedTransport([_ok_response()])
        llmc._transport = scripted.transport
        try:
            llmc.complete(
                db, role=llmc.Role.CLASSIFY, messages=[{"role": "user", "content": "hi"}],
                target_id=None, task=task,
            )
        finally:
            llmc._transport = None

        assert len(scripted.requests) == 1
        body = json.loads(scripted.requests[0].content)
        assert body["provider"]["data_collection"] == "allow"
        assert "zdr" not in body["provider"]
    finally:
        settings.llm_data_policy = prior_policy
        _cleanup(task)
        _restore_openrouter(snapshot)
        db.close()


# ── 3. R1+R3 load-bearing test ──────────────────────────────────────────────

def test_dev_permissive_pre_close_target_forces_strict_on_every_request():
    """R1+R3: dev_permissive is never enough on its own — a pre-close
    target forces strict regardless, on EVERY request the ladder sends,
    including a mid-ladder escalation."""
    suffix = uuid.uuid4().hex[:10]
    task = f"llm140-t3-{suffix}"
    db = SessionLocal()
    snapshot = _configure_openrouter(db)
    prior_policy = settings.llm_data_policy
    target = None
    try:
        settings.llm_data_policy = "dev_permissive"
        target = _make_target(db, suffix=suffix, pre_close=True)

        scripted = _ScriptedTransport([
            _error_response(404, message="no eligible endpoint"),
            _ok_response(model="z-ai/glm-5.3-flash"),
        ])
        llmc._transport = scripted.transport
        try:
            result = llmc.complete(
                db, role=llmc.Role.CLASSIFY, messages=[{"role": "user", "content": "hi"}],
                target_id=target.id, task=task,
            )
        finally:
            llmc._transport = None

        assert len(scripted.requests) == 2
        for req in scripted.requests:
            body = json.loads(req.content)
            assert body["provider"]["zdr"] is True
            assert body["provider"]["data_collection"] == "deny"
        assert result.tier == 3
    finally:
        settings.llm_data_policy = prior_policy
        _cleanup(task)
        _delete_target(target)
        _restore_openrouter(snapshot)
        db.close()


# ── 4. degrade explicitly across three models ───────────────────────────────

def test_degrade_across_three_models_to_success():
    suffix = uuid.uuid4().hex[:10]
    task = f"llm140-t4-{suffix}"
    db = SessionLocal()
    snapshot = _configure_openrouter(db)
    target = None
    try:
        target = _make_target(db, suffix=suffix, pre_close=True)
        scripted = _ScriptedTransport([
            _error_response(404, message="no endpoint 1"),
            _error_response(404, message="no endpoint 2"),
            _ok_response(model="google/gemini-2.5-flash-lite"),
        ])
        llmc._transport = scripted.transport
        try:
            result = llmc.complete(
                db, role=llmc.Role.CLASSIFY, messages=[{"role": "user", "content": "hi"}],
                target_id=target.id, task=task,
            )
        finally:
            llmc._transport = None

        assert len(scripted.requests) == 3
        for req in scripted.requests:
            assert json.loads(req.content)["provider"]["zdr"] is True
        assert result.tier == 3

        rows = db.query(LlmCall.status).filter(LlmCall.task == task).order_by(LlmCall.attempt).all()
        assert [r[0] for r in rows] == ["no_eligible_endpoint", "no_eligible_endpoint", "ok"]
    finally:
        _cleanup(task)
        _delete_target(target)
        _restore_openrouter(snapshot)
        db.close()


# ── 5. every model 404s ──────────────────────────────────────────────────────

def test_all_models_404_raises_no_compliant_endpoint():
    suffix = uuid.uuid4().hex[:10]
    task = f"llm140-t5-{suffix}"
    db = SessionLocal()
    snapshot = _configure_openrouter(db)
    prior_policy = settings.llm_data_policy
    try:
        settings.llm_data_policy = "strict"
        scripted = _ScriptedTransport([_error_response(404, message="none") for _ in range(3)])
        llmc._transport = scripted.transport
        try:
            with pytest.raises(llmc.NoCompliantEndpoint) as excinfo:
                llmc.complete(
                    db, role=llmc.Role.CLASSIFY, messages=[{"role": "user", "content": "hi"}],
                    target_id=None, task=task,
                )
        finally:
            llmc._transport = None

        assert len(scripted.requests) == 3
        for req in scripted.requests:
            assert json.loads(req.content)["provider"]["zdr"] is True

        msg = str(excinfo.value)
        assert "classify" in msg
        assert "strict" in msg
        for model in ("deepseek/deepseek-v4-flash", "z-ai/glm-5.3-flash", "google/gemini-2.5-flash-lite"):
            assert model in msg
    finally:
        settings.llm_data_policy = prior_policy
        _cleanup(task)
        _restore_openrouter(snapshot)
        db.close()


# ── 6. structured() request shape ───────────────────────────────────────────

def test_structured_sends_json_schema_strict_and_require_parameters():
    suffix = uuid.uuid4().hex[:10]
    task = f"llm140-t6-{suffix}"
    db = SessionLocal()
    snapshot = _configure_openrouter(db)
    try:
        content = json.dumps({"headline": {"value": _GROUND_QUOTE, "quote": _GROUND_QUOTE}})
        scripted = _ScriptedTransport([_ok_response(content=content)])
        llmc._transport = scripted.transport
        try:
            result = llmc.structured(
                db, role=llmc.Role.EXTRACT, messages=[{"role": "user", "content": "extract"}],
                schema=_Fact, target_id=None, task=task, source_text=_GROUND_SPAN,
            )
        finally:
            llmc._transport = None

        assert len(scripted.requests) == 1
        body = json.loads(scripted.requests[0].content)
        assert body["response_format"]["json_schema"]["strict"] is True
        assert body["response_format"]["json_schema"]["name"] == "_Fact"
        assert body["provider"]["require_parameters"] is True
        assert result.grounding == "verified"
    finally:
        _cleanup(task)
        _restore_openrouter(snapshot)
        db.close()


# ── 7. tier-1 invalid JSON falls through to tier 2 ──────────────────────────

def test_tier1_invalid_json_falls_through_to_tier2_extract_primary():
    suffix = uuid.uuid4().hex[:10]
    task = f"llm140-t7-{suffix}"
    db = SessionLocal()
    snapshot = _configure_openrouter(db)
    try:
        bindings = llmc.load_bindings(db)
        extract_primary = bindings[llmc.Role.EXTRACT].models[0]

        tier1_raw = "this is not valid json at all"
        tier2_content = json.dumps({"headline": {"value": _GROUND_QUOTE, "quote": _GROUND_QUOTE}})

        scripted = _ScriptedTransport([
            _ok_response(content=tier1_raw, model="deepseek/deepseek-v4-flash"),
            _ok_response(content=tier2_content, model=extract_primary),
        ])
        llmc._transport = scripted.transport
        try:
            result = llmc.structured(
                db, role=llmc.Role.CLASSIFY, messages=[{"role": "user", "content": "classify"}],
                schema=_Fact, target_id=None, task=task, source_text=_GROUND_SPAN,
            )
        finally:
            llmc._transport = None

        assert len(scripted.requests) == 2
        second_body = json.loads(scripted.requests[1].content)
        assert second_body["model"] == extract_primary
        user_texts = [m["content"] for m in second_body["messages"] if m["role"] == "user"]
        assert any(tier1_raw in text for text in user_texts)
        assert result.tier == 2
        assert result.grounding == "verified"

        rows = db.query(LlmCall.status, LlmCall.tier).filter(LlmCall.task == task).order_by(LlmCall.attempt).all()
        assert [tuple(r) for r in rows] == [("invalid_output", 1), ("ok", 2)]
    finally:
        _cleanup(task)
        _restore_openrouter(snapshot)
        db.close()


# ── 8. structurer as a source (R2) ──────────────────────────────────────────

def test_tier2_ungrounded_fails_and_positive_twin_passes():
    """R2: the structurer is a transformer, never a source. Same fixture
    (`_GROUND_SPAN`/schema) mutated only in what the mocked tier-2 model
    returns — negative case has an invented quote, positive case reuses
    `_GROUND_QUOTE`, which is genuinely present in the span."""
    suffix = uuid.uuid4().hex[:10]
    task_neg = f"llm140-t8neg-{suffix}"
    task_pos = f"llm140-t8pos-{suffix}"
    db = SessionLocal()
    snapshot = _configure_openrouter(db)
    bindings_snapshot = _snapshot_app_setting(db, "llm.role_bindings")
    try:
        custom = copy.deepcopy(app_settings._LLM_ROLE_BINDINGS_DEFAULT)
        custom["classify"] = {"models": ["fixture/model-a", "fixture/model-b"], "max_tokens": 512, "temperature": 0}
        app_settings.set_value(db, "llm.role_bindings", json.dumps(custom))

        bindings = llmc.load_bindings(db)
        extract_primary = bindings[llmc.Role.EXTRACT].models[0]

        tier1_raw = "not json"
        bad_quote_content = json.dumps({"headline": {"value": "a totally invented phrase", "quote": "a totally invented phrase"}})

        # ── negative: both bound models exhausted, tier 2 ungrounded twice ──
        scripted = _ScriptedTransport([
            _ok_response(content=tier1_raw, model="fixture/model-a"),
            _ok_response(content=bad_quote_content, model=extract_primary),
            _ok_response(content=tier1_raw, model="fixture/model-b"),
            _ok_response(content=bad_quote_content, model=extract_primary),
        ])
        llmc._transport = scripted.transport
        try:
            with pytest.raises(llmc.StructuredOutputFailed):
                llmc.structured(
                    db, role=llmc.Role.CLASSIFY, messages=[{"role": "user", "content": "classify"}],
                    schema=_Fact, target_id=None, task=task_neg, source_text=_GROUND_SPAN,
                )
        finally:
            llmc._transport = None

        ungrounded_rows = db.query(LlmCall).filter(LlmCall.task == task_neg, LlmCall.status == "ungrounded").all()
        assert len(ungrounded_rows) == 2
        assert all(row.ungrounded_fields == ["headline"] for row in ungrounded_rows)

        # ── positive twin: identical fixture, quote genuinely in span ──
        good_content = json.dumps({"headline": {"value": _GROUND_QUOTE, "quote": _GROUND_QUOTE}})
        scripted2 = _ScriptedTransport([
            _ok_response(content=tier1_raw, model="fixture/model-a"),
            _ok_response(content=good_content, model=extract_primary),
        ])
        llmc._transport = scripted2.transport
        try:
            result = llmc.structured(
                db, role=llmc.Role.CLASSIFY, messages=[{"role": "user", "content": "classify"}],
                schema=_Fact, target_id=None, task=task_pos, source_text=_GROUND_SPAN,
            )
        finally:
            llmc._transport = None
        assert result.grounding == "verified"
        assert result.tier == 2
    finally:
        _cleanup(task_neg)
        _cleanup(task_pos)
        _restore_app_setting(db, "llm.role_bindings", bindings_snapshot)
        _restore_openrouter(snapshot)
        db.close()


# ── 9. source_text=None -> not_applicable; missing required kwargs -> TypeError ─

def test_source_text_none_not_applicable_and_missing_kwargs_typeerror():
    suffix = uuid.uuid4().hex[:10]
    task = f"llm140-t9-{suffix}"
    db = SessionLocal()
    snapshot = _configure_openrouter(db)
    try:
        content = json.dumps({"headline": {"value": "whatever the model likes", "quote": "whatever the model likes"}})
        scripted = _ScriptedTransport([_ok_response(content=content)])
        llmc._transport = scripted.transport
        try:
            result = llmc.structured(
                db, role=llmc.Role.EXTRACT, messages=[{"role": "user", "content": "extract"}],
                schema=_Fact, target_id=None, task=task, source_text=None,
            )
        finally:
            llmc._transport = None
        assert result.grounding == "not_applicable"

        with pytest.raises(TypeError):
            llmc.structured(  # missing target_id
                db, role=llmc.Role.EXTRACT, messages=[{"role": "user", "content": "x"}],
                schema=_Fact, task=task, source_text="x",
            )
        with pytest.raises(TypeError):
            llmc.structured(  # missing source_text
                db, role=llmc.Role.EXTRACT, messages=[{"role": "user", "content": "x"}],
                schema=_Fact, target_id=None, task=task,
            )
        with pytest.raises(TypeError):
            llmc.complete(  # missing target_id
                db, role=llmc.Role.EXTRACT, messages=[{"role": "user", "content": "x"}], task=task,
            )
    finally:
        _cleanup(task)
        _restore_openrouter(snapshot)
        db.close()


# ── 10. 429 handling ─────────────────────────────────────────────────────────

def test_429_short_retry_after_retries_then_succeeds():
    suffix = uuid.uuid4().hex[:10]
    task = f"llm140-t10a-{suffix}"
    db = SessionLocal()
    snapshot = _configure_openrouter(db)
    sleep_calls: list[float] = []
    orig_sleep = llmc._sleep
    try:
        llmc._sleep = lambda s: sleep_calls.append(s)
        scripted = _ScriptedTransport([
            _error_response(429, message="slow down", headers={"Retry-After": "2"}),
            _ok_response(),
        ])
        llmc._transport = scripted.transport
        try:
            llmc.complete(
                db, role=llmc.Role.CLASSIFY, messages=[{"role": "user", "content": "hi"}],
                target_id=None, task=task,
            )
        finally:
            llmc._transport = None

        assert sleep_calls == [2.0]
        rows = db.query(LlmCall.status).filter(LlmCall.task == task).order_by(LlmCall.attempt).all()
        assert [r[0] for r in rows] == ["rate_limited", "ok"]
    finally:
        llmc._sleep = orig_sleep
        _cleanup(task)
        _restore_openrouter(snapshot)
        db.close()


def test_429_long_retry_after_raises_without_second_request():
    suffix = uuid.uuid4().hex[:10]
    task = f"llm140-t10b-{suffix}"
    db = SessionLocal()
    snapshot = _configure_openrouter(db)
    sleep_calls: list[float] = []
    orig_sleep = llmc._sleep
    try:
        llmc._sleep = lambda s: sleep_calls.append(s)
        scripted = _ScriptedTransport([_error_response(429, message="slow down", headers={"Retry-After": "120"})])
        llmc._transport = scripted.transport
        try:
            with pytest.raises(llmc.LLMRateLimited) as excinfo:
                llmc.complete(
                    db, role=llmc.Role.CLASSIFY, messages=[{"role": "user", "content": "hi"}],
                    target_id=None, task=task,
                )
        finally:
            llmc._transport = None

        assert excinfo.value.retry_after_s == 120.0
        assert len(scripted.requests) == 1
        assert sleep_calls == []
    finally:
        llmc._sleep = orig_sleep
        _cleanup(task)
        _restore_openrouter(snapshot)
        db.close()


# ── 11. 402 handling ─────────────────────────────────────────────────────────

def test_402_in_flight_budget_behaves_as_429_other_402_raises_budget_exhausted():
    suffix = uuid.uuid4().hex[:10]
    task_inflight = f"llm140-t11a-{suffix}"
    task_other = f"llm140-t11b-{suffix}"
    db = SessionLocal()
    snapshot = _configure_openrouter(db)
    orig_sleep = llmc._sleep
    try:
        llmc._sleep = lambda s: None
        scripted = _ScriptedTransport([
            httpx.Response(402, json={"error": {"message": "in flight", "metadata": {"reason": "in_flight_budget_exhausted"}}}),
            _ok_response(),
        ])
        llmc._transport = scripted.transport
        try:
            llmc.complete(
                db, role=llmc.Role.CLASSIFY, messages=[{"role": "user", "content": "hi"}],
                target_id=None, task=task_inflight,
            )
        finally:
            llmc._transport = None
        assert len(scripted.requests) == 2
        rows = db.query(LlmCall.status).filter(LlmCall.task == task_inflight).order_by(LlmCall.attempt).all()
        assert [r[0] for r in rows] == ["rate_limited", "ok"]

        scripted2 = _ScriptedTransport([httpx.Response(402, json={"error": {"message": "insufficient credit"}})])
        llmc._transport = scripted2.transport
        try:
            with pytest.raises(llmc.LLMBudgetExhausted):
                llmc.complete(
                    db, role=llmc.Role.CLASSIFY, messages=[{"role": "user", "content": "hi"}],
                    target_id=None, task=task_other,
                )
        finally:
            llmc._transport = None
        assert len(scripted2.requests) == 1
        rows2 = db.query(LlmCall.status).filter(LlmCall.task == task_other).all()
        assert [r[0] for r in rows2] == ["budget_refused"]
    finally:
        llmc._sleep = orig_sleep
        _cleanup(task_inflight)
        _cleanup(task_other)
        _restore_openrouter(snapshot)
        db.close()


# ── 12. budget gate ──────────────────────────────────────────────────────────

def test_budget_gate_just_under_proceeds_just_over_refuses():
    suffix = uuid.uuid4().hex[:10]
    task_under = f"llm140-t12u-{suffix}"
    task_over = f"llm140-t12o-{suffix}"
    db = SessionLocal()
    snapshot = _configure_openrouter(db)
    try:
        budget = Decimal(app_settings.get(db, "llm.daily_budget_usd") or "5")
        threshold_raw = budget / (1 + llmc.OPENROUTER_CREDIT_FEE_RATE)

        _insert_ledger_row(cost_usd=threshold_raw - Decimal("0.01"), task=task_under)
        scripted = _ScriptedTransport([_ok_response()])
        llmc._transport = scripted.transport
        try:
            llmc.complete(
                db, role=llmc.Role.CLASSIFY, messages=[{"role": "user", "content": "hi"}],
                target_id=None, task=task_under,
            )
        finally:
            llmc._transport = None
        assert len(scripted.requests) == 1
        _cleanup(task_under)

        _insert_ledger_row(cost_usd=threshold_raw + Decimal("0.02"), task=task_over)
        scripted2 = _ScriptedTransport([])
        llmc._transport = scripted2.transport
        try:
            with pytest.raises(llmc.LLMBudgetExhausted):
                llmc.complete(
                    db, role=llmc.Role.CLASSIFY, messages=[{"role": "user", "content": "hi"}],
                    target_id=None, task=task_over,
                )
        finally:
            llmc._transport = None
        assert len(scripted2.requests) == 0
        rows = db.query(LlmCall).filter(LlmCall.task == task_over).all()
        assert any(r.status == "budget_refused" for r in rows)
    finally:
        _cleanup(task_under)
        _cleanup(task_over)
        _restore_openrouter(snapshot)
        db.close()


# ── 13. not configured, three ways ──────────────────────────────────────────

def test_not_configured_various_reasons_zero_requests():
    db = SessionLocal()
    existing = connector_config_svc.get_one(db, "openrouter")
    outer_snapshot = _NO_ROW if existing is None else {
        "enabled": existing.enabled, "config_encrypted": existing.config_encrypted,
    }
    db.close()

    try:
        for scenario in ("missing", "disabled", "empty_key"):
            suffix = uuid.uuid4().hex[:10]
            task = f"llm140-t13-{scenario}-{suffix}"
            db = SessionLocal()
            try:
                db.query(ConnectorConfig).filter(ConnectorConfig.connector_id == "openrouter").delete()
                db.commit()
                if scenario == "disabled":
                    connector_config_svc.upsert_config(db, "openrouter", {"api_key": _TEST_API_KEY})
                    connector_config_svc.set_enabled(db, "openrouter", False)
                elif scenario == "empty_key":
                    connector_config_svc.upsert_config(db, "openrouter", {"api_key": ""})
                    connector_config_svc.set_enabled(db, "openrouter", True)
                # "missing": row stays deleted.

                scripted = _ScriptedTransport([])
                llmc._transport = scripted.transport
                try:
                    with pytest.raises(llmc.LLMNotConfigured):
                        llmc.complete(
                            db, role=llmc.Role.CLASSIFY, messages=[{"role": "user", "content": "hi"}],
                            target_id=None, task=task,
                        )
                finally:
                    llmc._transport = None

                assert len(scripted.requests) == 0
                rows = db.query(LlmCall).filter(LlmCall.task == task).all()
                assert len(rows) == 1, scenario
                assert rows[0].status == "not_configured"
                assert rows[0].tier == 1
                assert rows[0].attempt == 1
            finally:
                _cleanup(task)
                db.close()
    finally:
        _restore_openrouter(outer_snapshot)


# ── 14. invalid stored role bindings ────────────────────────────────────────

def test_invalid_role_bindings_raises_config_error_zero_requests():
    suffix = uuid.uuid4().hex[:10]
    task = f"llm140-t14-{suffix}"
    db = SessionLocal()
    snapshot = _configure_openrouter(db)
    bindings_snapshot = _snapshot_app_setting(db, "llm.role_bindings")
    try:
        app_settings.set_value(db, "llm.role_bindings", "not valid json{{{")
        scripted = _ScriptedTransport([])
        llmc._transport = scripted.transport
        try:
            with pytest.raises(llmc.LLMConfigError):
                llmc.complete(
                    db, role=llmc.Role.CLASSIFY, messages=[{"role": "user", "content": "hi"}],
                    target_id=None, task=task,
                )
        finally:
            llmc._transport = None
        assert len(scripted.requests) == 0
    finally:
        _restore_app_setting(db, "llm.role_bindings", bindings_snapshot)
        _cleanup(task)
        _restore_openrouter(snapshot)
        db.close()


# ── 15. no content ever leaks into the ledger (R4) ──────────────────────────

def test_ledger_row_never_contains_prompt_or_response_content():
    marker = f"MARKER-{uuid.uuid4().hex}"
    suffix = uuid.uuid4().hex[:10]
    task = f"llm140-t15-{suffix}"
    db = SessionLocal()
    snapshot = _configure_openrouter(db)
    try:
        messages = [{"role": "user", "content": f"Please summarize: {marker}"}]
        scripted = _ScriptedTransport([_ok_response(
            content=f"Sure, here is a summary mentioning {marker}.",
            model="deepseek/deepseek-v4-flash", provider="DeepSeek", gen_id="gen-marker-1",
            prompt_tokens=42, completion_tokens=7, cached_tokens=3, cost=0.002345,
        )])
        llmc._transport = scripted.transport
        try:
            result = llmc.complete(db, role=llmc.Role.CLASSIFY, messages=messages, target_id=None, task=task)
        finally:
            llmc._transport = None

        # Sanity: the marker really did flow through the completion — this
        # proves the assertion below is testing something, not vacuous.
        assert marker in result.text

        rows = db.query(LlmCall).filter(LlmCall.task == task).all()
        assert len(rows) == 1
        row = rows[0]
        assert row.served_model == "deepseek/deepseek-v4-flash"
        assert row.provider == "DeepSeek"
        assert row.generation_id == "gen-marker-1"
        assert row.prompt_tokens == 42
        assert row.completion_tokens == 7
        assert row.cached_tokens == 3
        assert row.cost_usd == Decimal("0.002345")

        for col in sa_inspect(LlmCall).columns:
            value = getattr(row, col.key)
            assert marker not in str(value), f"marker leaked into llm_calls.{col.key}"
    finally:
        _cleanup(task)
        _restore_openrouter(snapshot)
        db.close()


# ── 16. ledger survives caller rollback ─────────────────────────────────────

def test_ledger_survives_caller_rollback():
    suffix = uuid.uuid4().hex[:10]
    task = f"llm140-t16-{suffix}"
    db = SessionLocal()
    snapshot = _configure_openrouter(db)
    try:
        scripted = _ScriptedTransport([_ok_response()])
        llmc._transport = scripted.transport
        try:
            llmc.complete(db, role=llmc.Role.CLASSIFY, messages=[{"role": "user", "content": "hi"}], target_id=None, task=task)
        finally:
            llmc._transport = None

        db.rollback()

        fresh = SessionLocal()
        try:
            rows = fresh.query(LlmCall).filter(LlmCall.task == task).all()
            assert len(rows) == 1
        finally:
            fresh.close()
    finally:
        _cleanup(task)
        _restore_openrouter(snapshot)
        db.close()


# ── 17. retention pruning ────────────────────────────────────────────────────

def test_prune_ledger_deletes_old_keeps_new():
    suffix = uuid.uuid4().hex[:10]
    task = f"llm140-t17-{suffix}"
    db = SessionLocal()
    try:
        retention_days = app_settings.get_int(db, "llm_ledger_retention_days") or 400
        old_time = datetime.now(timezone.utc) - timedelta(days=retention_days + 5)
        new_time = datetime.now(timezone.utc) - timedelta(days=1)
        _insert_ledger_row(cost_usd=None, task=task, created_at=old_time)
        _insert_ledger_row(cost_usd=None, task=task, created_at=new_time)

        assert db.query(LlmCall).filter(LlmCall.task == task).count() == 2

        llmc.prune_ledger(db)

        rows_after = db.query(LlmCall).filter(LlmCall.task == task).all()
        assert len(rows_after) == 1
        assert abs((rows_after[0].created_at - new_time).total_seconds()) < 5
    finally:
        _cleanup(task)
        db.close()


# ── 18. free-model client-side rate limit ───────────────────────────────────

def test_free_model_window_throttles_21st_request_paid_model_unaffected():
    llmc._free_model_window.clear()
    sleep_calls: list[float] = []
    orig_sleep = llmc._sleep
    orig_now = llmc._now
    current = [datetime(2026, 1, 1, tzinfo=timezone.utc)]

    def _fake_sleep(s: float) -> None:
        sleep_calls.append(s)
        current[0] = current[0] + timedelta(seconds=s)

    try:
        llmc._sleep = _fake_sleep
        llmc._now = lambda: current[0]

        for _ in range(llmc.FREE_MODEL_RPM):
            llmc._rate_limit_free_model("fixture/some-model:free")
        assert sleep_calls == [], "the first 20 :free requests must not wait"

        llmc._rate_limit_free_model("fixture/some-model:free")
        assert len(sleep_calls) == 1, "the 21st :free request within 60s must wait"
        assert sleep_calls[0] > 0

        sleep_calls.clear()
        llmc._rate_limit_free_model("fixture/some-model")  # paid — no ":free" suffix
        assert sleep_calls == [], "a paid model must never be throttled by this window"
    finally:
        llmc._sleep = orig_sleep
        llmc._now = orig_now
        llmc._free_model_window.clear()


# ── 19. bad env value rejected at construction ──────────────────────────────

def test_invalid_llm_data_policy_env_value_rejected():
    with pytest.raises(ValidationError):
        Settings(llm_data_policy="nope")


# ── 20. is_configured() ignores a bare env var ──────────────────────────────

def test_is_configured_false_when_only_env_var_set():
    connector = OpenRouterConnector()
    secrets_mod.set_db_override("OPENROUTER_API_KEY", None)
    os.environ["OPENROUTER_API_KEY"] = "env-only-value-not-real"
    try:
        assert connector.is_configured() is False
    finally:
        del os.environ["OPENROUTER_API_KEY"]


# ── review additions (planning#140 slice-1 review) ──────────────────────────
#
# Each of these pins a defect found in review of the first cut, not a spec
# item. The first is a defect in the SPEC: it said tier-2 success is "always
# verified", which labels a claim grounded only in the model's own prose as
# sourced.

def test_tier2_without_source_text_is_not_applicable_not_verified():
    """R2 through the LABEL: with no caller source_text, tier 2 checks the
    structurer against tier 1's own prose. That proves "not invented by the
    structurer", NOT "sourced" - so the result must not carry the label a
    consumer would read as sourced. Asserts tier 2 was REACHED (two
    requests, a tier-2 ledger row), not just the label."""
    suffix = uuid.uuid4().hex[:10]
    task = f"llm140-r1-{suffix}"
    db = SessionLocal()
    snapshot = _configure_openrouter(db)
    try:
        tier1_raw = "Example Holdings reported a headline result this quarter (not JSON)."
        tier2_content = json.dumps({"headline": {"value": _GROUND_QUOTE, "quote": _GROUND_QUOTE}})
        scripted = _ScriptedTransport([
            _ok_response(content=tier1_raw),
            _ok_response(content=tier2_content),
        ])
        llmc._transport = scripted.transport
        try:
            result = llmc.structured(
                db, role=llmc.Role.CLASSIFY, messages=[{"role": "user", "content": "classify"}],
                schema=_Fact, target_id=None, task=task, source_text=None,
            )
        finally:
            llmc._transport = None

        assert len(scripted.requests) == 2
        assert result.tier == 2
        assert result.grounding == "not_applicable"
        rows = db.query(LlmCall.status, LlmCall.tier).filter(LlmCall.task == task).order_by(LlmCall.attempt).all()
        assert [tuple(r) for r in rows] == [("invalid_output", 1), ("ok", 2)]
    finally:
        _cleanup(task)
        _restore_openrouter(snapshot)
        db.close()


def test_not_configured_row_records_pre_close_posture_truthfully():
    """The refusal row is written before any request - it must still carry
    the target's real posture, not a default. dev_permissive env + pre-close
    target: the row says passive_only=True, data_policy=strict."""
    suffix = uuid.uuid4().hex[:10]
    task = f"llm140-r2-{suffix}"
    db = SessionLocal()
    snapshot = _configure_openrouter(db, enabled=False)
    prior_policy = settings.llm_data_policy
    target = None
    try:
        settings.llm_data_policy = "dev_permissive"
        target = _make_target(db, suffix=suffix, pre_close=True)
        scripted = _ScriptedTransport([])
        llmc._transport = scripted.transport
        try:
            with pytest.raises(llmc.LLMNotConfigured):
                llmc.complete(
                    db, role=llmc.Role.CLASSIFY, messages=[{"role": "user", "content": "hi"}],
                    target_id=target.id, task=task,
                )
        finally:
            llmc._transport = None
        assert len(scripted.requests) == 0
        row = db.query(LlmCall).filter(LlmCall.task == task).one()
        assert row.status == "not_configured"
        assert row.passive_only is True
        assert row.data_policy == "strict"
        assert row.target_id == target.id
    finally:
        settings.llm_data_policy = prior_policy
        _cleanup(task)
        _delete_target(target)
        _restore_openrouter(snapshot)
        db.close()


def test_200_without_content_is_upstream_error_billed_and_escalates():
    """A 200 with `content: null` (refusal / tool-call-only) or no choices
    must not be treated as success: it escalates to the next model, and its
    usage/cost is still recorded because it may have been billed."""
    suffix = uuid.uuid4().hex[:10]
    task = f"llm140-r3-{suffix}"
    db = SessionLocal()
    snapshot = _configure_openrouter(db)
    try:
        null_body = {
            "id": "gen-null", "model": "deepseek/deepseek-v4-flash", "provider": "DeepInfra",
            "choices": [{"message": {"role": "assistant", "content": None}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 7, "completion_tokens": 0, "cost": 0.000123},
        }
        empty_body = {"id": "gen-empty", "model": "z-ai/glm-5.3-flash", "choices": [], "usage": {"cost": 0.0001}}
        scripted = _ScriptedTransport([
            httpx.Response(200, json=null_body),
            httpx.Response(200, json=empty_body),
            _ok_response(model="google/gemini-2.5-flash-lite", content="fine"),
        ])
        llmc._transport = scripted.transport
        try:
            result = llmc.complete(
                db, role=llmc.Role.CLASSIFY, messages=[{"role": "user", "content": "hi"}],
                target_id=None, task=task,
            )
        finally:
            llmc._transport = None
        assert len(scripted.requests) == 3
        assert result.text == "fine"
        rows = db.query(LlmCall).filter(LlmCall.task == task).order_by(LlmCall.attempt).all()
        assert [r.status for r in rows] == ["upstream_error", "upstream_error", "ok"]
        assert rows[0].cost_usd == Decimal("0.000123")
        assert rows[0].generation_id == "gen-null"
    finally:
        _cleanup(task)
        _restore_openrouter(snapshot)
        db.close()


def test_5xx_retries_inline_then_escalates_and_transport_error_does_too():
    """The 5xx / TransportError branch, untested in the first cut: two inline
    retries on the SAME model (a backoff sleep each), then escalation to the
    next model - never a raise."""
    suffix = uuid.uuid4().hex[:10]
    task = f"llm140-r4-{suffix}"
    db = SessionLocal()
    snapshot = _configure_openrouter(db)
    sleeps: list[float] = []
    prior_sleep = llmc._sleep
    try:
        llmc._sleep = sleeps.append
        bindings = llmc.load_bindings(db)
        primary, second = bindings[llmc.Role.CLASSIFY].models[:2]
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            model = json.loads(request.content)["model"]
            calls.append(model)
            if model == primary:
                if calls.count(primary) == 1:
                    raise httpx.ConnectError("synthetic connect failure", request=request)
                return _error_response(503, message="overloaded")
            return _ok_response(model=second)

        llmc._transport = httpx.MockTransport(handler)
        try:
            result = llmc.complete(
                db, role=llmc.Role.CLASSIFY, messages=[{"role": "user", "content": "hi"}],
                target_id=None, task=task,
            )
        finally:
            llmc._transport = None

        # primary: transport_error, 503, 503 (1 + 2 retries) -> escalate -> second ok
        assert calls == [primary, primary, primary, second]
        assert len(sleeps) == 2
        assert all(1 <= s <= 2.5 for s in sleeps)
        assert result.tier == 3
        rows = db.query(LlmCall.status).filter(LlmCall.task == task).order_by(LlmCall.attempt).all()
        assert [r[0] for r in rows] == ["transport_error", "upstream_error", "upstream_error", "ok"]
    finally:
        llmc._sleep = prior_sleep
        _cleanup(task)
        _restore_openrouter(snapshot)
        db.close()


def test_spend_summary_aggregates_and_grosses_up():
    """Rows are placed in a window in the far past so nothing else in the
    suite can land in it."""
    suffix = uuid.uuid4().hex[:10]
    task = f"llm140-r5-{suffix}"
    base = datetime(2001, 1, 1, tzinfo=timezone.utc)
    db = SessionLocal()
    try:
        _insert_ledger_row(cost_usd=Decimal("1.000000"), task=task, created_at=base)
        _insert_ledger_row(cost_usd=Decimal("0.500000"), task=task, created_at=base + timedelta(hours=1))
        _insert_ledger_row(cost_usd=None, task=task, created_at=base + timedelta(hours=2))
        _insert_ledger_row(cost_usd=Decimal("9.000000"), task=task, created_at=base + timedelta(days=2))  # outside

        summary = llmc.spend_summary(db, since=base, until=base + timedelta(days=1))
        assert summary["calls"] == 3
        assert summary["raw_usd"] == Decimal("1.500000")
        assert summary["gross_usd"] == Decimal("1.500000") * Decimal("1.055")
        assert summary["by_task"] == {task: Decimal("1.500000")}
        assert summary["by_role"] == {"classify": Decimal("1.500000")}
        assert summary["passive_only_raw_usd"] == Decimal("0")
    finally:
        _cleanup(task)
        db.close()


def test_connector_test_button_ignores_env_key():
    """R5 for the Test button: with only an env var set and an empty stored
    config, it reports not configured and never reaches the network."""
    connector = OpenRouterConnector()
    os.environ["OPENROUTER_API_KEY"] = "env-only-value-not-real"
    prior_get = httpx.get

    def _no_network(*a, **k):
        raise AssertionError("Test button reached the network with an env-only key")

    httpx.get = _no_network
    try:
        result = connector.test({})
        assert result.success is False
        assert "not configured" in result.message
    finally:
        httpx.get = prior_get
        del os.environ["OPENROUTER_API_KEY"]
