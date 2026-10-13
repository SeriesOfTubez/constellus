"""Admin API for LLM model configuration (planning#224 items 1, 3, 5, 7).

Three concerns, all ADMIN-only:

- **Role bindings** (item 3) — `GET/PUT /api/llm/role-bindings` read and
  write `app_settings['llm.role_bindings']`, the role → model-ladder map
  `llm_connector.load_bindings` consumes. The PUT validates every role is
  present and well-formed (reusing `llm_connector.RoleBinding`) and audits
  the old → new ladders via `audit.record_detail`. Model ids are settings,
  not content, so recording them is correct (R4 is about prompt/response
  content, which never touches this path).

- **Guardrail allow-list** (item 1) — `GET /api/llm/models` returns the
  cached `/models/user` result (what this key's OpenRouter guardrail
  permits), and `POST /api/llm/models/refresh` re-fetches and re-caches it.
  Each entry also carries its ZDR endpoint counts (display only).

- **Status** (item 7) — `GET /api/llm/status`: the OpenRouter key's credit
  limit / remaining / usage next to the app's own daily budget and today's
  spend. Either the key or the budget can bite first, so the page shows
  both; a key-status failure is reported in `key_error`, never a 5xx that
  would also hide the budget. It also carries the automatic write-up cap
  and today's auto count (planning#226 slice 2).

- **Settings** — `PUT /api/llm/settings` sets
  `ai.finding_writeups.auto_daily_cap` (0 = off), audited old → new.
  `PUT /api/llm/chat-settings` sets `chat.transcript_retention_days`
  (planning#228), audited the same way; `GET /status` reports it.
  `PUT /api/llm/web-classification-settings` sets
  `ai.web_classifications.auto_daily_cap` (planning#231), likewise.
  `PUT /api/llm/digest-settings` sets `ai.digests.narrative_daily_cap`
  (planning#233 slice 2a); `GET /status` reports it as `digest_narratives`.

There is no code default for the bindings (item 5): until the first PUT,
`GET /role-bindings` answers `configured: false` and AI features report
"AI models not configured".
"""

import json

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy.orm import Session

from app.api.deps import require_role
from app.core.database import get_db
from app.models.user import UserRole
from app.services import app_settings, audit, finding_writeup, llm_connector
from app.services import chat, web_classifier
from app.services import digest
from app.services.llm_connector import Role, RoleBinding

router = APIRouter()


class RoleBindingIn(BaseModel):
    models: list[str]
    max_tokens: int
    temperature: float


class RoleBindingsUpdate(BaseModel):
    # One entry per Role, validated below. A mapping (not a list) so the
    # client names each role explicitly and a missing role is a clear 422
    # rather than a silently-short ladder.
    bindings: dict[str, RoleBindingIn]


class RoleBindingsResponse(BaseModel):
    # `configured: false` + `bindings: null` on a fresh install (item 5).
    configured: bool
    bindings: dict[str, dict] | None


class KeyStatus(BaseModel):
    limit: float | None
    limit_remaining: float | None
    usage: float | None
    is_free_tier: bool | None


class BudgetStatus(BaseModel):
    daily_budget_usd: float
    spent_today_usd: float


class AutoWriteupStatus(BaseModel):
    daily_cap: int
    today: int


class LlmStatusResponse(BaseModel):
    connector_configured: bool
    models_configured: bool
    key: KeyStatus | None
    key_error: str | None
    budget: BudgetStatus
    auto_writeups: AutoWriteupStatus
    auto_web_classifications: AutoWriteupStatus
    chat_transcript_retention_days: int
    digest_narratives: AutoWriteupStatus


class LlmSettingsUpdate(BaseModel):
    # An upper bound so a typo cannot authorise thousands of calls; the
    # global daily budget still bites first in practice.
    auto_writeups_daily_cap: int = Field(ge=0, le=1000)


class AllowedModelsResponse(BaseModel):
    fetched_at: str | None
    models: list[dict]


def _bindings_response(db: Session) -> RoleBindingsResponse:
    try:
        bindings = llm_connector.load_bindings(db)
    except llm_connector.ModelsNotConfigured:
        return RoleBindingsResponse(configured=False, bindings=None)
    except llm_connector.LLMConfigError as exc:
        # The stored value is corrupt/incomplete — surface it so the admin
        # can fix it, rather than 500ing.
        raise HTTPException(status_code=409, detail=str(exc))
    return RoleBindingsResponse(
        configured=True, bindings={role.value: binding.model_dump() for role, binding in bindings.items()},
    )


@router.get("/role-bindings", response_model=RoleBindingsResponse)
def get_role_bindings(
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN)),
):
    return _bindings_response(db)


@router.put("/role-bindings", response_model=RoleBindingsResponse)
def put_role_bindings(
    data: RoleBindingsUpdate,
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN)),
):
    required = {r.value for r in Role}
    given = set(data.bindings)
    missing = required - given
    if missing:
        raise HTTPException(status_code=422, detail=f"missing role(s): {sorted(missing)}")
    unknown = given - required
    if unknown:
        raise HTTPException(status_code=422, detail=f"unknown role(s): {sorted(unknown)}")

    # Validate each entry through the SAME model the call path validates
    # with (`RoleBinding`), so a binding that saves here can never fail to
    # load at call time. Build the canonical JSON the connector reads.
    validated: dict[str, dict] = {}
    for role_name, entry in data.bindings.items():
        try:
            binding = RoleBinding.model_validate(entry.model_dump())
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail=f"role {role_name!r} is invalid: {exc}")
        validated[role_name] = binding.model_dump()

    # Capture the old ladders for the audit trail BEFORE overwriting. Read
    # the stored value raw so a currently-corrupt binding is still recorded
    # as what it was, not an exception (None = never configured).
    old_raw = app_settings.get(db, "llm.role_bindings")
    try:
        old_parsed = json.loads(old_raw) if old_raw else None
    except json.JSONDecodeError:
        old_parsed = {"_unparseable": True}

    app_settings.set_value(db, "llm.role_bindings", json.dumps(validated))

    audit.record_detail(request, role_bindings={"from": old_parsed, "to": validated})
    return _bindings_response(db)


@router.get("/models", response_model=AllowedModelsResponse)
def get_allowed_models(
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN)),
):
    """The cached guardrail allow-list. `fetched_at` is null when it has
    never been refreshed (cold cache = the call path skips no model)."""
    allowed = llm_connector.load_allowed_models(db)
    if allowed is None:
        return AllowedModelsResponse(fetched_at=None, models=[])
    return AllowedModelsResponse(fetched_at=allowed.fetched_at.isoformat(), models=allowed.entries)


@router.post("/models/refresh", response_model=AllowedModelsResponse)
def refresh_allowed_models(
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN)),
):
    """Re-fetch `/models/user` and re-cache it. A fetch failure leaves the
    last good cache intact (409 not-configured / 502 upstream)."""
    try:
        allowed = llm_connector.refresh_allowed_models(db)
    except llm_connector.LLMNotConfigured as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except llm_connector.LLMUpstreamError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    audit.record_detail(
        request,
        allowed_models_refreshed={"count": len(allowed.entries), "fetched_at": allowed.fetched_at.isoformat()},
    )
    return AllowedModelsResponse(fetched_at=allowed.fetched_at.isoformat(), models=allowed.entries)


def _digest_narratives(db: Session) -> AutoWriteupStatus:
    return AutoWriteupStatus(daily_cap=digest.narrative_daily_cap(db), today=digest.narrative_count_today(db))


@router.get("/status", response_model=LlmStatusResponse)
def get_status(
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN)),
):
    """Key credit (live `/api/v1/key`, item 7) + app budget + whether the
    connector and the role bindings are configured. Sends no inference
    request and writes no ledger row."""
    connector_configured = llm_connector.is_configured(db)
    key, key_error = None, None
    if connector_configured:
        try:
            key = KeyStatus(**llm_connector.key_status(db))
        except (llm_connector.LLMNotConfigured, llm_connector.LLMUpstreamError) as exc:
            key_error = str(exc)
    budget = llm_connector.budget_status(db)
    return LlmStatusResponse(
        connector_configured=connector_configured,
        models_configured=llm_connector.models_configured(db),
        key=key,
        key_error=key_error,
        budget=BudgetStatus(
            daily_budget_usd=float(budget["daily_budget_usd"]), spent_today_usd=float(budget["spent_today_usd"]),
        ),
        auto_writeups=AutoWriteupStatus(
            daily_cap=finding_writeup.auto_daily_cap(db), today=finding_writeup.auto_count_today(db),
        ),
        auto_web_classifications=AutoWriteupStatus(
            daily_cap=web_classifier.auto_daily_cap(db), today=web_classifier.auto_count_today(db),
        ),
        chat_transcript_retention_days=chat.retention_days(db),
        digest_narratives=_digest_narratives(db),
    )


@router.put("/settings", response_model=AutoWriteupStatus)
def put_settings(
    data: LlmSettingsUpdate,
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN)),
):
    old = finding_writeup.auto_daily_cap(db)
    app_settings.set_value(db, finding_writeup.AUTO_CAP_KEY, str(data.auto_writeups_daily_cap))
    audit.record_detail(request, auto_writeups_daily_cap={"from": old, "to": data.auto_writeups_daily_cap})
    return AutoWriteupStatus(daily_cap=finding_writeup.auto_daily_cap(db), today=finding_writeup.auto_count_today(db))


class WebClassificationSettingsUpdate(BaseModel):
    # An upper bound so a typo cannot authorise thousands of calls; the
    # global daily budget still bites first in practice.
    daily_cap: int = Field(ge=0, le=10000)


@router.put("/web-classification-settings", response_model=AutoWriteupStatus)
def put_web_classification_settings(
    data: WebClassificationSettingsUpdate,
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN)),
):
    """Set `ai.web_classifications.auto_daily_cap` (0 = off), audited old -> new."""
    old = web_classifier.auto_daily_cap(db)
    app_settings.set_value(db, web_classifier.AUTO_CAP_KEY, str(data.daily_cap))
    audit.record_detail(request, auto_web_classifications_daily_cap={"from": old, "to": data.daily_cap})
    return AutoWriteupStatus(
        daily_cap=web_classifier.auto_daily_cap(db), today=web_classifier.auto_count_today(db),
    )


class ChatSettingsUpdate(BaseModel):
    transcript_retention_days: int = Field(ge=1, le=chat.MAX_RETENTION_DAYS)


class ChatSettings(BaseModel):
    transcript_retention_days: int


@router.put("/chat-settings", response_model=ChatSettings)
def put_chat_settings(
    data: ChatSettingsUpdate,
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN)),
):
    old = chat.retention_days(db)
    app_settings.set_value(db, chat.RETENTION_KEY, str(data.transcript_retention_days))
    audit.record_detail(request, chat_transcript_retention_days={"from": old, "to": data.transcript_retention_days})
    return ChatSettings(transcript_retention_days=chat.retention_days(db))


class DigestSettingsUpdate(BaseModel):
    # An upper bound so a typo cannot authorise thousands of calls; the
    # global daily budget still bites first in practice.
    narrative_daily_cap: int = Field(ge=0, le=1000)


@router.put("/digest-settings", response_model=AutoWriteupStatus)
def put_digest_settings(
    data: DigestSettingsUpdate,
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN)),
):
    """Set `ai.digests.narrative_daily_cap` (0 = off), audited old -> new."""
    old = digest.narrative_daily_cap(db)
    app_settings.set_value(db, digest.NARRATIVE_CAP_KEY, str(data.narrative_daily_cap))
    audit.record_detail(request, digest_narrative_daily_cap={"from": old, "to": data.narrative_daily_cap})
    return _digest_narratives(db)
