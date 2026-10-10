"""Admin API for LLM model configuration (planning#224 items 1, 3).

Two concerns, both ADMIN-only:

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
  The admin page (item 2, a later slice) reads these; exposing them now
  keeps the UI PR pure-frontend.

Deferred to the UI PR (item 5): removing the model ids from
`app_settings.DEFAULTS` and the "configure AI models" empty state. Until
then a fresh install still has a working default binding, and this PUT only
ever overwrites it.
"""

import json

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ValidationError
from sqlalchemy.orm import Session

from app.api.deps import require_role
from app.core.database import get_db
from app.models.user import UserRole
from app.services import app_settings, audit, llm_connector
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
    bindings: dict[str, dict]


class AllowedModelsResponse(BaseModel):
    fetched_at: str | None
    models: list[dict]


def _load_bindings_or_409(db: Session) -> dict[str, dict]:
    try:
        bindings = llm_connector.load_bindings(db)
    except llm_connector.LLMConfigError as exc:
        # The stored value is corrupt/incomplete — surface it so the admin
        # can fix it, rather than 500ing.
        raise HTTPException(status_code=409, detail=str(exc))
    return {role.value: binding.model_dump() for role, binding in bindings.items()}


@router.get("/role-bindings", response_model=RoleBindingsResponse)
def get_role_bindings(
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN)),
):
    return RoleBindingsResponse(bindings=_load_bindings_or_409(db))


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
    # the stored/default value raw so a currently-corrupt binding is still
    # recorded as what it was, not an exception.
    old_raw = app_settings.get(db, "llm.role_bindings")
    try:
        old_parsed = json.loads(old_raw) if old_raw else None
    except json.JSONDecodeError:
        old_parsed = {"_unparseable": True}

    app_settings.set_value(db, "llm.role_bindings", json.dumps(validated))

    audit.record_detail(request, role_bindings={"from": old_parsed, "to": validated})
    return RoleBindingsResponse(bindings=_load_bindings_or_409(db))


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
