"""app.services.llm_connector — the OpenRouter connector, its ledger, its
data policy (planning#140 slice 1).

Constellus's first AI code. Callers ask for a ROLE (`Role` below), never a
model name; `app_settings` key `llm.role_bindings` binds each role to an
ordered model ladder. Modelled on `app.services.shared_infra_verifier`'s
shape — an explicit `db: Session` argument on every entry point, no hidden
global state beyond the injectable transport/sleep/clock hooks tests need
(see "Testability" below) — rather than on `app.connectors.base`'s
`EnrichmentConnector`: this is a plain service any future caller reaches
directly, not a phase of the scan pipeline. `app.connectors.openrouter`
exists ONLY for the admin UI's enable/configure/test card; it does not
implement inference itself.

## What this slice deliberately does NOT build

No agentic research loop, no tool calling, no web-search/plugins, no job
queue (planning#134 — `LLMRateLimited` is written the way it is, raising
rather than escalating, specifically so a future queue can reschedule the
call instead of burning another model's budget), and no per-engagement
spend cap (planning#140 slice 2 rolls spend up per engagement in
`spend_summary`'s `by_engagement`, but the global daily budget stays the
only limit — see that function). It stops at the connector + ledger.

## Data policy is derived from the resolved engagement (planning#140 slice 2)

`effective_data_policy` takes the `Engagement` that `_resolve_scope`
resolved for this call (`None` when the call is unscoped) and returns
`"strict"` iff `settings.llm_data_policy == "strict"` or
`posture.posture_restricts(engagement.posture if engagement else None)` —
the SAME predicate `app.services.posture` exports for every other
posture-gated caller in this codebase (R3: there is no second rendering of
"is this restricted" anywhere in this module). `_precall` resolves scope
exactly once per call (`_resolve_scope`, below); `passive_only` and the
effective policy both come from that one resolved engagement, never from a
second lookup or a different predicate.

## R1 — no silent fallback to a non-compliant endpoint

EVERY request body this module sends carries a `provider` block computed by
`effective_data_policy` + `_provider_block` — including every inline retry
and every escalation to a fallback model. There is no code path that
resends a request with a relaxed `provider` block. When no compliant
endpoint exists across the whole bound model ladder, this module either
raises `NoCompliantEndpoint` (every attempt was OpenRouter's own 404 "no
endpoint satisfies zdr/data_collection/require_parameters") or
`LLMUpstreamError`/`StructuredOutputFailed` (some other failure occurred) —
it never quietly serves the request from a laxer policy.

## R8 — strict never reaches web search (planning#215 rule 4)

ZDR covers inference routing only. OpenRouter runs a web search when a
slug carries the `:online` variant, or when the body carries `plugins` or
`web_search_options`, and that search sends the query to a party ZDR never
covers, and with the query the deal interest. So under `strict`:

- `_precall` refuses the WHOLE call (`StrictPolicyRefused`: zero requests,
  no ledger row, same as any other `LLMConfigError`) when ANY model the
  call could reach is an `:online` slug. A clean primary does not excuse
  an `:online` fallback: the ladder would reach it on the first 5xx.
- `_attempt_model` re-checks the body it is about to send (slug AND keys)
  as a backstop, so a future caller that adds `plugins` cannot skip the
  first check.

`dev_permissive` sends `:online` slugs unchanged: post-close research may
search. ⚠ This covers only the variant and the two keys. Models that search
natively whatever the request says (search-native model families,
`openrouter/auto` routing to one) are NOT caught here.

## R2 — the structurer is a transformer, never a source

`structured()`'s tier-1/tier-2 split (see "The three-tier ladder" below)
exists to make structuring cheap to retry, not to let a structuring model
invent facts. Whenever a grounding span exists, every `Grounded` field in
the parsed result must be supported by that span
(`app.services.llm_grounding.check_grounding`) — an ungrounded result is a
failed attempt (`ungrounded` ledger status), never a partially accepted
one.

## R4 — the ledger never stores prompt or response content

Not the messages, not the output, not a hash of either. `error_detail` is
the upstream error MESSAGE only, truncated to 2000 chars. A pre-close query
leaks deal intent if the ledger ever recorded what was asked; the ledger is
high-volume telemetry with long retention (`app_settings` key
`llm_ledger_retention_days`, default 400 days — see `prune_ledger`), which
is precisely the profile a leak would be worst under.

## The three-tier ladder (`structured()`)

For each model in the role's binding, in order (first model = tiers 1-2,
every later model = tier 3):

  - Tier 1 (first model only): native constrained decoding — the request
    carries `response_format` (JSON Schema, `strict: true`) and
    `provider.require_parameters = true`, which is OpenRouter's own
    endpoint pinning (routes only to endpoints that support every
    parameter in the request; there is no client-side capability probe and
    no pin list here). Parse -> validate -> ground. Pass -> return.
  - Tier 2 (first model only, on a tier-1 validation/grounding failure):
    split structuring — ONE request to the `extract` binding's PRIMARY
    model (always the primary; escalation across models is tier 3's job,
    not tier 2's), asking it to convert the tier-1 raw content into the
    schema using only what that text states. This is retry economics: with
    one model doing generation and structuring, a parse failure discards
    the whole (potentially ~150k-token) generation; splitting means only
    the short structuring call re-runs against text already in hand.
  - Tier 3 (every model after the first): repeat tier 1 (+ tier 2 on
    failure) against the next bound model.

`complete()` has no ladder beyond model fallback — it is tier 1 only,
because there is no structured output to validate or split-repair.

## Testability — the injectable seams

`_transport` (an `httpx.BaseTransport | None`, used as
`httpx.Client(transport=_transport, ...)`), `_sleep` (defaults to
`time.sleep`) and `_now` (defaults to `datetime.now(timezone.utc)`) are
module-level so tests can substitute `httpx.MockTransport` and control
time/backoff without ever touching the network (R7). `llm_connector` is
registered in `app/tests/conftest.py`'s `_GUARDED_MODULES` so a raw-
assignment monkeypatch of any of these (or of `_free_model_window`,
reassigned wholesale rather than mutated) is restored between tests.
"""

from __future__ import annotations

import json
import logging
import random
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum
from typing import Annotated, Any, Generic, Literal, TypeVar

import httpx
from pydantic import BaseModel, Field, StringConstraints, ValidationError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import SessionLocal
from app.models.engagement import Engagement
from app.models.llm_call import LlmCall
from app.models.target import Target
from app.services import app_settings, connector_config, posture
from app.services.llm_grounding import check_grounding

log = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

_CONNECTOR_ID = "openrouter"
_CHAT_COMPLETIONS_URL = "https://openrouter.ai/api/v1/chat/completions"

# OpenRouter passes provider rates through without markup but charges 5.5%
# on card credit purchases ($0.80 minimum per purchase — the per-purchase
# minimum is not modelled here). `cost_usd` in the ledger is the RAW
# vendor cost; the budget check and `spend_summary` gross it up by this
# rate to approximate what a day's usage actually costs us in real dollars.
OPENROUTER_CREDIT_FEE_RATE = Decimal("0.055")

# OpenRouter's platform-level rate cap applies ONLY to `:free` model
# variants ("switch to the paid variant of the model, which has no
# platform-level request cap" — OpenRouter limits doc, verified
# 2026-09-23). Paid models get no client-side cap from this module.
FREE_MODEL_RPM = 20

_CONNECT_TIMEOUT_S = 10.0
_READ_TIMEOUT_S = 120.0

_MAX_5XX_RETRIES = 2
_MAX_429_RETRIES = 3
_MAX_INLINE_WAIT_S = 30.0

_TIER2_SYSTEM_PROMPT = (
    "Convert the text below into the schema. Use only information stated "
    "in the text. For each field that must be grounded, copy the "
    "supporting words verbatim into its quote. If the text does not state "
    "a value, use null."
)

# ── injectable seams (see module docstring's "Testability") ────────────────
_transport: httpx.BaseTransport | None = None
_sleep = time.sleep
_now = lambda: datetime.now(timezone.utc)  # noqa: E731

_free_model_lock = threading.Lock()
_free_model_window: list[datetime] = []


# ── roles and bindings ──────────────────────────────────────────────────────

class Role(str, Enum):
    RESEARCH = "research"
    EXTRACT = "extract"
    CLASSIFY = "classify"
    JUDGE = "judge"
    NARRATE = "narrate"


class RoleBinding(BaseModel):
    # Non-empty, no whitespace: an OpenRouter slug never has either, and a
    # padded " x/y:online " would otherwise slip past R8's variant check.
    models: list[Annotated[str, StringConstraints(pattern=r"^\S+$")]] = Field(min_length=1)
    max_tokens: int = Field(gt=0)
    temperature: float = Field(ge=0, le=2)


def load_bindings(db: Session) -> dict[Role, RoleBinding]:
    """Parse `app_settings['llm.role_bindings']` into one `RoleBinding` per
    `Role`. Raises `LLMConfigError` naming the key and the role on a
    value that fails to parse, or a stored value missing a role — this
    NEVER silently falls back to `app_settings.DEFAULTS`'s value once a
    value has been stored: a typo in a saved binding must not quietly
    route a role to a different model set. If the key has never been set
    at all, `app_settings.get` already returns the default itself."""
    raw = app_settings.get(db, "llm.role_bindings")
    try:
        parsed = json.loads(raw) if raw is not None else {}
    except json.JSONDecodeError as exc:
        raise LLMConfigError(
            f"app_settings['llm.role_bindings'] is not valid JSON: {exc}"
        ) from exc

    bindings: dict[Role, RoleBinding] = {}
    for role in Role:
        entry = parsed.get(role.value)
        if entry is None:
            raise LLMConfigError(
                f"app_settings['llm.role_bindings'] is missing role {role.value!r}"
            )
        try:
            bindings[role] = RoleBinding.model_validate(entry)
        except ValidationError as exc:
            raise LLMConfigError(
                f"app_settings['llm.role_bindings'][{role.value!r}] is invalid: {exc}"
            ) from exc
    return bindings


# ── exceptions ───────────────────────────────────────────────────────────────

class LLMError(Exception):
    """Base class for every exception this module raises."""


class LLMNotConfigured(LLMError):
    """The `openrouter` connector row is missing, disabled, or has no
    stored API key (R5) — or OpenRouter itself rejected the key
    (401/403)."""


class LLMConfigError(LLMError):
    """A stored configuration value (role bindings, or a `target_id` that
    does not resolve to a real `targets` row) is unusable."""


class StrictPolicyRefused(LLMConfigError):
    """R8: under `strict`, the call could reach an `:online` slug, or a
    body about to be sent carries a web-search key. Refused before any
    request. The binding is the config error here, which is why this
    subclasses `LLMConfigError`."""

    def __init__(self, role: str, reason: str) -> None:
        super().__init__(f"Refused under strict data policy for role={role!r}: {reason}")
        self.role = role
        self.reason = reason


class LLMBudgetExhausted(LLMError):
    """Today's grossed-up spend has met or exceeded `app_settings
    ['llm.daily_budget_usd']`, or OpenRouter itself refused the request on
    cost grounds (HTTP 402, reason other than in-flight budget)."""


class LLMRateLimited(LLMError):
    """OpenRouter rate-limited every inline retry attempted, or handed
    back a `Retry-After` longer than this module will ever wait inline.
    Deliberately NOT escalated to another model — see the module
    docstring's `complete()`/model-fallback section and this module's
    "queue-aware" framing: planning#134's future queue is meant to
    reschedule the job against the SAME model/budget rather than this
    module silently burning a different model's rate limit instead."""

    def __init__(self, message: str, retry_after_s: float | None) -> None:
        super().__init__(message)
        self.retry_after_s = retry_after_s


class NoCompliantEndpoint(LLMError):
    """Every bound model, under the effective data policy, returned
    OpenRouter's 404 "no endpoint satisfies the routing constraints" —
    zdr/data_collection/require_parameters. There is nothing this module
    can silently relax to satisfy the request instead (R1)."""

    def __init__(self, role: str, policy: str, attempted_models: list[str]) -> None:
        message = (
            f"No compliant OpenRouter endpoint for role={role!r} under "
            f"data policy {policy!r} — every bound model returned no "
            f"eligible endpoint: {attempted_models}"
        )
        super().__init__(message)
        self.role = role
        self.policy = policy
        self.attempted_models = attempted_models


class StructuredOutputFailed(LLMError):
    """Every bound model failed to produce a valid, grounded structured
    result (tier 1 and, where reached, tier 2)."""

    def __init__(self, role: str, attempts: list[str]) -> None:
        message = f"Structured output failed for role={role!r}: " + "; ".join(attempts)
        super().__init__(message)
        self.role = role
        self.attempts = attempts


class LLMUpstreamError(LLMError):
    """Every bound model was exhausted by a mix of upstream/transport
    failures (not exclusively `no_eligible_endpoint`, or `structured()`
    would have raised `StructuredOutputFailed`/`NoCompliantEndpoint`
    instead)."""


# ── public result types ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class Completion:
    text: str
    model: str
    provider: str | None
    generation_id: str | None
    tier: int
    ledger_ids: list[int]


@dataclass(frozen=True)
class StructuredResult(Generic[T]):
    """`grounding` is about the CALLER'S `source_text`, nothing else:
    "verified" = every `Grounded` field's value appears (normalised) in a
    quote that appears in `source_text`; "not_applicable" = no source_text
    was given, so no claim in `value` is sourced, whatever tier produced it.

    ⚠ "verified" proves the value's STRING occurs in the source. It does not
    prove the source asserts the RELATION the schema names - a company
    mentioned as a competitor passes as a `subsidiaries[i].name`. That is a
    judgment, not a substring test (a candidate for a calibrated `classify`
    call later - see the Jev evaluation on planning#140). Treat "verified"
    as "not invented", not as "true"."""

    value: T
    grounding: Literal["verified", "not_applicable"]
    model: str
    provider: str | None
    generation_id: str | None
    tier: int
    ledger_ids: list[int]


# ── data policy ──────────────────────────────────────────────────────────────

def effective_data_policy(engagement: Engagement | None) -> str:
    """`"strict"` if `settings.llm_data_policy == "strict"` OR the resolved
    engagement's posture restricts traffic to passive-only
    (`posture.posture_restricts`, `None` reads as "no engagement, nothing
    to restrict") — dev_permissive is never enough on its own to relax a
    restricted engagement (R3). Otherwise `"dev_permissive"`. `engagement`
    is whatever `_resolve_scope` resolved for this call; see the module
    docstring's "Data policy is derived from the resolved engagement"
    section."""
    restricts = posture.posture_restricts(engagement.posture if engagement is not None else None)
    if settings.llm_data_policy == "strict" or restricts:
        return "strict"
    return "dev_permissive"


def _provider_block(policy: str, *, require_parameters: bool = False) -> dict[str, Any]:
    """R1: this is the ONLY place a `provider` block is built. strict never
    omits `zdr`/`data_collection: deny`; dev_permissive never SENDS `zdr`
    at all (not `zdr: false` — simply absent). `allow_fallbacks: True`
    lets OpenRouter try other PROVIDERS of the same model (still filtered
    server-side by zdr/data_collection) — MODEL fallback stays ours alone;
    `models` is never sent."""
    if policy == "strict":
        block: dict[str, Any] = {"zdr": True, "data_collection": "deny", "allow_fallbacks": True}
    else:
        block = {"data_collection": "allow", "allow_fallbacks": True}
    if require_parameters:
        block["require_parameters"] = True
    return block


# R8. Body keys that make OpenRouter run a web search for the request.
_WEB_SEARCH_BODY_KEYS = ("plugins", "web_search_options")


def _slug_enables_web_search(slug: str) -> bool:
    """True when the slug carries OpenRouter's `:online` variant, anywhere
    in its variant chain and in any case. A `:` in the vendor part (before
    the `/`) is not a variant."""
    _, _, model_part = slug.partition("/")
    return "online" in (v.strip().lower() for v in model_part.split(":")[1:])


def _refuse_web_search(policy: str, role: Role, *, models: list[str], body: dict[str, Any] | None = None) -> None:
    """R8's one check, used both before the call (`models` = every model it
    can reach) and before each send (`body`). Does nothing unless strict."""
    if policy != "strict":
        return
    online = [m for m in models if _slug_enables_web_search(m)]
    if online:
        raise StrictPolicyRefused(role.value, f"`:online` slug(s) would run a web search: {online}")
    keys = [k for k in _WEB_SEARCH_BODY_KEYS if body is not None and k in body]
    if keys:
        raise StrictPolicyRefused(role.value, f"request body carries web-search key(s): {keys}")
    # The third way OpenRouter enables search: a `tools` entry for its
    # `openrouter:web_search` server tool. Matched on the substring so a
    # renamed or versioned variant of the tool is refused too.
    tools = (body or {}).get("tools") or []
    search_tools = [t for t in tools if "web_search" in str((t or {}).get("type", "")).lower()]
    if search_tools:
        raise StrictPolicyRefused(role.value, f"request body carries a web-search server tool: {search_tools}")


def _response_format(schema: type[BaseModel]) -> dict[str, Any]:
    return {
        "type": "json_schema",
        "json_schema": {
            "name": schema.__name__,
            "strict": True,
            "schema": schema.model_json_schema(),
        },
    }


def _headers(api_key: str) -> dict[str, str]:
    # X-Title is OpenRouter's optional app-attribution header. HTTP-Referer
    # (its sibling) is deliberately NOT sent: it expects a URL, and there is
    # no deployment URL this module can know that is not invented.
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "X-Title": "Constellus",
    }


# ── ledger ───────────────────────────────────────────────────────────────────

def _write_ledger(
    *,
    role: str,
    task: str,
    target_id: uuid.UUID | None,
    engagement_id: uuid.UUID | None,
    passive_only: bool,
    data_policy: str,
    requested_model: str,
    tier: int,
    attempt: int,
    status: str,
    served_model: str | None = None,
    provider: str | None = None,
    generation_id: str | None = None,
    prompt_tokens: int | None = None,
    completion_tokens: int | None = None,
    cached_tokens: int | None = None,
    cost_usd: Decimal | None = None,
    latency_ms: int | None = None,
    error_detail: str | None = None,
    ungrounded_fields: list[str] | None = None,
) -> int:
    """Write ONE ledger row and return its id. Uses a SEPARATE `SessionLocal()`
    session, committed and closed here regardless of what the caller's own
    session later does — spend that happened must stay recorded even if the
    caller's session later rolls back (see module docstring / R4)."""
    session = SessionLocal()
    try:
        row = LlmCall(
            role=role,
            task=task,
            target_id=target_id,
            engagement_id=engagement_id,
            passive_only=passive_only,
            data_policy=data_policy,
            requested_model=requested_model,
            served_model=served_model,
            provider=provider,
            generation_id=generation_id,
            tier=tier,
            attempt=attempt,
            status=status,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cached_tokens=cached_tokens,
            cost_usd=cost_usd,
            latency_ms=latency_ms,
            error_detail=error_detail[:2000] if error_detail else None,
            ungrounded_fields=ungrounded_fields,
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        return row.id
    finally:
        session.close()


def prune_ledger(db: Session) -> int:
    """Delete `llm_calls` rows older than `app_settings
    ['llm_ledger_retention_days']` (default 400). Returns the number of
    rows deleted. Registered as a daily job in `app.services.scheduler`."""
    retention_days = app_settings.get_int(db, "llm_ledger_retention_days") or 400
    cutoff = _now() - timedelta(days=retention_days)
    deleted = db.query(LlmCall).filter(LlmCall.created_at < cutoff).delete(synchronize_session=False)
    db.commit()
    return deleted


def spend_summary(db: Session, *, since: datetime, until: datetime) -> dict[str, Any]:
    """Aggregate RAW (not grossed-up) spend over `[since, until)`, plus the
    fee rate and gross total, broken down by role/model/task/engagement, and
    the passive-only-target subtotal. Read-side only — no API endpoint yet;
    the `by_engagement` roll-up (planning#140 slice 2) now exists, but
    whether/how spend is exposed in the UI is still an open decision."""
    from sqlalchemy import func

    window = (LlmCall.created_at >= since, LlmCall.created_at < until)

    raw_usd = Decimal(str(db.query(func.coalesce(func.sum(LlmCall.cost_usd), 0)).filter(*window).scalar()))
    calls = db.query(func.count(LlmCall.id)).filter(*window).scalar() or 0

    by_role = {
        role: Decimal(str(total))
        for role, total in db.query(LlmCall.role, func.coalesce(func.sum(LlmCall.cost_usd), 0))
        .filter(*window).group_by(LlmCall.role).all()
    }

    model_col = func.coalesce(LlmCall.served_model, LlmCall.requested_model)
    by_model = {
        model: Decimal(str(total))
        for model, total in db.query(model_col, func.coalesce(func.sum(LlmCall.cost_usd), 0))
        .filter(*window).group_by(model_col).all()
    }

    by_task = {
        task: Decimal(str(total))
        for task, total in db.query(LlmCall.task, func.coalesce(func.sum(LlmCall.cost_usd), 0))
        .filter(*window).group_by(LlmCall.task).all()
    }

    # Keyed by `str(uuid)` for a scoped row, Python `None` (not the string
    # "None") for the unscoped bucket — `LlmCall.engagement_id` itself is
    # `NULL` for those rows, and `group_by` already groups all of them
    # together under that one `NULL` key.
    by_engagement = {
        (str(engagement_id) if engagement_id is not None else None): Decimal(str(total))
        for engagement_id, total in db.query(LlmCall.engagement_id, func.coalesce(func.sum(LlmCall.cost_usd), 0))
        .filter(*window).group_by(LlmCall.engagement_id).all()
    }

    passive_only_raw_usd = Decimal(str(
        db.query(func.coalesce(func.sum(LlmCall.cost_usd), 0))
        .filter(*window, LlmCall.passive_only == True)  # noqa: E712
        .scalar()
    ))

    return {
        "raw_usd": raw_usd,
        "fee_rate": OPENROUTER_CREDIT_FEE_RATE,
        "gross_usd": raw_usd * (1 + OPENROUTER_CREDIT_FEE_RATE),
        "calls": calls,
        "by_role": by_role,
        "by_model": by_model,
        "by_task": by_task,
        "by_engagement": by_engagement,
        "passive_only_raw_usd": passive_only_raw_usd,
    }


def _grossed_up_spend_today(db: Session) -> Decimal:
    from sqlalchemy import func

    today_start = _now().replace(hour=0, minute=0, second=0, microsecond=0)
    raw = Decimal(str(
        db.query(func.coalesce(func.sum(LlmCall.cost_usd), 0))
        .filter(LlmCall.created_at >= today_start)
        .scalar()
    ))
    return raw * (1 + OPENROUTER_CREDIT_FEE_RATE)


# ── scope resolution ─────────────────────────────────────────────────────────

def _resolve_scope(
    db: Session, *, target_id: uuid.UUID | None, engagement_id: uuid.UUID | None,
) -> Engagement | None:
    """Resolve the `Engagement` in scope for this call, per the table in
    planning#140 slice 2's spec:

    | target_id | engagement_id | result                                   |
    |-----------|----------------|------------------------------------------|
    | None      | None           | `None` (unscoped)                        |
    | set       | None           | `target.engagement` (may itself be `None`)|
    | None      | set            | the `Engagement` row                     |
    | set       | set            | target's `engagement_id` must EQUAL the given `engagement_id` |

    A `target_id` that does not resolve to a `targets` row, or an
    `engagement_id` that does not resolve to an `engagements` row, is an
    `LLMConfigError` — never silently treated as unscoped (R6, the same
    discipline the old target-only check already applied). A target/
    engagement_id PAIR that disagree is ALSO an `LLMConfigError`: a mismatch
    is scope confusion, and either side might be the one holding the
    restricting posture, so there is no safe default to fall back to.
    Raised before any ledger row or HTTP request, same as every other
    `LLMConfigError` this module raises.

    Why `engagement_id` without a `target_id` exists: the #215 research
    loop works on an engagement's subject before any `targets` row exists.
    That is the reason, and there is no caller yet.
    """
    if target_id is None:
        if engagement_id is None:
            return None
        engagement_row = db.get(Engagement, engagement_id)
        if engagement_row is None:
            raise LLMConfigError(f"engagement_id={engagement_id} does not resolve to an engagements row")
        return engagement_row

    target_row = db.get(Target, target_id)
    if target_row is None:
        raise LLMConfigError(f"target_id={target_id} does not resolve to a targets row")

    if engagement_id is None:
        return target_row.engagement

    if target_row.engagement_id != engagement_id:
        raise LLMConfigError(
            f"target_id={target_id} belongs to engagement_id={target_row.engagement_id!r}, "
            f"which does not match the given engagement_id={engagement_id!r}"
        )
    return target_row.engagement


# ── pre-call ─────────────────────────────────────────────────────────────────

def _precall(
    db: Session, *, role: Role, target_id: uuid.UUID | None, engagement_id: uuid.UUID | None, task: str,
    uses_extract: bool,
) -> tuple[str, dict[Role, RoleBinding], bool, str, uuid.UUID | None]:
    """Everything §5's "Pre-call, once per public call" section requires,
    shared by `complete()` and `structured()`. Returns
    (api_key, bindings, passive_only, effective_policy, resolved_engagement_id)."""
    bindings = load_bindings(db)  # LLMConfigError propagates untouched — zero requests, no ledger row.
    primary_model = bindings[role].models[0]

    # 1. Resolve scope + effective policy FIRST, before any ledger row can
    # be written: every row snapshots `passive_only`/`data_policy`/
    # `engagement_id`, and a `not_configured` row written ahead of this
    # would record a restricted engagement as `passive_only=False` under
    # whatever the env var says - a false record in the one table
    # spend-by-posture is read from. `_resolve_scope` raises `LLMConfigError`
    # for an unresolvable target_id/engagement_id or a mismatched pair,
    # never treats either as unscoped (R6).
    # `passive_only` and `policy` both derive from this ONE resolved
    # `engagement_row` via the same `posture.posture_restricts` (R3).
    engagement_row = _resolve_scope(db, target_id=target_id, engagement_id=engagement_id)
    resolved_engagement_id = engagement_row.id if engagement_row is not None else None
    passive_only = posture.posture_restricts(engagement_row.posture if engagement_row is not None else None)
    policy = effective_data_policy(engagement_row)

    # 1b. R8, before anything else can happen: every model this call can
    # reach, fallbacks included, plus the extract primary when `structured()`
    # may run tier 2 on it.
    reachable = list(bindings[role].models)
    if uses_extract:
        reachable.append(bindings[Role.EXTRACT].models[0])
    _refuse_web_search(policy, role, models=reachable)

    # 2. Connector row + key (R5) — missing/disabled/empty key -> not_configured.
    row = connector_config.get_one(db, _CONNECTOR_ID)
    api_key = None
    if row is not None and row.enabled:
        api_key = connector_config.get_decrypted_config(db, _CONNECTOR_ID).get("api_key")
    if not api_key:
        _write_ledger(
            role=role.value, task=task, target_id=target_id, engagement_id=resolved_engagement_id,
            passive_only=passive_only, data_policy=policy, requested_model=primary_model,
            tier=1, attempt=1, status="not_configured",
        )
        raise LLMNotConfigured(
            f"OpenRouter connector is not configured, disabled, or has no stored API "
            f"key (role={role.value!r})"
        )

    # 3. Budget — checked ONCE before the call starts, not between attempts;
    # a call already in progress may finish even if it pushes spend over
    # the line mid-flight.
    budget = Decimal(app_settings.get(db, "llm.daily_budget_usd") or "5")
    gross = _grossed_up_spend_today(db)
    if gross >= budget:
        _write_ledger(
            role=role.value, task=task, target_id=target_id, engagement_id=resolved_engagement_id,
            passive_only=passive_only, data_policy=policy, requested_model=primary_model, tier=1, attempt=1,
            status="budget_refused",
        )
        raise LLMBudgetExhausted(
            f"Daily LLM budget exhausted for role={role.value!r}: grossed-up spend "
            f"{gross} >= budget {budget}"
        )

    return api_key, bindings, passive_only, policy, resolved_engagement_id


# ── HTTP attempt (one model, with its own inline retries) ──────────────────

def _backoff_seconds(attempt_in_model: int) -> float:
    base = min(2 ** (attempt_in_model - 1), 4)  # 1, 2, 4, capped
    return base + random.uniform(0, 0.5)


def _rate_limit_free_model(model: str) -> None:
    """Process-wide sliding window, `:free` model ids only (FREE_MODEL_RPM
    per 60s across all threads) — see module docstring. Paid models are
    never throttled here."""
    if not model.endswith(":free"):
        return
    with _free_model_lock:
        while True:
            now = _now()
            cutoff = now - timedelta(seconds=60)
            # `<=`, not `<`: an entry exactly 60s old must age out of the
            # window. With `<`, a caller whose `_sleep` advances `_now` by
            # EXACTLY the computed wait (as a deterministic test double
            # does — real wall-clock time never lands on the boundary
            # exactly) leaves that entry permanently equal to `cutoff`,
            # recomputes the same zero-second wait forever, and spins.
            while _free_model_window and _free_model_window[0] <= cutoff:
                _free_model_window.pop(0)
            if len(_free_model_window) < FREE_MODEL_RPM:
                _free_model_window.append(now)
                return
            wait_s = max(0.0, (_free_model_window[0] + timedelta(seconds=60) - now).total_seconds())
            _sleep(wait_s)


def _safe_json(resp: httpx.Response) -> dict | None:
    try:
        return resp.json()
    except ValueError:
        return None


def _error_message(resp: httpx.Response) -> str:
    data = _safe_json(resp)
    if data is not None:
        error = data.get("error")
        if isinstance(error, dict) and error.get("message"):
            return str(error["message"])
        if isinstance(error, str) and error:
            return error
    return f"HTTP {resp.status_code}: {resp.text[:500]}"


def _parse_retry_after(resp: httpx.Response) -> float | None:
    raw = resp.headers.get("Retry-After")
    if raw is None:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


def _usage_fields(resp_json: dict) -> dict[str, Any]:
    usage = resp_json.get("usage") or {}
    details = usage.get("prompt_tokens_details") or {}
    cost = usage.get("cost")
    return {
        "prompt_tokens": usage.get("prompt_tokens"),
        "completion_tokens": usage.get("completion_tokens"),
        "cached_tokens": details.get("cached_tokens"),
        "cost_usd": Decimal(str(cost)) if cost is not None else None,
    }


def _attempt_model(
    db: Session,
    *,
    api_key: str,
    body: dict[str, Any],
    model: str,
    role: Role,
    task: str,
    target_id: uuid.UUID | None,
    engagement_id: uuid.UUID | None,
    passive_only: bool,
    policy: str,
    tier: int,
    ledger_ids: list[int],
    attempt_counter: list[int],
) -> dict[str, Any]:
    """Send `body` to `model`, retrying inline per the response/error
    handling rules (§5.1). Writes a ledger row for every HTTP attempt
    EXCEPT a raw 200 success — that one row is the CALLER's to write, once
    it knows (for `structured()`) whether the parsed body actually
    validated/grounded. `attempt_counter` is a one-element list shared
    across this call's WHOLE ladder (every model, every tier) so `attempt`
    stays 1-based across all of it, not reset per model.

    Returns `{"status": "ok", "response_json": ..., "latency_ms": ...}` on
    raw 200 success, or `{"status": "no_eligible_endpoint" |
    "upstream_error" | "transport_error", "error_detail": ...}` once this
    MODEL's own attempts are exhausted (caller escalates to the next
    model). Raises `LLMRateLimited` / `LLMBudgetExhausted` /
    `LLMNotConfigured` directly on 429-exhausted / 402-other / 401/403 —
    those end the WHOLE call, never just this model: a rate limit, a
    billing refusal, or a rejected key is not fixed by trying a different
    model with the same account behind it.
    """
    _refuse_web_search(policy, role, models=[model, str(body.get("model", ""))], body=body)  # R8 backstop
    attempt_in_model = 0

    def _record(status: str, **fields: Any) -> int:
        attempt_counter[0] += 1
        row_id = _write_ledger(
            role=role.value, task=task, target_id=target_id, engagement_id=engagement_id,
            passive_only=passive_only, data_policy=policy, requested_model=model, tier=tier,
            attempt=attempt_counter[0], status=status, **fields,
        )
        ledger_ids.append(row_id)
        return row_id

    while True:
        _rate_limit_free_model(model)
        start = _now()
        try:
            with httpx.Client(
                transport=_transport,
                timeout=httpx.Timeout(connect=_CONNECT_TIMEOUT_S, read=_READ_TIMEOUT_S, write=_READ_TIMEOUT_S, pool=_READ_TIMEOUT_S),
            ) as client:
                resp = client.post(_CHAT_COMPLETIONS_URL, headers=_headers(api_key), json=body)
        except httpx.TransportError as exc:
            latency_ms = int((_now() - start).total_seconds() * 1000)
            attempt_in_model += 1
            _record("transport_error", error_detail=str(exc), latency_ms=latency_ms)
            if attempt_in_model <= _MAX_5XX_RETRIES:
                _sleep(_backoff_seconds(attempt_in_model))
                continue
            return {"status": "transport_error", "error_detail": str(exc)}

        latency_ms = int((_now() - start).total_seconds() * 1000)

        if resp.status_code == 200:
            data = _safe_json(resp) or {}
            choices = data.get("choices") or []
            first = choices[0] if choices and isinstance(choices[0], dict) else {}
            content = (first.get("message") or {}).get("content")
            # A 200 with no string content (no choices; `content: null` on a
            # refusal or a tool-call-only reply) is NOT a success: `complete()`
            # would index into nothing AFTER the spend happened, and
            # `structured()` would hand `None` to tier 2 as "text to structure".
            is_error = (
                bool(data.get("error"))
                or first.get("finish_reason") == "error"
                or not isinstance(content, str)
            )
            if is_error:
                attempt_in_model += 1
                # Deliberately NOT `_error_message(resp)` here (that
                # helper falls back to dumping raw response text, which on
                # a 200 could be the assistant's own message content — R4
                # forbids storing anything content-shaped in the ledger).
                error_obj = data.get("error")
                if isinstance(error_obj, dict) and error_obj.get("message"):
                    msg = str(error_obj["message"])
                elif isinstance(error_obj, str) and error_obj:
                    msg = error_obj
                else:
                    msg = (
                        f"200 without usable content: finish_reason={first.get('finish_reason')!r}, "
                        f"choices={len(choices)} (model={data.get('model')!r})"
                    )
                # Usage is recorded here too: a 200 that produced nothing
                # usable may still have been billed.
                _record(
                    "upstream_error", error_detail=msg, latency_ms=latency_ms,
                    served_model=data.get("model"), provider=data.get("provider"), generation_id=data.get("id"),
                    **_usage_fields(data),
                )
                return {"status": "upstream_error", "error_detail": msg}
            return {"status": "ok", "response_json": data, "latency_ms": latency_ms}

        if resp.status_code == 404:
            # Deterministic — OpenRouter returns 404 when no endpoint
            # satisfies the routing constraints (zdr/data_collection/
            # require_parameters). Never retried on the same model.
            msg = _error_message(resp)
            _record("no_eligible_endpoint", error_detail=msg, latency_ms=latency_ms)
            return {"status": "no_eligible_endpoint", "error_detail": msg}

        if resp.status_code == 429 or (resp.status_code == 402 and _is_in_flight_budget(resp)):
            retry_after = _parse_retry_after(resp)
            attempt_in_model += 1
            msg = _error_message(resp)
            _record("rate_limited", error_detail=msg, latency_ms=latency_ms)
            if (retry_after is not None and retry_after > _MAX_INLINE_WAIT_S) or attempt_in_model > _MAX_429_RETRIES:
                raise LLMRateLimited(
                    f"Rate limited on model={model!r} (role={role.value!r}): {msg}", retry_after,
                )
            _sleep(retry_after if retry_after is not None else _backoff_seconds(attempt_in_model))
            continue

        if resp.status_code == 402:
            msg = _error_message(resp)
            _record("budget_refused", error_detail=msg, latency_ms=latency_ms)
            raise LLMBudgetExhausted(f"OpenRouter refused model={model!r} on cost grounds: {msg}")

        if resp.status_code in (401, 403):
            msg = _error_message(resp)
            _record("upstream_error", error_detail=msg, latency_ms=latency_ms)
            raise LLMNotConfigured(f"OpenRouter rejected the API key (HTTP {resp.status_code}): {msg}")

        if resp.status_code >= 500:
            msg = _error_message(resp)
            attempt_in_model += 1
            _record("upstream_error", error_detail=msg, latency_ms=latency_ms)
            if attempt_in_model <= _MAX_5XX_RETRIES:
                _sleep(_backoff_seconds(attempt_in_model))
                continue
            return {"status": "upstream_error", "error_detail": msg}

        # Any other status — one ledger row, no retry, escalate.
        msg = _error_message(resp)
        _record("upstream_error", error_detail=msg, latency_ms=latency_ms)
        return {"status": "upstream_error", "error_detail": msg}


def _is_in_flight_budget(resp: httpx.Response) -> bool:
    data = _safe_json(resp) or {}
    error = data.get("error")
    if not isinstance(error, dict):
        return False
    return (error.get("metadata") or {}).get("reason") == "in_flight_budget_exhausted"


# ── structured-output validation + grounding ────────────────────────────────

def _validate_and_ground(
    raw_content: str, schema: type[BaseModel], span: str | None,
) -> tuple[BaseModel | None, str | None, list[str] | None, str]:
    """Returns (value, grounding_label, ungrounded_fields, ledger_status).
    `ledger_status` is one of "invalid_output" | "ungrounded" | "ok"."""
    try:
        payload = json.loads(raw_content)
        value = schema.model_validate(payload)
    except (json.JSONDecodeError, ValidationError, TypeError):
        return None, None, None, "invalid_output"

    if span is None:
        return value, "not_applicable", None, "ok"

    ungrounded_fields = check_grounding(value, span)
    if ungrounded_fields:
        return value, None, ungrounded_fields, "ungrounded"
    return value, "verified", None, "ok"


# ── public API ───────────────────────────────────────────────────────────────

def complete(
    db: Session, *, role: Role, messages: list[dict], target_id: uuid.UUID | None,
    engagement_id: uuid.UUID | None, task: str,
) -> Completion:
    """Tier 1 only — plain chat completion, model fallback across the
    role's bound ladder, no structured-output validation. `target_id` and
    `engagement_id` both have no default (R6): omitting either is a
    `TypeError`, not a silent unscoped call. See `_resolve_scope` for how
    the two combine."""
    api_key, bindings, passive_only, policy, resolved_engagement_id = _precall(
        db, role=role, target_id=target_id, engagement_id=engagement_id, task=task, uses_extract=False,
    )
    binding = bindings[role]

    ledger_ids: list[int] = []
    attempt_counter = [0]
    attempts: list[tuple[str, str]] = []

    for model_index, model in enumerate(binding.models):
        tier = 1 if model_index == 0 else 3
        body = {
            "model": model,
            "messages": messages,
            "max_tokens": binding.max_tokens,
            "temperature": binding.temperature,
            "usage": {"include": True},
            "provider": _provider_block(policy),
        }
        outcome = _attempt_model(
            db, api_key=api_key, body=body, model=model, role=role, task=task,
            target_id=target_id, engagement_id=resolved_engagement_id, passive_only=passive_only,
            policy=policy, tier=tier, ledger_ids=ledger_ids, attempt_counter=attempt_counter,
        )
        if outcome["status"] != "ok":
            attempts.append((model, outcome["status"]))
            continue

        resp_json = outcome["response_json"]
        attempt_counter[0] += 1
        row_id = _write_ledger(
            role=role.value, task=task, target_id=target_id, engagement_id=resolved_engagement_id,
            passive_only=passive_only, data_policy=policy, requested_model=model, tier=tier,
            attempt=attempt_counter[0], status="ok", served_model=resp_json.get("model"),
            provider=resp_json.get("provider"), generation_id=resp_json.get("id"),
            latency_ms=outcome.get("latency_ms"), **_usage_fields(resp_json),
        )
        ledger_ids.append(row_id)
        return Completion(
            text=resp_json["choices"][0]["message"]["content"],
            model=resp_json.get("model", model),
            provider=resp_json.get("provider"),
            generation_id=resp_json.get("id"),
            tier=tier,
            ledger_ids=ledger_ids,
        )

    if attempts and all(status == "no_eligible_endpoint" for _, status in attempts):
        raise NoCompliantEndpoint(role.value, policy, [m for m, _ in attempts])
    raise LLMUpstreamError(
        f"All bound models exhausted for role={role.value!r}: "
        + "; ".join(f"{m}:{s}" for m, s in attempts)
    )


def structured(
    db: Session, *, role: Role, messages: list[dict], schema: type[T], target_id: uuid.UUID | None,
    engagement_id: uuid.UUID | None, task: str, source_text: str | None,
) -> StructuredResult[T]:
    """The three-tier ladder — see module docstring. `target_id`,
    `engagement_id` and `source_text` all have no default (R6): a fact
    extraction that forgets its scope or its span must not silently become
    unscoped/"not_applicable". See `_resolve_scope` for how `target_id`
    and `engagement_id` combine."""
    api_key, bindings, passive_only, policy, resolved_engagement_id = _precall(
        db, role=role, target_id=target_id, engagement_id=engagement_id, task=task, uses_extract=True,
    )
    binding = bindings[role]
    extract_binding = bindings[Role.EXTRACT]
    extract_primary = extract_binding.models[0]

    ledger_ids: list[int] = []
    attempt_counter = [0]
    attempts: list[str] = []
    saw_non_404 = False

    for model_index, model in enumerate(binding.models):
        tier1 = 1 if model_index == 0 else 3
        tier2 = 2 if model_index == 0 else 3

        body1 = {
            "model": model,
            "messages": messages,
            "max_tokens": binding.max_tokens,
            "temperature": binding.temperature,
            "usage": {"include": True},
            "provider": _provider_block(policy, require_parameters=True),
            "response_format": _response_format(schema),
        }
        outcome1 = _attempt_model(
            db, api_key=api_key, body=body1, model=model, role=role, task=task,
            target_id=target_id, engagement_id=resolved_engagement_id, passive_only=passive_only,
            policy=policy, tier=tier1, ledger_ids=ledger_ids, attempt_counter=attempt_counter,
        )
        if outcome1["status"] != "ok":
            attempts.append(f"{model} tier{tier1}: {outcome1['status']}")
            if outcome1["status"] != "no_eligible_endpoint":
                saw_non_404 = True
            continue  # nothing came back at all — skip tier 2, next model

        resp1 = outcome1["response_json"]
        raw1 = resp1["choices"][0]["message"]["content"]
        value1, ground1, ungrounded1, status1 = _validate_and_ground(raw1, schema, source_text)

        attempt_counter[0] += 1
        row1_id = _write_ledger(
            role=role.value, task=task, target_id=target_id, engagement_id=resolved_engagement_id,
            passive_only=passive_only, data_policy=policy, requested_model=model, tier=tier1,
            attempt=attempt_counter[0], status=status1, served_model=resp1.get("model"),
            provider=resp1.get("provider"), generation_id=resp1.get("id"),
            latency_ms=outcome1.get("latency_ms"), ungrounded_fields=ungrounded1, **_usage_fields(resp1),
        )
        ledger_ids.append(row1_id)
        saw_non_404 = True

        if status1 == "ok":
            return StructuredResult(
                value=value1, grounding=ground1, model=resp1.get("model", model),
                provider=resp1.get("provider"), generation_id=resp1.get("id"), tier=tier1,
                ledger_ids=ledger_ids,
            )
        attempts.append(f"{model} tier{tier1}: {status1}")

        # Tier 2 — split structuring, always against the extract binding's
        # PRIMARY model (never escalated across models; tier 3 is model
        # fallback's job).
        span2 = source_text if source_text is not None else raw1
        body2 = {
            "model": extract_primary,
            "messages": [
                {"role": "system", "content": _TIER2_SYSTEM_PROMPT},
                {"role": "user", "content": raw1},
            ],
            "max_tokens": extract_binding.max_tokens,
            "temperature": extract_binding.temperature,
            "usage": {"include": True},
            "provider": _provider_block(policy, require_parameters=True),
            "response_format": _response_format(schema),
        }
        outcome2 = _attempt_model(
            db, api_key=api_key, body=body2, model=extract_primary, role=role, task=task,
            target_id=target_id, engagement_id=resolved_engagement_id, passive_only=passive_only,
            policy=policy, tier=tier2, ledger_ids=ledger_ids, attempt_counter=attempt_counter,
        )
        if outcome2["status"] != "ok":
            attempts.append(f"{extract_primary} tier{tier2}: {outcome2['status']}")
            if outcome2["status"] != "no_eligible_endpoint":
                saw_non_404 = True
            continue  # next model in the outer ladder

        resp2 = outcome2["response_json"]
        raw2 = resp2["choices"][0]["message"]["content"]
        # Tier 2 always has a span to check the STRUCTURER against (source_text,
        # or the tier-1 raw content), so the check always runs. But the result
        # is labelled "verified" ONLY when that span was the caller's
        # `source_text`. Checked against tier 1's own prose, it proves the
        # structurer invented nothing beyond what the model already said - it
        # does NOT prove any source says it, and labelling that "verified"
        # would admit an unsourced claim under a sourced label: R2's failure
        # arriving through the label instead of the value.
        value2, ground2, ungrounded2, status2 = _validate_and_ground(raw2, schema, span2)
        if status2 == "ok" and source_text is None:
            ground2 = "not_applicable"

        attempt_counter[0] += 1
        row2_id = _write_ledger(
            role=role.value, task=task, target_id=target_id, engagement_id=resolved_engagement_id,
            passive_only=passive_only, data_policy=policy, requested_model=extract_primary, tier=tier2,
            attempt=attempt_counter[0], status=status2, served_model=resp2.get("model"),
            provider=resp2.get("provider"), generation_id=resp2.get("id"),
            latency_ms=outcome2.get("latency_ms"), ungrounded_fields=ungrounded2, **_usage_fields(resp2),
        )
        ledger_ids.append(row2_id)
        saw_non_404 = True

        if status2 == "ok":
            return StructuredResult(
                value=value2, grounding=ground2, model=resp2.get("model", extract_primary),
                provider=resp2.get("provider"), generation_id=resp2.get("id"), tier=tier2,
                ledger_ids=ledger_ids,
            )
        attempts.append(f"{extract_primary} tier{tier2}: {status2}")

        if model_index == 0 and model_index + 1 < len(binding.models):
            log.warning(
                "llm_connector: role=%s escalating past its primary model after tier-2 "
                "failure — a role escalating often is a config problem", role.value,
            )

    if not saw_non_404:
        raise NoCompliantEndpoint(role.value, policy, list(binding.models))
    raise StructuredOutputFailed(role.value, attempts)
