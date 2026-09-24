import json

from sqlalchemy.orm import Session

from app.models.app_settings import AppSetting

# planning#140 — default role -> model-ladder bindings for
# app.services.llm_connector. Chosen 2026-09-23 against live OpenRouter
# rates; every model listed had >=1 endpoint that is BOTH ZDR and
# structured-output-capable on that date; each role's primary and first
# fallback are different vendors (governing constraint: no single-vendor
# dependency; Claude allowed, never required). Rates are NOT recorded in
# code — they change. A Python dict, not a JSON literal, so it stays
# readable; `DEFAULTS["llm.role_bindings"]` below serialises it once.
_LLM_ROLE_BINDINGS_DEFAULT = {
    "classify": {"models": ["deepseek/deepseek-v4-flash", "z-ai/glm-5.3-flash", "google/gemini-2.5-flash-lite"], "max_tokens": 1024, "temperature": 0},
    "extract":  {"models": ["z-ai/glm-5.3-flash", "deepseek/deepseek-v4-flash", "openai/gpt-5-mini"], "max_tokens": 4096, "temperature": 0},
    "research": {"models": ["z-ai/glm-5.3", "moonshotai/kimi-k2.6", "deepseek/deepseek-v4-pro"], "max_tokens": 8192, "temperature": 0.2},
    "judge":    {"models": ["deepseek/deepseek-v4-pro", "anthropic/claude-sonnet-5", "google/gemini-3.1-pro-preview"], "max_tokens": 4096, "temperature": 0},
    "narrate":  {"models": ["google/gemini-3.8-flash", "moonshotai/kimi-k2.6", "z-ai/glm-5.3"], "max_tokens": 2048, "temperature": 0.4},
}

DEFAULTS = {
    "log_retention_days": "15",
    # Authorisation gating is intentionally disabled by default — the act of
    # adding a target IS the authorisation. The mode plumbing (strict /
    # acknowledge / disabled) is retained so a deployer who wants a second
    # confirmation step can flip it via the API; the UI no longer exposes
    # the toggle.
    "scan_authorisation_mode": "disabled",
    # planning#148 — the composed probe-authorisation gate's rollout switch
    # ("log_only" | "enforce"). Defaults to log-only because `probe_class`
    # is only ever `direct_addressable` for an IP inside a declared CIDR
    # target or a datacenter IP with a confirmed-ours affinity verdict, and
    # `shared_infra_verifier` (the thing that actually sets confirmed_ours)
    # runs AFTER Phase 1.5 port discovery in the scan pipeline — so on a
    # target's first run, no IP has had a chance to earn direct_addressable
    # yet. Enforcing the gate by default would silently stop naabu from
    # discovering a single port on a first-ever scan. `log_only` still
    # writes the real computed verdict to `authorisation_decisions` for
    # every asset/connector pair, so the deny rate is fully visible before
    # anyone flips this to "enforce" — see app.services.probe_authorisation
    # module docstring for the full story.
    "probe_authorisation_mode": "log_only",
    "aggressiveness": "polite",
    # Org branding — applied as CSS vars at boot; see api/settings.py for
    # the curated accent palette and logo URL validation rules.
    "org.name": "Constellus",
    "org.logo_url": "",
    "org.brand_accent": "#8b7bf0",
    "org.name_color": "",
    # planning#140 — role -> model-ladder bindings, see
    # _LLM_ROLE_BINDINGS_DEFAULT above. app.services.llm_connector.
    # load_bindings raises LLMConfigError on a stored value that fails to
    # parse or is missing a role — it never silently falls back to this
    # default once a value has been stored (a typo must not quietly route
    # to a different model).
    "llm.role_bindings": json.dumps(_LLM_ROLE_BINDINGS_DEFAULT),
    # Daily USD budget. Compared against today's GROSSED-UP spend (raw
    # ledger cost_usd x (1 + llm_connector.OPENROUTER_CREDIT_FEE_RATE), i.e.
    # what the credits actually cost); at or above it, llm_connector
    # refuses every new call outright.
    "llm.daily_budget_usd": "5",
    # Retention for the llm_calls ledger (app.services.llm_connector.
    # prune_ledger) — high-volume telemetry, long retention, never the
    # prompt/response content itself (R4).
    "llm_ledger_retention_days": "400",
}


def get(db: Session, key: str) -> str | None:
    row = db.get(AppSetting, key)
    if row:
        return row.value
    return DEFAULTS.get(key)


def get_int(db: Session, key: str) -> int | None:
    val = get(db, key)
    try:
        return int(val) if val is not None else None
    except (ValueError, TypeError):
        return None


def set_value(db: Session, key: str, value: str) -> None:
    row = db.get(AppSetting, key)
    if row:
        row.value = value
    else:
        db.add(AppSetting(key=key, value=value))
    db.commit()
