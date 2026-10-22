from sqlalchemy.orm import Session

from app.models.app_settings import AppSetting

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
    # planning#224 item 5 — `llm.role_bindings` deliberately has NO default
    # here: model choice is config, not code. Until an admin saves bindings
    # (Admin -> AI models, PUT /api/llm/role-bindings),
    # llm_connector.load_bindings raises ModelsNotConfigured and AI features
    # say "configure AI models" instead of calling a code-chosen model.
    # Daily USD budget. Compared against today's GROSSED-UP spend (raw
    # ledger cost_usd x (1 + llm_connector.OPENROUTER_CREDIT_FEE_RATE), i.e.
    # what the credits actually cost); at or above it, llm_connector
    # refuses every new call outright.
    "llm.daily_budget_usd": "5",
    # planning#226 slice 2 — automatic finding write-ups per UTC day, after
    # a scan (the write-up service's auto_generate). 0 is off: Jason
    # turns it on from Admin -> AI models once he has seen the cost.
    "ai.finding_writeups.auto_daily_cap": "0",
    # planning#231 - automatic web-app classifications per UTC day, after a
    # scan (web_classifier.auto_generate). 0 is off. Counts classification
    # rows (one per web endpoint), not assets.
    "ai.web_classifications.auto_daily_cap": "0",
    # Retention for the llm_calls ledger (app.services.llm_connector.
    # prune_ledger) — high-volume telemetry, long retention, never the
    # prompt/response content itself (R4).
    "llm_ledger_retention_days": "400",
    # planning#228 — chat assistant transcripts (questions + answers: content, unlike
    # the ledger) are deleted this many days after a conversation's last
    # activity (app.services.chat.purge_transcripts, daily).
    "chat.transcript_retention_days": "30",
    # planning#233 slice 2a - alert digests: the one global send hour (UTC, 0-23),
    # the AI-narrative cap per UTC day, and the public base URL used for links.
    "notifications.digest_hour_utc": "7",
    "ai.digests.narrative_daily_cap": "10",
    "notifications.app_base_url": "",
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
