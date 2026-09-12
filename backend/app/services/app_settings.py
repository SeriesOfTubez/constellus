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
