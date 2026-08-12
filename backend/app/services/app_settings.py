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
