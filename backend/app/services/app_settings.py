from sqlalchemy.orm import Session

from app.models.app_settings import AppSetting

DEFAULTS = {
    "log_retention_days": "15",
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
