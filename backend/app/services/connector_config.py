import base64
import hashlib
import json
from typing import Any

from cryptography.fernet import Fernet
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.connector_config import ConnectorConfig


def _fernet() -> Fernet:
    key = hashlib.sha256(settings.secret_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def _encrypt(data: dict) -> str:
    return _fernet().encrypt(json.dumps(data).encode()).decode()


def _decrypt(encrypted: str) -> dict:
    return json.loads(_fernet().decrypt(encrypted.encode()).decode())


def get_all(db: Session) -> list[ConnectorConfig]:
    return db.query(ConnectorConfig).all()


def get_one(db: Session, connector_id: str) -> ConnectorConfig | None:
    return db.query(ConnectorConfig).filter(ConnectorConfig.connector_id == connector_id).first()


def upsert_config(db: Session, connector_id: str, config: dict[str, Any]) -> ConnectorConfig:
    row = get_one(db, connector_id)
    if row is None:
        row = ConnectorConfig(connector_id=connector_id)
        db.add(row)
    row.config_encrypted = _encrypt(config) if config else None
    db.commit()
    db.refresh(row)
    return row


def set_enabled(db: Session, connector_id: str, enabled: bool) -> ConnectorConfig:
    row = get_one(db, connector_id)
    if row is None:
        row = ConnectorConfig(connector_id=connector_id)
        db.add(row)
    row.enabled = enabled
    db.commit()
    db.refresh(row)
    return row


def get_decrypted_config(db: Session, connector_id: str) -> dict[str, Any]:
    row = get_one(db, connector_id)
    if row is None or not row.config_encrypted:
        return {}
    try:
        return _decrypt(row.config_encrypted)
    except Exception:
        return {}


def mask_config(config: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    """Return config with secret fields replaced by a placeholder."""
    masked = {}
    for key, value in config.items():
        field_def = schema.get(key, {})
        if field_def.get("type") == "secret" and value:
            masked[key] = "**configured**"
        else:
            masked[key] = value
    return masked


def load_overrides_from_db(db: Session, registry: dict) -> None:
    """Called at startup — populate the secrets override layer from DB-stored config."""
    from app.core.secrets import set_db_override

    for connector_id, connector in registry.items():
        config = get_decrypted_config(db, connector_id)
        env_key_map: dict[str, str] = getattr(connector, "env_key_map", {})
        for field_name, env_key in env_key_map.items():
            value = config.get(field_name)
            set_db_override(env_key, value if value else None)
