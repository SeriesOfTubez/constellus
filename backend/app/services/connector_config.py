import base64
import hashlib
import json
import logging
from typing import Any

from cryptography.fernet import Fernet
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.connector_config import ConnectorConfig

log = logging.getLogger(__name__)

# Domain-separated from the JWT signing key (core/auth.py uses settings.secret_key
# directly) so the two keys aren't byte-identical, even though both are still
# ultimately rooted in one secret. Compromising one doesn't hand over the other
# by coincidence of them being literally the same value.
_ENCRYPTION_KEY_CONTEXT = "connector-encryption"

# Old (pre-planning#85) derivation — secret_key hashed with no domain
# separation, so it produced the exact same key material as the JWT signing
# key. Kept only so rotate_encryption_key.py can decrypt configs written
# before this change and re-encrypt them under the new derivation.
_LEGACY_CONTEXT = None


def _fernet(*, context: str | None = _ENCRYPTION_KEY_CONTEXT) -> Fernet:
    material = settings.secret_key if context is None else f"{settings.secret_key}:{context}"
    key = hashlib.sha256(material.encode()).digest()
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
        log.warning(
            "Failed to decrypt stored config for connector %s — secret_key may have "
            "changed since it was saved. Treating as unconfigured; run "
            "`python -m app.scripts.rotate_encryption_key` if this follows a key rotation.",
            connector_id,
        )
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
