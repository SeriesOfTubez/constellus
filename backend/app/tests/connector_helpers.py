"""Helpers for tests that need a GLOBAL-type connector instance (naabu,
nuclei, openrouter, ...) enabled for the duration of one test and the
database left as it was found (planning#284).

The snapshot/restore shape mirrors the old `connector_configs` pattern:
`snapshot` records what exists, `force_enabled` creates-or-updates and
COMMITS (the callers own their sessions and the code under test opens
others), `restore` undoes it — deleting an instance the test created.
"""

from typing import Any

from sqlalchemy.orm import Session

from app.models.connector_instance import ConnectorInstance
from app.services import connector_instances as svc


def snapshot(db: Session, type: str) -> tuple[bool, str | None] | None:
    """(enabled, config_encrypted) of the type's instance, or None if absent."""
    inst = svc.single(db, type)
    return None if inst is None else (inst.enabled, inst.config_encrypted)


def force_enabled(
    db: Session, type: str, *, enabled: bool = True, config: dict[str, Any] | None = None
) -> ConnectorInstance:
    """Create the type's instance if absent, set `enabled`, and (when given)
    merge `config` over its decrypted config. Commits."""
    inst = svc.single(db, type)
    if inst is None:
        inst = svc.create(db, type=type, name=type, bound_entity_id=None, config={}, created_by_id=None)
    svc.set_enabled(db, inst, enabled)
    if config is not None:
        svc.update_config(db, inst, {**svc.decrypted_config(inst), **config})
    db.commit()
    return inst


def restore(db: Session, type: str, snap: tuple[bool, str | None] | None) -> None:
    db.rollback()
    inst = svc.single(db, type)
    if inst is None:
        return
    if snap is None:
        db.delete(inst)
    else:
        inst.enabled, inst.config_encrypted = snap
    db.commit()


def _single_or_create(db: Session, type: str) -> ConnectorInstance:
    inst = svc.single(db, type)
    if inst is None:
        inst = svc.create(db, type=type, name=type, bound_entity_id=None, config={}, created_by_id=None)
    return inst


def set_config(db: Session, type: str, config: dict[str, Any]) -> ConnectorInstance:
    """REPLACE the type's config (creating the instance if absent). Commits."""
    inst = _single_or_create(db, type)
    svc.update_config(db, inst, config)
    db.commit()
    return inst


def set_enabled(db: Session, type: str, enabled: bool) -> ConnectorInstance:
    """Set `enabled` (creating the instance if absent). Commits."""
    inst = _single_or_create(db, type)
    svc.set_enabled(db, inst, enabled)
    db.commit()
    return inst
