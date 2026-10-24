"""Connector instances (planning#284): the service layer.

A connector TYPE (one of the 14 registry keys) has one or more INSTANCES.
Account-style types (`ACCOUNT_TYPES`) are multi-instance and each instance is
bound to an organization; every other type is a global service or scanning
tool with at most one unbound instance. Migration 0085 enforces both rules
in the database; this module checks them first so the caller gets a typed
error instead of an IntegrityError.

Transaction ownership (CONTRIBUTING.md "Development principles"): nothing
here commits. Writers `flush()` where an id is needed; the caller (router,
startup hook) owns the commit and the rollback.
"""

import base64
import hashlib
import json
import logging
import os
import uuid
from typing import Any

from cryptography.fernet import Fernet
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.connector_instance import (
    ACCOUNT_TYPES,
    CONNECTOR_TYPES,
    ConnectorEnvSeed,
    ConnectorInstance,
)
from app.models.engagement import Engagement, EngagementPosture
from app.models.org_entity import RELATIONSHIP_MA_TARGET, RELATIONSHIP_OURS, OrgEntity
from app.models.scope_candidate import ScopeCandidate

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

# Never seeded from the environment: the OpenRouter key comes only from an
# instance's stored config (planning#140, R5).
_NEVER_SEEDED = frozenset({"openrouter"})


class ConnectorInstanceError(ValueError):
    """Base class for refused connector-instance operations."""


class UnknownType(ConnectorInstanceError):
    pass


class BindingRequired(ConnectorInstanceError):
    """An account type needs an organization."""


class BindingForbidden(ConnectorInstanceError):
    """A non-account type must not be bound to an organization."""


class BindingNotAllowed(ConnectorInstanceError):
    def __init__(self, reason: str):
        super().__init__(f"binding not allowed: {reason}")
        self.reason = reason


class SingleInstanceType(ConnectorInstanceError):
    """A non-account type already has its one instance."""


class DuplicateName(ConnectorInstanceError):
    pass


def _fernet(*, context: str | None = _ENCRYPTION_KEY_CONTEXT) -> Fernet:
    material = settings.secret_key if context is None else f"{settings.secret_key}:{context}"
    key = hashlib.sha256(material.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def _encrypt(data: dict) -> str:
    return _fernet().encrypt(json.dumps(data).encode()).decode()


def _decrypt(encrypted: str) -> dict:
    return json.loads(_fernet().decrypt(encrypted.encode()).decode())


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


# ── reads ─────────────────────────────────────────────────────────────────


def is_account_type(type: str) -> bool:
    return type in ACCOUNT_TYPES


def get(db: Session, instance_id: uuid.UUID) -> ConnectorInstance | None:
    return db.get(ConnectorInstance, instance_id)


def list_all(db: Session) -> list[ConnectorInstance]:
    return (
        db.query(ConnectorInstance)
        .order_by(ConnectorInstance.type, ConnectorInstance.created_at, ConnectorInstance.id)
        .all()
    )


def list_of_type(db: Session, type: str, *, enabled_only: bool = False) -> list[ConnectorInstance]:
    q = db.query(ConnectorInstance).filter(ConnectorInstance.type == type)
    if enabled_only:
        q = q.filter(ConnectorInstance.enabled.is_(True))
    return q.order_by(ConnectorInstance.created_at, ConnectorInstance.id).all()


def enabled_types(db: Session) -> set[str]:
    """The connector TYPES that have at least one enabled instance."""
    return {
        r[0]
        for r in db.query(ConnectorInstance.type).filter(ConnectorInstance.enabled.is_(True)).distinct().all()
    }


def single(db: Session, type: str) -> ConnectorInstance | None:
    """The one instance of a non-account type, or None."""
    if is_account_type(type):
        raise ValueError(f"{type} is an account type; it has no single instance")
    return db.query(ConnectorInstance).filter(ConnectorInstance.type == type).first()


def decrypted_config(instance: ConnectorInstance) -> dict[str, Any]:
    if not instance.config_encrypted:
        return {}
    try:
        return _decrypt(instance.config_encrypted)
    except Exception:
        log.warning(
            "Failed to decrypt stored config for connector instance %s (type %s) — secret_key "
            "may have changed since it was saved. Treating as unconfigured; run "
            "`python -m app.scripts.rotate_encryption_key` if this follows a key rotation.",
            instance.id, instance.type,
        )
        return {}


def config_is_unreadable(instance: ConnectorInstance) -> bool:
    """True when a config blob is stored but cannot be decrypted (key rotation
    pending). `decrypted_config` returns `{}` for it, so any write that MERGES
    into the stored config would silently overwrite a blob the rotation script
    can still recover: callers must refuse instead."""
    if not instance.config_encrypted:
        return False
    try:
        _decrypt(instance.config_encrypted)
    except Exception:
        return True
    return False


def enabled_config(db: Session, type: str) -> dict[str, Any] | None:
    """Decrypted config of a non-account type's instance iff it exists and is
    enabled; otherwise None ("no key")."""
    instance = single(db, type)
    if instance is None or not instance.enabled:
        return None
    return decrypted_config(instance)


# ── binding rule (mirrors trg_connector_instances_binding_guard) ───────────


def deal_engagement(db: Session, entity_id: uuid.UUID) -> Engagement | None:
    """The single non-abandoned engagement of an ma_target organization.
    None for an `ours` organization, an unknown entity, or when there are zero
    or several (ambiguity fails closed)."""
    entity = db.get(OrgEntity, entity_id)
    if entity is None or entity.relationship != RELATIONSHIP_MA_TARGET:
        return None
    rows = (
        db.query(Engagement)
        .filter(
            Engagement.subject_entity_id == entity_id,
            Engagement.posture != EngagementPosture.ABANDONED.value,
        )
        .limit(2)
        .all()
    )
    return rows[0] if len(rows) == 1 else None


def binding_allowed(db: Session, entity_id: uuid.UUID) -> tuple[bool, str | None]:
    entity = db.get(OrgEntity, entity_id)
    if entity is None:
        return False, "unknown_entity"
    if entity.relationship is None:
        return False, "not_an_organization"
    if entity.relationship == RELATIONSHIP_OURS:
        return True, None
    if entity.relationship == RELATIONSHIP_MA_TARGET:
        engagement = deal_engagement(db, entity_id)
        if engagement is None:
            return False, "deal_engagement_ambiguous"
        if engagement.posture not in (EngagementPosture.DAY_0.value, EngagementPosture.INTEGRATED.value):
            return False, "deal_not_closed"
        return True, None
    return False, "not_an_organization"


SCOPE_ESTATE = "estate"
SCOPE_UNKNOWN = "unknown"


def instance_scope_key(db: Session, instance: ConnectorInstance) -> str | None:
    """The scope an account instance belongs to: "estate" (bound to an `ours`
    organization), the deal's engagement id as a string (bound to a deal
    organization with a single non-abandoned engagement), or None (unbound,
    unknown entity or ambiguous deal; fails closed)."""
    if instance.bound_entity_id is None:
        return None
    entity = db.get(OrgEntity, instance.bound_entity_id)
    if entity is None:
        return None
    if entity.relationship == RELATIONSHIP_OURS:
        return SCOPE_ESTATE
    engagement = deal_engagement(db, instance.bound_entity_id)
    return str(engagement.id) if engagement is not None else None


def instance_matches_scope(db: Session, instance: ConnectorInstance, scope_key: str) -> bool:
    """May `instance` be called on a chunk whose scope key is `scope_key`?
    An account instance runs only on targets of its own scope (planning#284,
    Jason): an `ours`-bound instance on "estate", a deal-bound one on that
    deal's engagement id; "unknown" matches no account instance. A non-account
    instance is global and always matches."""
    if not is_account_type(instance.type):
        return True
    if scope_key == SCOPE_UNKNOWN:
        return False
    own = instance_scope_key(db, instance)
    return own is not None and own == scope_key


def runnable_instances(
    db: Session, type: str
) -> tuple[list[tuple[ConnectorInstance, dict[str, Any]]], list[tuple[ConnectorInstance, str]]]:
    """Instances of `type` a scan may call now, and those it must skip.

    Runnable = enabled AND (non-account type, OR `binding_allowed` now). An
    enabled account instance whose binding is no longer allowed (its deal
    regressed) lands in the second list with the reason, so the caller can
    record the skip. Disabled instances appear in neither. Ordered by
    created_at. Read-only; never commits."""
    runnable: list[tuple[ConnectorInstance, dict[str, Any]]] = []
    skipped: list[tuple[ConnectorInstance, str]] = []
    for instance in list_of_type(db, type, enabled_only=True):
        if is_account_type(type):
            if instance.bound_entity_id is None:
                skipped.append((instance, "not_bound"))
                continue
            ok, reason = binding_allowed(db, instance.bound_entity_id)
            if not ok:
                skipped.append((instance, reason or "unknown"))
                continue
        runnable.append((instance, decrypted_config(instance)))
    return runnable, skipped


def _check_binding(db: Session, type: str, bound_entity_id: uuid.UUID | None) -> None:
    if is_account_type(type):
        if bound_entity_id is None:
            raise BindingRequired(f"{type} needs an instance bound to an organization")
        ok, reason = binding_allowed(db, bound_entity_id)
        if not ok:
            raise BindingNotAllowed(reason or "unknown")
    elif bound_entity_id is not None:
        raise BindingForbidden(f"{type} is a global connector; it cannot be bound to an organization")


def _clean_name(name: str | None) -> str:
    cleaned = (name or "").strip()
    if not cleaned:
        raise ConnectorInstanceError("name must not be empty")
    return cleaned


def _name_taken(db: Session, type: str, name: str, *, exclude_id: uuid.UUID | None = None) -> bool:
    q = db.query(ConnectorInstance.id).filter(ConnectorInstance.type == type, ConnectorInstance.name == name)
    if exclude_id is not None:
        q = q.filter(ConnectorInstance.id != exclude_id)
    return q.first() is not None


# ── writes (never commit) ───────────────────────────────────────────────────


def create(
    db: Session,
    *,
    type: str,
    name: str,
    bound_entity_id: uuid.UUID | None,
    config: dict[str, Any] | None,
    created_by_id: uuid.UUID | None,
) -> ConnectorInstance:
    if type not in CONNECTOR_TYPES:
        raise UnknownType(f"unknown connector type: {type!r}")
    cleaned = _clean_name(name)
    _check_binding(db, type, bound_entity_id)
    if not is_account_type(type) and db.query(ConnectorInstance.id).filter(ConnectorInstance.type == type).first():
        raise SingleInstanceType(f"{type} already has an instance")
    if _name_taken(db, type, cleaned):
        raise DuplicateName(f"a {type} instance named {cleaned!r} already exists")
    instance = ConnectorInstance(
        type=type,
        name=cleaned,
        enabled=True,
        config_encrypted=_encrypt(config) if config else None,
        bound_entity_id=bound_entity_id,
        created_by_id=created_by_id,
    )
    db.add(instance)
    db.flush()
    return instance


def update_config(db: Session, instance: ConnectorInstance, config: dict[str, Any]) -> ConnectorInstance:
    """Replace the whole config dict (the masked-secret merge is the router's job)."""
    instance.config_encrypted = _encrypt(config) if config else None
    db.flush()
    return instance


def set_enabled(db: Session, instance: ConnectorInstance, enabled: bool) -> ConnectorInstance:
    instance.enabled = enabled
    db.flush()
    return instance


def rename(db: Session, instance: ConnectorInstance, name: str) -> ConnectorInstance:
    cleaned = _clean_name(name)
    if _name_taken(db, instance.type, cleaned, exclude_id=instance.id):
        raise DuplicateName(f"a {instance.type} instance named {cleaned!r} already exists")
    instance.name = cleaned
    db.flush()
    return instance


def rebind(db: Session, instance: ConnectorInstance, bound_entity_id: uuid.UUID | None) -> ConnectorInstance:
    _check_binding(db, instance.type, bound_entity_id)
    instance.bound_entity_id = bound_entity_id
    db.flush()
    return instance


# ── binding suggestion ──────────────────────────────────────────────────────


def suggest_binding(
    db: Session, zones: list[str], *, hidden_entities: Any = None
) -> tuple[uuid.UUID | None, list[dict[str, Any]]]:
    """Which organization does an account's zone list belong to?

    Counts, per organization, the zones that are one of its CLAIMED domain
    candidates (exact match after lowercasing and stripping a trailing dot).
    Only organizations an instance may be bound to (`binding_allowed`) are
    candidates, so a deal that has not closed is neither suggested nor
    revealed. Returns `(suggested_id, candidates)`, candidates sorted by
    matches descending; the suggestion is None when no organization matches
    or the first place is tied. `hidden_entities` (a select of organization ids,
    from `read_scope.closed_subject_entities`) removes organizations the caller
    may not see BEFORE the suggestion is computed. Read-only; never commits."""
    hidden: set[uuid.UUID] = (
        set(db.execute(hidden_entities).scalars().all()) if hidden_entities is not None else set()
    )
    normalised = sorted({z.strip().rstrip(".").lower() for z in zones if z and z.strip().rstrip(".")})
    if not normalised:
        return None, []
    rows = (
        db.query(ScopeCandidate.root_entity_id, func.count(func.distinct(ScopeCandidate.value)))
        .filter(
            ScopeCandidate.kind == "domain",
            ScopeCandidate.status == "claimed",
            ScopeCandidate.value.in_(normalised),
        )
        .group_by(ScopeCandidate.root_entity_id)
        .all()
    )
    candidates: list[dict[str, Any]] = []
    for entity_id, matches in rows:
        if entity_id in hidden or not binding_allowed(db, entity_id)[0]:
            continue
        entity = db.get(OrgEntity, entity_id)
        candidates.append({"entity_id": entity_id, "name": entity.legal_name, "matches": int(matches)})
    candidates.sort(key=lambda c: (-c["matches"], c["name"], str(c["entity_id"])))
    if not candidates or (len(candidates) > 1 and candidates[0]["matches"] == candidates[1]["matches"]):
        return None, candidates
    return candidates[0]["entity_id"], candidates


# ── one-time environment seeding ────────────────────────────────────────────


def _sole_ours_org(db: Session) -> uuid.UUID | None:
    ids = [
        r[0]
        for r in db.query(OrgEntity.id).filter(OrgEntity.relationship == RELATIONSHIP_OURS).limit(2).all()
    ]
    return ids[0] if len(ids) == 1 else None


def seed_from_env(db: Session, registry: dict) -> None:
    """Seed connector instances from environment variables, ONCE per type.

    Fills only EMPTY fields of an existing instance (never overwrites), or
    creates the instance. An account type is created bound to the sole `ours`
    organization; with zero or several it is skipped and NOT recorded, so a
    later startup retries. A type is recorded in `connector_env_seeds` once a
    seed was applied or the environment holds no value for any of its fields.
    openrouter is never seeded. Does not commit; logs types and counts only,
    never values.
    """
    already = {r[0] for r in db.query(ConnectorEnvSeed.type).all()}
    for type, connector in registry.items():
        if type in _NEVER_SEEDED or type in already or type not in CONNECTOR_TYPES:
            continue
        env_key_map: dict[str, str] = getattr(connector, "env_key_map", {}) or {}
        env_values = {
            field: value
            for field, env_key in env_key_map.items()
            if (value := os.environ.get(env_key))
        }
        if not env_values:
            db.add(ConnectorEnvSeed(type=type, instance_id=None))
            db.flush()
            log.info("Connector env seed %s: skipped: environment holds no value (recorded)", type)
            continue

        if is_account_type(type):
            org_id = _sole_ours_org(db)
            if org_id is None:
                log.warning(
                    "Connector env seed %s: skipped: needs exactly one 'ours' organization to bind to "
                    "(will retry next startup)", type,
                )
                continue
            instance = (
                db.query(ConnectorInstance)
                .filter(ConnectorInstance.type == type, ConnectorInstance.bound_entity_id == org_id)
                .order_by(ConnectorInstance.created_at, ConnectorInstance.id)
                .first()
            )
            if instance is None:
                if _name_taken(db, type, type):
                    log.warning(
                        "Connector env seed %s: skipped: an instance named %r already exists for another "
                        "organization (will retry next startup)", type, type,
                    )
                    continue
                instance = create(
                    db, type=type, name=type, bound_entity_id=org_id,
                    config=env_values, created_by_id=None,
                )
                db.add(ConnectorEnvSeed(type=type, instance_id=instance.id))
                db.flush()
                log.info("Connector env seed %s: created (%d fields)", type, len(env_values))
                continue
        else:
            instance = single(db, type)
            if instance is None:
                instance = create(
                    db, type=type, name=type, bound_entity_id=None,
                    config=env_values, created_by_id=None,
                )
                db.add(ConnectorEnvSeed(type=type, instance_id=instance.id))
                db.flush()
                log.info("Connector env seed %s: created (%d fields)", type, len(env_values))
                continue

        config = decrypted_config(instance)
        if instance.config_encrypted and not config:
            # Undecryptable (key rotation pending): filling would overwrite a
            # blob the rotation script may still recover.
            log.warning(
                "Connector env seed %s: skipped: instance %s config cannot be decrypted "
                "(will retry next startup)", type, instance.id,
            )
            continue
        fillable = {f: v for f, v in env_values.items() if not config.get(f)}
        if fillable:
            update_config(db, instance, {**config, **fillable})
        db.add(ConnectorEnvSeed(type=type, instance_id=instance.id))
        db.flush()
        log.info("Connector env seed %s: filled %d fields", type, len(fillable))
