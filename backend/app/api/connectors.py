import logging
import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Response
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import require_permission
from app.core.permissions import Permission
from app.connectors.base import DNSDiscoveryConnector
from app.connectors.certspotter import CertspotterConnector
from app.services import aggressiveness as aggr_svc
from app.services import app_settings as app_settings_svc
from app.connectors.cloudflare import CloudflareConnector
from app.connectors.fortimanager import FortiManagerConnector
from app.connectors.mailtrap import MailtrapConnector
from app.connectors.banner_grab import BannerGrabConnector
from app.connectors.httpx_probe import HttpxConnector
from app.connectors.naabu import NaabuConnector
from app.connectors.nuclei import NucleiConnector
from app.connectors.openrouter import OpenRouterConnector
from app.connectors.tlsx import TlsxConnector
from app.connectors.shodan import ShodanConnector
from app.connectors.tenable import TenableConnector
from app.connectors.vulncheck import VulnCheckConnector
from app.connectors.wiz import WizConnector
from app.core.database import get_db

from pydantic import BaseModel
from app.schemas.connector import (
    BindableOrganization,
    BindingCandidate,
    BindingSuggestionRequest,
    BindingSuggestionResponse,
    ConnectorConfigResponse,
    ConnectorConfigUpdate,
    ConnectorInstanceCreate,
    ConnectorInstanceSummary,
    ConnectorInstanceUpdate,
    ConnectorTypeSummary,
)
from app.models.connector_instance import ConnectorInstance
from app.models.org_entity import OrgEntity
from app.models.target import Target
from app.services import connector_instances as svc
from app.services import read_scope

log = logging.getLogger(__name__)

router = APIRouter()

_MASK = "**configured**"

REGISTRY: dict = {
    "certspotter": CertspotterConnector(),
    "cloudflare": CloudflareConnector(),
    "shodan": ShodanConnector(),
    "wiz": WizConnector(),
    "fortimanager": FortiManagerConnector(),
    "tenable": TenableConnector(),
    "vulncheck": VulnCheckConnector(),
    "nuclei": NucleiConnector(),
    "naabu": NaabuConnector(),
    "banner_grab": BannerGrabConnector(),
    "httpx_probe": HttpxConnector(),
    "tlsx": TlsxConnector(),
    "mailtrap": MailtrapConnector(),
    "openrouter": OpenRouterConnector(),
}


# ── helpers ───────────────────────────────────────────────────────────────────


def _get_connector(connector_id: str):
    connector = REGISTRY.get(connector_id)
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")
    return connector


def _load_instance(db: Session, user, instance_id: uuid.UUID) -> ConnectorInstance:
    """The instance, if `user` may read it; otherwise 404 (not 403), so an
    instance bound to a deal the user cannot see is not confirmed to exist."""
    instance = (
        db.query(ConnectorInstance)
        .filter(ConnectorInstance.id == instance_id, read_scope.connector_instance_clause(user, ConnectorInstance))
        .first()
    )
    if instance is None:
        raise HTTPException(status_code=404, detail="Connector instance not found")
    return instance


def _dns_connector(instance: ConnectorInstance) -> DNSDiscoveryConnector:
    connector = _get_connector(instance.type)
    if not isinstance(connector, DNSDiscoveryConnector):
        raise HTTPException(status_code=400, detail="Connector does not support zone discovery")
    return connector


_UNREADABLE_CONFIG = "stored connector config cannot be decrypted; run the key-rotation script first"


def _refuse_unreadable_config(instance: ConnectorInstance) -> None:
    """409 before any write that merges into the stored config: an undecryptable
    blob reads as {} and the merge would overwrite what key rotation can recover."""
    if svc.config_is_unreadable(instance):
        raise HTTPException(status_code=409, detail=_UNREADABLE_CONFIG)


def _refuse_invisible_binding(db: Session, user, bound_entity_id: uuid.UUID | None) -> None:
    """422 binding_not_allowed/not_visible when `user` cannot see the organization
    (deal data closed to them under the #261 rule), rather than a success they
    then cannot read back."""
    if bound_entity_id is None:
        return
    hidden = read_scope.closed_subject_entities(user, Permission.CONNECTORS_READ)
    if hidden is not None and bound_entity_id in set(db.execute(hidden).scalars().all()):
        raise _service_error(svc.BindingNotAllowed("not_visible"))


def _service_error(exc: svc.ConnectorInstanceError) -> HTTPException:
    if isinstance(exc, svc.UnknownType):
        return HTTPException(status_code=404, detail="Connector not found")
    if isinstance(exc, (svc.SingleInstanceType, svc.DuplicateName)):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, svc.BindingNotAllowed):
        return HTTPException(status_code=422, detail={"code": "binding_not_allowed", "reason": exc.reason})
    if isinstance(exc, svc.BindingRequired):
        return HTTPException(status_code=422, detail={"code": "binding_required", "reason": str(exc)})
    if isinstance(exc, svc.BindingForbidden):
        return HTTPException(status_code=422, detail={"code": "binding_forbidden", "reason": str(exc)})
    return HTTPException(status_code=422, detail=str(exc))


def _summary(db: Session, inst: ConnectorInstance) -> ConnectorInstanceSummary:
    connector = REGISTRY.get(inst.type)
    bound = inst.bound_entity
    return ConnectorInstanceSummary(
        id=inst.id,
        type=inst.type,
        name=inst.name,
        enabled=inst.enabled,
        configured=bool(connector and connector.is_configured(svc.decrypted_config(inst))),
        bound_entity_id=inst.bound_entity_id,
        bound_entity_name=bound.legal_name if bound is not None else None,
        binding_ok=True if inst.bound_entity_id is None else svc.binding_allowed(db, inst.bound_entity_id)[0],
        created_at=inst.created_at,
        updated_at=inst.updated_at,
    )


def _merge_config(existing: dict, incoming: dict, schema: dict) -> dict:
    """Secrets still showing the masked placeholder keep their stored value."""
    merged = {**existing}
    for k, v in incoming.items():
        if schema.get(k, {}).get("type") == "secret" and v == _MASK:
            continue
        merged[k] = v
    return merged


# ── catalogue + instances ─────────────────────────────────────────────────────


@router.get("/", response_model=list[ConnectorTypeSummary])
def list_connectors(
    db: Session = Depends(get_db),
    current_user=Depends(require_permission(Permission.CONNECTORS_READ)),
):
    by_type: dict[str, list[ConnectorInstance]] = {}
    visible = (
        db.query(ConnectorInstance)
        .filter(read_scope.connector_instance_clause(current_user, ConnectorInstance))
        .order_by(ConnectorInstance.created_at, ConnectorInstance.id)
        .all()
    )
    for inst in visible:
        by_type.setdefault(inst.type, []).append(inst)
    current_tier = aggr_svc.normalize(app_settings_svc.get(db, "aggressiveness"))
    tier_profile = aggr_svc.profile(current_tier)
    result = []
    for key, connector in REGISTRY.items():
        # A connector is "disabled at this tier" when the global tier's
        # profile has a slot for the connector ID with `enabled: False`.
        # Generic so new tier-gated connectors (e.g. nmap later) inherit
        # this behaviour without touching this code.
        slot = tier_profile.get(key)
        disabled_at_tier = isinstance(slot, dict) and slot.get("enabled") is False
        account = svc.is_account_type(key)
        result.append(
            ConnectorTypeSummary(
                id=key,
                name=connector.name,
                description=connector.description,
                phase=getattr(connector, "phase", "unknown"),
                core=getattr(connector, "core", False),
                config_schema=connector.get_config_schema(),
                disabled_at_current_tier=disabled_at_tier,
                current_tier=current_tier,
                account_scoped=account,
                multi_instance=account,
                supports_zones=isinstance(connector, DNSDiscoveryConnector),
                instances=[_summary(db, i) for i in by_type.get(key, [])],
            )
        )
    return result


@router.post("/{connector_type}/instances", response_model=ConnectorInstanceSummary, status_code=201)
def create_instance(
    connector_type: str,
    data: ConnectorInstanceCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission(Permission.CONNECTORS_CONFIGURE)),
):
    _get_connector(connector_type)
    _refuse_invisible_binding(db, current_user, data.bound_entity_id)
    try:
        instance = svc.create(
            db, type=connector_type, name=data.name, bound_entity_id=data.bound_entity_id,
            config=data.config, created_by_id=current_user.id,
        )
        db.commit()
    except svc.ConnectorInstanceError as exc:
        db.rollback()
        raise _service_error(exc)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Connector instance conflicts with an existing one")
    return _summary(db, instance)


@router.post("/{connector_type}/binding-suggestion", response_model=BindingSuggestionResponse)
def suggest_binding(
    connector_type: str,
    data: BindingSuggestionRequest,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission(Permission.CONNECTORS_CONFIGURE)),
):
    """Which organization do this account's zones belong to? Lists the zones
    with the POSTED credentials (outbound call to the provider's fixed API
    base; nothing in the request selects the URL) and counts them against
    each organization's claimed domains."""
    connector = _get_connector(connector_type)
    # Only account types are bound to an organization; a global DNS connector
    # (shodan) gets the empty suggestion with no outbound call.
    if not svc.is_account_type(connector_type) or not isinstance(connector, DNSDiscoveryConnector):
        return BindingSuggestionResponse(suggested_entity_id=None, candidates=[], zone_count=None)
    config = dict(data.config)
    if data.instance_id is not None:
        instance = _load_instance(db, current_user, data.instance_id)
        if instance.type != connector_type:
            raise HTTPException(status_code=404, detail="Connector instance not found")
        _refuse_unreadable_config(instance)
        config = _merge_config(svc.decrypted_config(instance), config, connector.get_config_schema())
    try:
        # Every zone, whatever the saved exclusions say.
        zones = connector.list_domains({**config, "excluded_zones": []})
    except Exception:
        log.exception("Binding suggestion: listing zones failed for connector type %s", connector_type)
        raise HTTPException(status_code=502, detail="Could not list zones from the provider")
    suggested, candidates = svc.suggest_binding(
        db, zones, hidden_entities=read_scope.closed_subject_entities(current_user, Permission.CONNECTORS_READ)
    )
    return BindingSuggestionResponse(
        suggested_entity_id=suggested,
        candidates=[BindingCandidate(**c) for c in candidates],
        zone_count=len(zones),
    )


@router.get("/bindable-organizations", response_model=list[BindableOrganization])
def list_bindable_organizations(
    db: Session = Depends(get_db),
    current_user=Depends(require_permission(Permission.CONNECTORS_CONFIGURE)),
):
    """Organizations an account-type instance may be bound to now (ours, or a
    deal whose single non-abandoned engagement is day_0/integrated). Gated by
    the connector permission, not `entities.read`, which integration admins
    may lack."""
    roots = (
        db.query(OrgEntity)
        .filter(OrgEntity.relationship.is_not(None), read_scope.entity_clause(current_user, OrgEntity))
        .order_by(OrgEntity.legal_name, OrgEntity.id)
        .all()
    )
    hidden_q = read_scope.closed_subject_entities(current_user, Permission.CONNECTORS_READ)
    hidden = set(db.execute(hidden_q).scalars().all()) if hidden_q is not None else set()
    result = []
    for org in roots:
        if org.id in hidden:
            continue
        if not svc.binding_allowed(db, org.id)[0]:
            continue
        engagement = svc.deal_engagement(db, org.id)
        result.append(
            BindableOrganization(
                id=org.id, name=org.legal_name, relationship=org.relationship,
                posture=engagement.posture if engagement is not None else None,
            )
        )
    return result


@router.get("/domains")
def list_available_domains(
    db: Session = Depends(get_db),
    current_user=Depends(require_permission(Permission.CONNECTORS_READ)),
):
    """
    Returns targets available for scanning.
    In strict mode: verified targets only.
    In acknowledge/disabled mode: all targets in the system (adding one is confirmation enough).
    """
    from app.models.target import TargetType
    from app.services import app_settings as settings_svc

    auth_mode = settings_svc.get(db, "scan_authorisation_mode") or "disabled"
    result: list[dict] = []

    # Connector-sourced domains: every enabled, configured DNS instance the caller may read
    dns_types = [k for k, c in REGISTRY.items() if isinstance(c, DNSDiscoveryConnector)]
    instances = (
        db.query(ConnectorInstance)
        .filter(
            ConnectorInstance.type.in_(dns_types),
            ConnectorInstance.enabled.is_(True),
            read_scope.connector_instance_clause(current_user, ConnectorInstance),
        )
        .order_by(ConnectorInstance.created_at, ConnectorInstance.id)
        .all()
    )
    for instance in instances:
        connector = REGISTRY[instance.type]
        config = svc.decrypted_config(instance)
        if not connector.is_configured(config):
            continue
        instance_id, instance_name, type_name = instance.id, instance.name, connector.name
        try:
            domains = connector.list_domains(config)
        except Exception:
            log.exception("Listing domains failed for connector %s (instance %s)", instance.type, instance_id)
            continue
        for domain in domains:
            result.append({
                "domain": domain, "connector_id": instance.type, "connector_name": type_name,
                "connector_instance_id": instance_id, "connector_instance_name": instance_name,
            })

    # Manual targets — filter by verification state only in strict mode
    connector_values = {r["domain"] for r in result}
    manual_q = db.query(Target).filter(
        Target.connector_instance_id == None,  # noqa: E711
        read_scope.target_clause(current_user, Target),
    )
    if auth_mode == "strict":
        manual_q = manual_q.filter(Target.verified == True)  # noqa: E712
    for t in manual_q.all():
        if t.value not in connector_values:
            label = "Manual" if t.type == TargetType.DOMAIN else t.type.upper()
            result.append({
                "domain": t.value, "connector_id": None, "connector_name": label,
                "connector_instance_id": None, "connector_instance_name": None,
            })

    return result


@router.get("/instances/{instance_id}", response_model=ConnectorInstanceSummary)
def get_instance(
    instance_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission(Permission.CONNECTORS_READ)),
):
    return _summary(db, _load_instance(db, current_user, instance_id))


@router.patch("/instances/{instance_id}", response_model=ConnectorInstanceSummary)
def update_instance(
    instance_id: uuid.UUID,
    data: ConnectorInstanceUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission(Permission.CONNECTORS_CONFIGURE)),
):
    instance = _load_instance(db, current_user, instance_id)
    try:
        if "name" in data.model_fields_set:
            svc.rename(db, instance, data.name or "")
        if "bound_entity_id" in data.model_fields_set:
            _refuse_invisible_binding(db, current_user, data.bound_entity_id)
            svc.rebind(db, instance, data.bound_entity_id)
        db.commit()
    except svc.ConnectorInstanceError as exc:
        db.rollback()
        raise _service_error(exc)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Connector instance conflicts with an existing one")
    return _summary(db, instance)


@router.get("/instances/{instance_id}/config", response_model=ConnectorConfigResponse)
def get_config(
    instance_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission(Permission.CONNECTORS_READ_CONFIG)),
):
    instance = _load_instance(db, current_user, instance_id)
    connector = _get_connector(instance.type)
    return ConnectorConfigResponse(
        instance_id=instance.id,
        type=instance.type,
        enabled=instance.enabled,
        config=svc.mask_config(svc.decrypted_config(instance), connector.get_config_schema()),
    )


@router.put("/instances/{instance_id}/config", response_model=ConnectorConfigResponse)
def save_config(
    instance_id: uuid.UUID,
    data: ConnectorConfigUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission(Permission.CONNECTORS_CONFIGURE)),
):
    instance = _load_instance(db, current_user, instance_id)
    connector = _get_connector(instance.type)
    schema = connector.get_config_schema()
    _refuse_unreadable_config(instance)
    # Merge with existing config — don't overwrite secrets still showing the masked placeholder
    merged = _merge_config(svc.decrypted_config(instance), data.config, schema)
    svc.update_config(db, instance, merged)
    db.commit()
    return ConnectorConfigResponse(
        instance_id=instance.id, type=instance.type, enabled=instance.enabled,
        config=svc.mask_config(merged, schema),
    )


@router.post("/instances/{instance_id}/enable")
def enable_instance(
    instance_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission(Permission.CONNECTORS_TOGGLE)),
):
    svc.set_enabled(db, _load_instance(db, current_user, instance_id), True)
    db.commit()
    return {"status": "enabled"}


@router.post("/instances/{instance_id}/disable")
def disable_instance(
    instance_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission(Permission.CONNECTORS_TOGGLE)),
):
    svc.set_enabled(db, _load_instance(db, current_user, instance_id), False)
    db.commit()
    return {"status": "disabled"}


@router.post("/instances/{instance_id}/test")
def test_instance(
    instance_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission(Permission.CONNECTORS_TEST)),
):
    instance = _load_instance(db, current_user, instance_id)
    result = _get_connector(instance.type).test(svc.decrypted_config(instance))
    return {"success": result.success, "message": result.message, "details": result.details}


class ZonesUpdate(BaseModel):
    excluded_zones: list[str]


@router.get("/instances/{instance_id}/zones")
def list_instance_zones(
    instance_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission(Permission.CONNECTORS_READ_CONFIG)),
):
    """Return all zones from a DNS connector instance with their current exclusion state."""
    instance = _load_instance(db, current_user, instance_id)
    connector = _dns_connector(instance)
    config = svc.decrypted_config(instance)
    if not connector.is_configured(config):
        raise HTTPException(status_code=400, detail="Connector is not configured")

    excluded: set[str] = set(config.get("excluded_zones", []))

    # Fetch all zones from the provider, ignoring stored exclusions
    all_zones = connector.list_domains({**config, "excluded_zones": []})

    return [{"name": z, "excluded": z in excluded} for z in all_zones]


@router.put("/instances/{instance_id}/zones")
def save_instance_zones(
    instance_id: uuid.UUID,
    data: ZonesUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission(Permission.CONNECTORS_CONFIGURE)),
):
    """Save zone exclusions for a DNS connector instance."""
    instance = _load_instance(db, current_user, instance_id)
    _dns_connector(instance)
    _refuse_unreadable_config(instance)
    svc.update_config(db, instance, {**svc.decrypted_config(instance), "excluded_zones": data.excluded_zones})
    db.commit()
    return {"excluded_zones": data.excluded_zones}


@router.post("/instances/{instance_id}/sync", status_code=202)
def sync_instance(
    instance_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission(Permission.CONNECTORS_SYNC)),
):
    """Manually trigger a full re-sync of all domains from a DNS discovery connector instance."""
    instance = _load_instance(db, current_user, instance_id)
    connector = _get_connector(instance.type)
    if not isinstance(connector, DNSDiscoveryConnector):
        raise HTTPException(status_code=400, detail="Connector does not support domain discovery")
    if not instance.enabled:
        raise HTTPException(status_code=409, detail="Connector instance is disabled")
    if instance.bound_entity_id is not None:
        ok, reason = svc.binding_allowed(db, instance.bound_entity_id)
        if not ok:
            raise HTTPException(status_code=409, detail={"code": "binding_not_allowed", "reason": reason})
    if not connector.is_configured(svc.decrypted_config(instance)):
        raise HTTPException(status_code=400, detail="Connector is not configured")
    background_tasks.add_task(_auto_discover_all_domains, instance.id)
    return {"status": "sync queued"}


@router.delete("/instances/{instance_id}", status_code=204)
def delete_instance(
    instance_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission(Permission.CONNECTORS_CONFIGURE)),
):
    """Refused (409, target ids only) while targets reference the instance:
    disable it instead. `targets.connector_instance_id` is ON DELETE RESTRICT,
    so the database refuses too; the explicit check gives the caller the ids."""
    instance = _load_instance(db, current_user, instance_id)
    if (refusal := _referencing_targets(db, instance.id)) is not None:
        return refusal
    try:
        db.delete(instance)
        db.commit()
    except IntegrityError:
        db.rollback()
        return _referencing_targets(db, instance_id) or JSONResponse(
            status_code=409, content={"detail": "Connector instance is still referenced", "target_ids": []}
        )
    return Response(status_code=204)


def _referencing_targets(db: Session, instance_id: uuid.UUID) -> JSONResponse | None:
    ids = [str(i) for (i,) in db.query(Target.id).filter(Target.connector_instance_id == instance_id).all()]
    if not ids:
        return None
    return JSONResponse(
        status_code=409,
        content={
            "detail": "Connector instance is referenced by targets; disable it instead of deleting it",
            "target_ids": ids,
        },
    )


# ── background sync ───────────────────────────────────────────────────────────


def _auto_discover_all_domains(instance_id: uuid.UUID) -> None:
    """Background task: pull domains from the connector instance, add them as verified targets,
    and immediately write their DNS records as assets via a lightweight sync scan run.

    Each domain is its own unit of work: a failure rolls back that domain only."""
    from datetime import datetime, timezone

    from app.core.database import SessionLocal
    from app.models.scan import ScanKind, ScanRun, ScanStatus
    from app.services.asset_writer import write_assets
    from app.services.target_service import ensure_connector_verified

    db = SessionLocal()
    run = None
    try:
        instance = svc.get(db, instance_id)
        if instance is None or not instance.enabled:
            return
        connector = REGISTRY.get(instance.type)
        if not isinstance(connector, DNSDiscoveryConnector):
            return
        if instance.bound_entity_id is not None and not svc.binding_allowed(db, instance.bound_entity_id)[0]:
            log.warning("Connector sync refused for instance %s: binding no longer allowed", instance_id)
            return
        connector_type = instance.type
        config = svc.decrypted_config(instance)
        domains = connector.list_domains(config)

        if not domains:
            return

        # Create a sync scan run to hold the discovered assets
        now = datetime.now(timezone.utc)
        run = ScanRun(
            id=uuid.uuid4(),
            name=f"Connector Sync: {connector.name}",
            status=ScanStatus.RUNNING,
            kind=ScanKind.MANUAL,
            scope={"domains": domains, "ip_ranges": []},
            started_at=now,
            connectors_used=[connector_type],
        )
        db.add(run)
        db.commit()

        asset_count = 0
        skipped_clash = 0
        for domain in domains:
            try:
                target = ensure_connector_verified(db, domain, instance)
                if target is None:
                    # Zone clash (planning#284 comment 6386279550): the zone is already
                    # a target of a different scope. Skip and log for now; may change;
                    # person-facing flag with the connector_zone slice.
                    skipped_clash += 1
                    continue
                result = connector.discover(domain, config)
                if result.assets:
                    write_assets(db, run.id, result.assets, target_ids=[target.id])
                    asset_count += len(result.assets)
                db.commit()
            except Exception:
                db.rollback()
                log.exception("Connector sync failed for domain %s (instance %s)", domain, instance_id)

        run.status = ScanStatus.COMPLETED
        run.completed_at = datetime.now(timezone.utc)
        db.commit()
        log.info(
            "Connector sync complete: %s — %d domains, %d assets, %d skipped (zone belongs to another scope)",
            connector_type, len(domains), asset_count, skipped_clash,
        )
    except Exception:
        db.rollback()
        log.exception("Connector sync failed for instance %s", instance_id)
        if run is not None:
            try:
                run.status = ScanStatus.FAILED
                db.commit()
            except Exception:
                db.rollback()
                log.exception("Could not mark connector sync run %s failed", run.id)
    finally:
        db.close()
