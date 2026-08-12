import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_role
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
from app.connectors.tlsx import TlsxConnector
from app.connectors.shodan import ShodanConnector
from app.connectors.tenable import TenableConnector
from app.connectors.vulncheck import VulnCheckConnector
from app.connectors.wiz import WizConnector
from app.core.database import get_db
from app.models.user import UserRole
from pydantic import BaseModel
from app.schemas.connector import ConnectorConfigUpdate, ConnectorConfigResponse, ConnectorSummary
from app.services import connector_config as svc

router = APIRouter()

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
}


@router.get("/", response_model=list[ConnectorSummary])
def list_connectors(db: Session = Depends(get_db), _=Depends(get_current_user)):
    result = []
    db_rows = {r.connector_id: r for r in svc.get_all(db)}
    current_tier = aggr_svc.normalize(app_settings_svc.get(db, "aggressiveness"))
    tier_profile = aggr_svc.profile(current_tier)
    for key, connector in REGISTRY.items():
        row = db_rows.get(key)
        # A connector is "disabled at this tier" when the global tier's
        # profile has a slot for the connector ID with `enabled: False`.
        # Generic so new tier-gated connectors (e.g. nmap later) inherit
        # this behaviour without touching this code.
        slot = tier_profile.get(key)
        disabled_at_tier = isinstance(slot, dict) and slot.get("enabled") is False
        result.append(
            ConnectorSummary(
                id=key,
                name=connector.name,
                description=connector.description,
                phase=getattr(connector, "phase", "unknown"),
                enabled=row.enabled if row else False,
                configured=connector.is_configured(),
                core=getattr(connector, "core", False),
                config_schema=connector.get_config_schema(),
                disabled_at_current_tier=disabled_at_tier,
                current_tier=current_tier,
            )
        )
    return result


@router.get("/domains")
def list_available_domains(db: Session = Depends(get_db), _=Depends(get_current_user)):
    """
    Returns targets available for scanning.
    In strict mode: verified targets only.
    In acknowledge/disabled mode: all targets in the system (adding one is confirmation enough).
    """
    from app.models.target import Target, TargetType
    from app.services import app_settings as settings_svc

    auth_mode = settings_svc.get(db, "scan_authorisation_mode") or "disabled"
    result: list[dict] = []

    # Connector-sourced domains (always included when connector is enabled)
    enabled_ids = {r.connector_id for r in svc.get_all(db) if r.enabled}
    for cid, connector in REGISTRY.items():
        if cid not in enabled_ids or not isinstance(connector, DNSDiscoveryConnector):
            continue
        if not connector.is_configured():
            continue
        config = svc.get_decrypted_config(db, cid) or {}
        domains = connector.list_domains(config)
        for domain in domains:
            result.append({"domain": domain, "connector_id": cid, "connector_name": connector.name})

    # Manual targets — filter by verification state only in strict mode
    connector_values = {r["domain"] for r in result}
    manual_q = db.query(Target).filter(Target.connector_id == None)  # noqa: E711
    if auth_mode == "strict":
        manual_q = manual_q.filter(Target.verified == True)  # noqa: E712
    for t in manual_q.all():
        if t.value not in connector_values:
            label = "Manual" if t.type == TargetType.DOMAIN else t.type.upper()
            result.append({"domain": t.value, "connector_id": None, "connector_name": label})

    return result


@router.get("/{connector_id}/config", response_model=ConnectorConfigResponse)
def get_config(
    connector_id: str,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    connector = _get_connector(connector_id)
    config = svc.get_decrypted_config(db, connector_id)
    row = svc.get_one(db, connector_id)
    return ConnectorConfigResponse(
        connector_id=connector_id,
        enabled=row.enabled if row else False,
        config=svc.mask_config(config, connector.get_config_schema()),
    )


@router.put("/{connector_id}/config", response_model=ConnectorConfigResponse)
def save_config(
    connector_id: str,
    data: ConnectorConfigUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    connector = _get_connector(connector_id)
    was_configured = connector.is_configured()

    # Merge with existing config — don't overwrite secrets still showing the masked placeholder
    schema = connector.get_config_schema()
    existing = svc.get_decrypted_config(db, connector_id) or {}
    merged = {**existing}
    for k, v in data.config.items():
        if schema.get(k, {}).get("type") == "secret" and v == "**configured**":
            pass  # keep existing value
        else:
            merged[k] = v

    row = svc.upsert_config(db, connector_id, merged)

    # Propagate merged values into the in-process secrets override layer
    from app.core.secrets import set_db_override
    env_key_map: dict = getattr(connector, "env_key_map", {})
    for field_name, env_key in env_key_map.items():
        value = merged.get(field_name)
        set_db_override(env_key, value if value else None)

    masked = svc.mask_config(merged, connector.get_config_schema())
    return ConnectorConfigResponse(connector_id=connector_id, enabled=row.enabled, config=masked)


@router.post("/{connector_id}/enable")
def enable_connector(
    connector_id: str,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    _get_connector(connector_id)
    svc.set_enabled(db, connector_id, True)
    return {"status": "enabled"}


@router.post("/{connector_id}/disable")
def disable_connector(
    connector_id: str,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    _get_connector(connector_id)
    svc.set_enabled(db, connector_id, False)
    return {"status": "disabled"}


@router.post("/{connector_id}/test")
def test_connector(
    connector_id: str,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    connector = _get_connector(connector_id)
    config = svc.get_decrypted_config(db, connector_id) or {}
    result = connector.test(config)
    return {"success": result.success, "message": result.message, "details": result.details}


class ZonesUpdate(BaseModel):
    excluded_zones: list[str]


@router.get("/{connector_id}/zones")
def list_connector_zones(
    connector_id: str,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    """Return all zones from a DNS connector with their current exclusion state."""
    connector = _get_connector(connector_id)
    if not isinstance(connector, DNSDiscoveryConnector):
        raise HTTPException(status_code=400, detail="Connector does not support zone discovery")
    if not connector.is_configured():
        raise HTTPException(status_code=400, detail="Connector is not configured")

    config = svc.get_decrypted_config(db, connector_id) or {}
    excluded: set[str] = set(config.get("excluded_zones", []))

    # Fetch all zones from the provider, ignoring stored exclusions
    all_zones = connector.list_domains({**config, "excluded_zones": []})

    return [{"name": z, "excluded": z in excluded} for z in all_zones]


@router.put("/{connector_id}/zones")
def save_connector_zones(
    connector_id: str,
    data: ZonesUpdate,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    """Save zone exclusions for a DNS connector."""
    connector = _get_connector(connector_id)
    if not isinstance(connector, DNSDiscoveryConnector):
        raise HTTPException(status_code=400, detail="Connector does not support zone discovery")

    config = svc.get_decrypted_config(db, connector_id) or {}
    svc.upsert_config(db, connector_id, {**config, "excluded_zones": data.excluded_zones})
    return {"excluded_zones": data.excluded_zones}


@router.post("/{connector_id}/sync", status_code=202)
def sync_connector(
    connector_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    """Manually trigger a full re-sync of all domains from a DNS discovery connector."""
    connector = _get_connector(connector_id)
    if not isinstance(connector, DNSDiscoveryConnector):
        raise HTTPException(status_code=400, detail="Connector does not support domain discovery")
    if not connector.is_configured():
        raise HTTPException(status_code=400, detail="Connector is not configured")
    background_tasks.add_task(
        _auto_discover_all_domains, connector_id, connector
    )
    return {"status": "sync queued"}


# ── helpers ───────────────────────────────────────────────────────────────────

def _get_connector(connector_id: str):
    connector = REGISTRY.get(connector_id)
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")
    return connector


def _auto_discover_all_domains(
    connector_id: str,
    connector: DNSDiscoveryConnector,
) -> None:
    """Background task: pull domains from the connector, add them as verified targets,
    and immediately write their DNS records as assets via a lightweight sync scan run."""
    import logging
    from datetime import datetime, timezone

    from app.core.database import SessionLocal
    from app.models.scan import ScanKind, ScanRun, ScanStatus
    from app.services.asset_writer import write_assets
    from app.services.connector_config import get_decrypted_config
    from app.services.target_service import ensure_connector_verified

    log = logging.getLogger(__name__)
    db = SessionLocal()
    run = None
    try:
        config = get_decrypted_config(db, connector_id) or {}
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
            connectors_used=[connector_id],
        )
        db.add(run)
        db.commit()

        all_assets = []
        for domain in domains:
            target = ensure_connector_verified(db, domain, connector_id)
            try:
                result = connector.discover(domain, config)
                if result.assets:
                    write_assets(db, run.id, result.assets, target_ids=[target.id])
                    all_assets.extend(result.assets)
            except Exception:
                log.exception("Discover failed for domain %s during sync", domain)

        run.status = ScanStatus.COMPLETED
        run.completed_at = datetime.now(timezone.utc)
        db.commit()
        log.info(
            "Connector sync complete: %s — %d domains, %d assets",
            connector_id, len(domains), len(all_assets),
        )
    except Exception:
        log.exception("Connector sync failed for %s", connector_id)
        if run is not None:
            try:
                run.status = ScanStatus.FAILED
                db.commit()
            except Exception:
                pass
    finally:
        db.close()
