import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import require_role
from app.connectors.base import DNSDiscoveryConnector
from app.connectors.cloudflare import CloudflareConnector
from app.connectors.fortimanager import FortiManagerConnector
from app.connectors.mailtrap import MailtrapConnector
from app.connectors.nuclei import NucleiConnector
from app.connectors.tenable import TenableConnector
from app.connectors.wiz import WizConnector
from app.core.database import get_db
from app.models.scan import ScanRun, ScanStatus
from app.models.user import UserRole
from app.schemas.connector import ConnectorConfigUpdate, ConnectorConfigResponse, ConnectorSummary
from app.services import connector_config as svc

router = APIRouter()

REGISTRY: dict = {
    "cloudflare": CloudflareConnector(),
    "wiz": WizConnector(),
    "fortimanager": FortiManagerConnector(),
    "tenable": TenableConnector(),
    "nuclei": NucleiConnector(),
    "mailtrap": MailtrapConnector(),
}


@router.get("/", response_model=list[ConnectorSummary])
def list_connectors(db: Session = Depends(get_db)):
    result = []
    db_rows = {r.connector_id: r for r in svc.get_all(db)}
    for key, connector in REGISTRY.items():
        row = db_rows.get(key)
        result.append(
            ConnectorSummary(
                id=key,
                name=connector.name,
                description=connector.description,
                phase=getattr(connector, "phase", "unknown"),
                enabled=row.enabled if row else False,
                configured=connector.is_configured(),
                schema=connector.get_config_schema(),
            )
        )
    return result


@router.get("/domains")
def list_available_domains(db: Session = Depends(get_db)):
    """
    Returns all verified targets (connector-sourced + manually verified).
    Used to populate the new scan dialog.
    """
    from app.models.target import Target, TargetType
    result: list[dict] = []

    # Connector-sourced domains
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

    # Manually verified targets (TXT / acknowledged)
    connector_values = {r["domain"] for r in result}
    manual = db.query(Target).filter(
        Target.verified == True,  # noqa: E712
        Target.connector_id == None,  # noqa: E711
    ).all()
    for t in manual:
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


@router.post("/{connector_id}/sync", status_code=202)
def sync_connector(
    connector_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    """Manually trigger a full re-sync of all domains from a DNS discovery connector."""
    connector = _get_connector(connector_id)
    if not isinstance(connector, DNSDiscoveryConnector):
        raise HTTPException(status_code=400, detail="Connector does not support domain discovery")
    if not connector.is_configured():
        raise HTTPException(status_code=400, detail="Connector is not configured")
    background_tasks.add_task(
        _auto_discover_all_domains, connector_id, connector, current_user.id
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
    created_by_id: uuid.UUID,
) -> None:
    """Background task: list all domains from the connector and launch a discovery scan."""
    from app.core.database import SessionLocal
    from app.services import scan_executor
    from app.services.connector_config import get_decrypted_config

    db = SessionLocal()
    try:
        config = get_decrypted_config(db, connector_id) or {}
        domains = connector.list_domains(config)
        if not domains:
            return

        # Auto-verify every domain sourced from this connector
        from app.services.target_service import ensure_connector_verified
        for domain in domains:
            ensure_connector_verified(db, domain, connector_id)

        run = ScanRun(
            id=uuid.uuid4(),
            name=f"Auto-sync: {connector.name}",
            status=ScanStatus.PENDING,
            scope={"domains": domains, "ip_ranges": []},
            created_by_id=created_by_id,
        )
        db.add(run)
        db.commit()

        scan_executor.launch(run.id, run.scope, REGISTRY)
    finally:
        db.close()
