from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import require_role
from app.connectors.cloudflare import CloudflareConnector
from app.connectors.fortimanager import FortiManagerConnector
from app.connectors.nuclei import NucleiConnector
from app.connectors.tenable import TenableConnector
from app.connectors.wiz import WizConnector
from app.core.database import get_db
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
                enabled=row.enabled if row else False,
                configured=connector.is_configured(),
                schema=connector.get_config_schema(),
            )
        )
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
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    connector = _get_connector(connector_id)
    row = svc.upsert_config(db, connector_id, data.config)

    # Propagate new values into the in-process secrets override layer
    env_key_map: dict = getattr(connector, "env_key_map", {})
    from app.core.secrets import set_db_override
    for field_name, env_key in env_key_map.items():
        value = data.config.get(field_name)
        set_db_override(env_key, value if value else None)

    masked = svc.mask_config(data.config, connector.get_config_schema())
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
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    connector = _get_connector(connector_id)
    result = connector.test()
    return {"success": result.success, "message": result.message, "details": result.details}


def _get_connector(connector_id: str):
    connector = REGISTRY.get(connector_id)
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")
    return connector
