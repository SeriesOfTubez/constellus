from fastapi import APIRouter, HTTPException
from app.connectors.cloudflare import CloudflareConnector
from app.connectors.wiz import WizConnector
from app.connectors.fortimanager import FortiManagerConnector
from app.connectors.tenable import TenableConnector
from app.connectors.nuclei import NucleiConnector

router = APIRouter()

REGISTRY: dict = {
    "cloudflare": CloudflareConnector(),
    "wiz": WizConnector(),
    "fortimanager": FortiManagerConnector(),
    "tenable": TenableConnector(),
    "nuclei": NucleiConnector(),
}


@router.get("/")
def list_connectors():
    return [
        {
            "id": key,
            "name": connector.name,
            "description": connector.description,
            "configured": connector.is_configured(),
            "schema": connector.get_config_schema(),
        }
        for key, connector in REGISTRY.items()
    ]


@router.post("/{connector_id}/test")
def test_connector(connector_id: str):
    connector = REGISTRY.get(connector_id)
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")
    result = connector.test()
    return {"success": result.success, "message": result.message, "details": result.details}
