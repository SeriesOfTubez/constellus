from app.connectors.base import BaseConnector, TestResult
from app.core.secrets import get_secret


class FortiManagerConnector(BaseConnector):
    name = "FortiManager"
    env_key_map = {
        "connector_url": "FORTIMANAGER_CONNECTOR_URL",
        "api_key": "FORTIMANAGER_CONNECTOR_API_KEY",
    }
    description = (
        "On-premises asset correlation — maps public IPs to internal hosts via VIP objects, "
        "retrieves firewall ACLs and IPS sensor status"
    )

    def get_config_schema(self) -> dict:
        return {
            "connector_url": {
                "label": "Connector URL",
                "type": "string",
                "help": "Internal URL of the FortiManager connector sidecar (e.g. http://fortimanager-connector:8080)",
            },
            "api_key": {
                "label": "Connector API Key",
                "type": "secret",
                "help": "API key for authenticating to the FortiManager connector sidecar",
            },
        }

    def is_configured(self) -> bool:
        return bool(
            get_secret("FORTIMANAGER_CONNECTOR_URL")
            and get_secret("FORTIMANAGER_CONNECTOR_API_KEY")
        )

    def test(self) -> TestResult:
        import httpx

        url = get_secret("FORTIMANAGER_CONNECTOR_URL")
        api_key = get_secret("FORTIMANAGER_CONNECTOR_API_KEY")

        if not url or not api_key:
            return TestResult(success=False, message="FortiManager connector not configured")

        try:
            response = httpx.get(
                f"{url}/health",
                headers={"X-API-Key": api_key},
                timeout=10,
            )
            if response.status_code == 200:
                return TestResult(success=True, message="Connector reachable and authenticated")
            return TestResult(
                success=False,
                message="Connector unreachable or auth failed",
                details={"status": response.status_code},
            )
        except Exception as e:
            return TestResult(success=False, message=str(e))
