from typing import Any

from app.connectors.base import (
    DiscoveredAsset,
    EnrichmentConnector,
    PhaseResult,
    TestResult,
)
from app.core.secrets import get_secret


class FortiManagerConnector(EnrichmentConnector):
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

    def _test(self, config: dict) -> TestResult:
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

    def enrich(self, assets: list[DiscoveredAsset], config: dict[str, Any]) -> PhaseResult:
        """
        Maps discovered public IPs to internal hosts via FortiManager VIP objects.
        Returns INTERNAL_HOST assets and any firewall/IPS findings.

        Full implementation: call the FortiManager connector sidecar's /vips and /ips endpoints.
        Stubbed here — add sidecar calls when connector is deployed.
        """
        import httpx

        url = get_secret("FORTIMANAGER_CONNECTOR_URL")
        api_key = get_secret("FORTIMANAGER_CONNECTOR_API_KEY")
        if not url or not api_key:
            return PhaseResult()

        ip_assets = [a for a in assets if a.asset_type == "ip_address"]
        if not ip_assets:
            return PhaseResult()

        # TODO: implement FortiManager sidecar enrichment
        # Pattern:
        #   1. POST {url}/vips with list of public IPs → get internal host mappings
        #   2. For each mapping, emit INTERNAL_HOST asset with parent = public IP
        #   3. GET {url}/ips/findings → emit findings for any active IPS alerts
        _ = (httpx, api_key)

        return PhaseResult()
