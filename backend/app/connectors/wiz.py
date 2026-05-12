from typing import Any

from app.connectors.base import (
    DiscoveredAsset,
    EnrichmentConnector,
    PhaseResult,
    TestResult,
)
from app.core.secrets import get_secret


class WizConnector(EnrichmentConnector):
    name = "Wiz"
    description = "Cloud asset correlation — maps public IPs to cloud resources and Wiz findings"
    env_key_map = {
        "client_id": "WIZ_CLIENT_ID",
        "client_secret": "WIZ_CLIENT_SECRET",
        "api_endpoint": "WIZ_API_ENDPOINT",
    }

    def get_config_schema(self) -> dict:
        return {
            "client_id": {
                "label": "Client ID",
                "type": "secret",
                "help": "Wiz service account client ID",
            },
            "client_secret": {
                "label": "Client Secret",
                "type": "secret",
                "help": "Wiz service account client secret",
            },
            "api_endpoint": {
                "label": "API Endpoint",
                "type": "string",
                "help": "Wiz API endpoint URL (e.g. https://api.us1.app.wiz.io/graphql)",
            },
        }

    def is_configured(self) -> bool:
        return bool(get_secret("WIZ_CLIENT_ID") and get_secret("WIZ_CLIENT_SECRET"))

    def _test(self, config: dict) -> TestResult:
        import httpx

        client_id = get_secret("WIZ_CLIENT_ID")
        client_secret = get_secret("WIZ_CLIENT_SECRET")

        if not client_id or not client_secret:
            return TestResult(success=False, message="Wiz credentials not configured")

        try:
            response = httpx.post(
                "https://auth.app.wiz.io/oauth/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "audience": "wiz-api",
                },
                timeout=15,
            )
            if response.status_code == 200:
                return TestResult(success=True, message="Connected successfully")
            return TestResult(
                success=False,
                message="Authentication failed",
                details={"status": response.status_code},
            )
        except Exception as e:
            return TestResult(success=False, message=str(e))

    def enrich(self, assets: list[DiscoveredAsset], config: dict[str, Any]) -> PhaseResult:
        """
        Correlates discovered IPs against Wiz cloud inventory.
        Returns cloud resource context and any Wiz issues for matched assets.

        Full implementation: query Wiz GraphQL API for cloudResources filtered by publicIpAddress.
        Stubbed here — add GraphQL calls when credentials are available.
        """
        import httpx

        client_id = get_secret("WIZ_CLIENT_ID")
        client_secret = get_secret("WIZ_CLIENT_SECRET")
        api_endpoint = get_secret("WIZ_API_ENDPOINT")
        if not client_id or not client_secret or not api_endpoint:
            return PhaseResult()

        ip_assets = [a for a in assets if a.asset_type == "ip_address"]
        if not ip_assets:
            return PhaseResult()

        # TODO: implement Wiz GraphQL enrichment
        # Pattern:
        #   1. POST /oauth/token → get bearer token
        #   2. GraphQL query cloudResources(where: {publicIpAddress: {in: [ips]}})
        #   3. For each matched resource, emit CLOUD_RESOURCE asset + any open issues as findings
        _ = (httpx, api_endpoint)

        return PhaseResult()
