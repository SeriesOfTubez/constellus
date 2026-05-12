from typing import Any

from app.connectors.base import (
    DiscoveredAsset,
    EnrichmentConnector,
    PhaseResult,
    TestResult,
)
from app.core.secrets import get_secret


class TenableConnector(EnrichmentConnector):
    name = "Tenable"
    env_key_map = {"api_key": "TENABLE_API_KEY", "api_secret": "TENABLE_API_SECRET"}
    description = "Patch and vulnerability correlation — maps internal IPs to Tenable assets and findings"

    def get_config_schema(self) -> dict:
        return {
            "api_key": {
                "label": "API Key",
                "type": "secret",
                "help": "Tenable.io API key",
            },
            "api_secret": {
                "label": "API Secret",
                "type": "secret",
                "help": "Tenable.io API secret",
            },
        }

    def is_configured(self) -> bool:
        return bool(get_secret("TENABLE_API_KEY") and get_secret("TENABLE_API_SECRET"))

    def _test(self, config: dict) -> TestResult:
        import httpx

        api_key = get_secret("TENABLE_API_KEY")
        api_secret = get_secret("TENABLE_API_SECRET")

        if not api_key or not api_secret:
            return TestResult(success=False, message="Tenable credentials not configured")

        try:
            response = httpx.get(
                "https://cloud.tenable.com/session",
                headers={"X-ApiKeys": f"accessKey={api_key}; secretKey={api_secret}"},
                timeout=10,
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
        Correlates discovered IP addresses against Tenable.io asset inventory.
        Returns findings for any IPs that have open vulnerabilities in Tenable.

        Full implementation: query /assets/export and /vulns/export, join on IP.
        Stubbed here — add Tenable API calls when credentials are available.
        """
        import httpx

        api_key = get_secret("TENABLE_API_KEY")
        api_secret = get_secret("TENABLE_API_SECRET")
        if not api_key or not api_secret:
            return PhaseResult()

        ip_assets = [a for a in assets if a.asset_type == "ip_address"]
        if not ip_assets:
            return PhaseResult()

        headers = {"X-ApiKeys": f"accessKey={api_key}; secretKey={api_secret}"}
        target_ips = {a.value for a in ip_assets}

        # TODO: implement Tenable asset + vuln export and correlation
        # Pattern:
        #   1. POST /assets/export  → poll until ready → stream results
        #   2. Filter to IPs in target_ips
        #   3. POST /vulns/export   → poll → stream results
        #   4. For each vuln, emit a DiscoveredFinding with source="tenable"
        _ = (httpx, target_ips, headers)  # silence unused warnings until implemented

        return PhaseResult()
