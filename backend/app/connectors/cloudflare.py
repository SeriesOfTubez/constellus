from app.connectors.base import BaseConnector, TestResult
from app.core.secrets import get_secret


class CloudflareConnector(BaseConnector):
    name = "Cloudflare"
    description = "DNS record discovery and WAF proxy status per record"
    env_key_map = {"api_token": "CLOUDFLARE_API_TOKEN"}

    def get_config_schema(self) -> dict:
        return {
            "api_token": {
                "label": "API Token",
                "type": "secret",
                "help": "Cloudflare API token with Zone.DNS read permission",
            },
            "zone_ids": {
                "label": "Zone IDs",
                "type": "list",
                "help": "One or more Cloudflare zone IDs to enumerate",
            },
        }

    def is_configured(self) -> bool:
        return bool(get_secret("CLOUDFLARE_API_TOKEN"))

    def test(self) -> TestResult:
        import httpx

        token = get_secret("CLOUDFLARE_API_TOKEN")
        if not token:
            return TestResult(success=False, message="API token not configured")

        try:
            response = httpx.get(
                "https://api.cloudflare.com/client/v4/user/tokens/verify",
                headers={"Authorization": f"Bearer {token}"},
                timeout=10,
            )
            data = response.json()
            if response.status_code == 200 and data.get("success"):
                return TestResult(success=True, message="Connected successfully")
            return TestResult(
                success=False,
                message="Token verification failed",
                details={"status": response.status_code},
            )
        except Exception as e:
            return TestResult(success=False, message=str(e))
