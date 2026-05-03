from app.connectors.base import BaseConnector, TestResult
from app.core.secrets import get_secret


class TenableConnector(BaseConnector):
    name = "Tenable"
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

    def test(self) -> TestResult:
        import httpx

        api_key = get_secret("TENABLE_API_KEY")
        api_secret = get_secret("TENABLE_API_SECRET")

        if not api_key or not api_secret:
            return TestResult(success=False, message="Tenable credentials not configured")

        try:
            response = httpx.get(
                "https://cloud.tenable.com/session",
                headers={
                    "X-ApiKeys": f"accessKey={api_key}; secretKey={api_secret}",
                },
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
