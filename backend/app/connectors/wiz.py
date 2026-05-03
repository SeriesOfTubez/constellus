from app.connectors.base import BaseConnector, TestResult
from app.core.secrets import get_secret


class WizConnector(BaseConnector):
    name = "Wiz"
    description = "Cloud asset correlation — maps public IPs to cloud resources and Wiz findings"

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

    def test(self) -> TestResult:
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
