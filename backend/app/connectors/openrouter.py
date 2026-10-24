"""OpenRouter connector — admin-UI plumbing only (planning#140 slice 1).

This is config/test plumbing exactly like `vulncheck.py`'s: it exists so
the API key is configurable from Admin -> Connectors and so `Connectors.tsx`
has a card to enable/disable/test it. It does NOT implement the actual
inference path — that is `app.services.llm_connector` (a plain service, not
an `EnrichmentConnector`; see that module's docstring for why). Declaring
this as a bare `BaseConnector` keeps it out of every phase-shaped connector
loop (discovery/enrich/scan) the same way VulnCheck's own comment explains.

## Where the key comes from (R5)

The API key comes ONLY from the connector instance's stored (encrypted)
config: `is_configured(config)` reads `config["api_key"]` and nothing else,
and `llm_connector.py` reads the same instance. A key sitting in `.env` must
not count as "configured" here, so `env_key_map` is kept for the field list
but one-time environment seeding (`connector_instances.seed_from_env`)
skips this connector entirely.
"""

import logging
from typing import Any

import httpx

from app.connectors.base import BaseConnector, ConnectorPhase, TestResult

log = logging.getLogger(__name__)

_KEY_INFO_URL = "https://openrouter.ai/api/v1/key"


class OpenRouterConnector(BaseConnector):
    name = "OpenRouter"
    description = "LLM inference — role-routed, ZDR-enforced (AI core, planning#140)"
    phase = ConnectorPhase.INFERENCE
    env_key_map = {"api_key": "OPENROUTER_API_KEY"}

    def get_config_schema(self) -> dict[str, Any]:
        return {
            "api_key": {
                "label": "API Key",
                "type": "secret",
                "help": "openrouter.ai → Keys. Stored encrypted; never read from .env.",
            },
        }

    def is_configured(self, config: dict[str, Any]) -> bool:
        # R5: the instance config only; see the module docstring.
        return bool((config or {}).get("api_key"))

    def _test(self, config: dict[str, Any]) -> TestResult:
        # From the decrypted instance config the Test endpoint passes in
        # (R5: never the environment).
        api_key = (config or {}).get("api_key")
        if not api_key:
            return TestResult(success=False, message="OpenRouter API key not configured")

        try:
            resp = httpx.get(
                _KEY_INFO_URL,
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=10,
            )
        except Exception as exc:
            # Never log the key — the exception text from httpx never
            # includes request headers, only connection-level detail.
            return TestResult(success=False, message=str(exc))

        if resp.status_code == 401:
            return TestResult(success=False, message="key rejected")
        if resp.status_code != 200:
            return TestResult(
                success=False,
                message=f"OpenRouter returned HTTP {resp.status_code}",
                details={"status": resp.status_code},
            )

        try:
            data = resp.json().get("data", {})
        except ValueError:
            data = {}
        limit_remaining = data.get("limit_remaining")
        is_free_tier = data.get("is_free_tier")
        return TestResult(
            success=True,
            message=f"Connected — limit_remaining={limit_remaining}, is_free_tier={is_free_tier}",
            details={"limit_remaining": limit_remaining, "is_free_tier": is_free_tier},
        )
