"""OpenRouter connector — admin-UI plumbing only (planning#140 slice 1).

This is config/test plumbing exactly like `vulncheck.py`'s: it exists so
the API key is configurable from Admin -> Connectors and so `Connectors.tsx`
has a card to enable/disable/test it. It does NOT implement the actual
inference path — that is `app.services.llm_connector` (a plain service, not
an `EnrichmentConnector`; see that module's docstring for why). Declaring
this as a bare `BaseConnector` keeps it out of every phase-shaped connector
loop (discovery/enrich/scan) the same way VulnCheck's own comment explains.

## Why `env_key_map` exists here even though R5 forbids reading it back

`app.services.connector_config.load_overrides_from_db` (called at startup)
and `api/connectors.py`'s save-config path both use `env_key_map` to push a
saved secret into `app.core.secrets`'s in-process override layer — that
plumbing is generic and this connector needs it to make the Test button and
`is_configured()` line up with what `llm_connector.py` will later read
straight out of `connector_configs` for the real call. But `is_configured()`
below does NOT call `get_secret("OPENROUTER_API_KEY")` (which would also
return true for a bare `.env` value) — it calls
`app.core.secrets.has_db_override`, which is only ever true once a value
has actually been saved through the DB-config path. A key sitting in
`.env` must not count as "configured" here, because R5 requires
`llm_connector.py` to read the API key from `connector_configs` only, never
from `os.environ`/`get_secret`/`.env` — so this connector's own
"configured" badge would otherwise lie about what the real call path can
see.
"""

import logging
from typing import Any

import httpx

from app.connectors.base import BaseConnector, ConnectorPhase, TestResult
from app.core.secrets import has_db_override

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

    def is_configured(self) -> bool:
        # See the module docstring's "Why env_key_map exists here even
        # though R5 forbids reading it back" — `has_db_override`, not
        # `get_secret`, is the whole point.
        return has_db_override("OPENROUTER_API_KEY")

    def _test(self, config: dict[str, Any]) -> TestResult:
        # From the decrypted connector_configs row the Test endpoint passes
        # in - NOT `get_secret`, which falls back to `.env` and would let
        # this button validate a key the real call path never uses (R5).
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
