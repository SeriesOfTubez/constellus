"""VulnCheck connector — vulnerability intelligence (NVD2 + KEV + XDB).

Wraps VulnCheck's API as a first-class connector so the API key is
configurable from Admin → Connectors, mirroring the Certspotter pattern.
Unlike Certspotter, VulnCheck has no anonymous tier — a free community key
(vulncheck.com, 1000 req/min) is required for any lookup.

This connector is config/test plumbing only. It does NOT implement enrich():
the actual NVD2/KEV/XDB lookups run as an explicit post-scan step (see
app.services.cve_enrichment / the Constellus Risk Score pipeline), the same
way eol_enrichment and cve_enrichment call their APIs directly via
get_secret() + connector_get() rather than through the generic Phase 2
enrichment loop. Declaring it as a plain BaseConnector — not an
EnrichmentConnector — keeps it out of that loop.
"""

import logging
from typing import Any

import httpx

from app.connectors.base import BaseConnector, ConnectorPhase, TestResult
from app.core.secrets import get_secret

log = logging.getLogger(__name__)

_API_BASE = "https://api.vulncheck.com/v3"


class VulnCheckConnector(BaseConnector):
    name = "VulnCheck"
    description = "Vulnerability intelligence — NVD2 CVSS/CWE data, KEV, and exploit DB (XDB) for the Constellus Risk Score"
    phase = ConnectorPhase.ENRICHMENT
    core = True
    env_key_map = {"api_key": "VULNCHECK_API_KEY"}

    def get_config_schema(self) -> dict:
        return {
            "api_key": {
                "label": "API Key",
                "type": "secret",
                "help": (
                    "Required. Free community key at vulncheck.com/login (1000 req/min) — "
                    "powers CVSS/EPSS/KEV context and the Constellus Risk Score. "
                    "Without it, findings have no severity ranking or prioritization."
                ),
            },
        }

    def is_configured(self) -> bool:
        return bool(get_secret("VULNCHECK_API_KEY"))

    def _test(self, config: dict[str, Any]) -> TestResult:
        api_key = get_secret("VULNCHECK_API_KEY")
        if not api_key:
            return TestResult(success=False, message="VulnCheck API key not configured")

        try:
            resp = httpx.get(
                f"{_API_BASE}/index",
                headers={"Accept": "application/json", "Authorization": f"Bearer {api_key}"},
                timeout=10,
            )
            if resp.status_code == 200:
                return TestResult(success=True, message="Connected — NVD2/KEV/XDB lookups enabled")
            if resp.status_code == 401:
                return TestResult(success=False, message="Authentication failed — check the API key")
            return TestResult(
                success=False,
                message=f"VulnCheck returned HTTP {resp.status_code}",
                details={"status": resp.status_code},
            )
        except Exception as exc:
            return TestResult(success=False, message=str(exc))
