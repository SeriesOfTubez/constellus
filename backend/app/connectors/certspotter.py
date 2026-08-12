"""Certificate Transparency (Certspotter) discovery connector.

Wraps SSLMate's Certspotter API as a first-class connector so the API token
is configurable from Admin → Connectors. Unlike the other discovery
connectors, this one works with no configuration — Certspotter's free tier
returns CT log data for any public domain. Setting a free API token raises
the rate limit from 100/hr → 1000/hr.

The connector exposes the duck-typed `index_lookup` method that the scan
executor walks (same pattern Shodan uses for /dns/domain). It does NOT
implement enrich(): CT is purely a passive subdomain discovery source.

Actual network calls are gated by `app.services.ct_refresher`, which keeps
`ct_query_cache` warm asynchronously to respect the rate limit. The
`index_lookup` call here is a cache read — it never blocks on Certspotter.
"""

import logging
from typing import Any

import httpx

from app.connectors.base import (
    BaseConnector,
    ConnectorPhase,
    PhaseResult,
    TestResult,
)
from app.core.secrets import get_secret

log = logging.getLogger(__name__)


class CertspotterConnector(BaseConnector):
    name = "Certificate Transparency"
    description = "Passive subdomain enumeration via SSLMate's Certspotter API (CT logs)"
    phase = ConnectorPhase.DISCOVERY
    env_key_map = {"api_key": "CERTSPOTTER_API_TOKEN"}

    def get_config_schema(self) -> dict:
        return {
            "api_key": {
                "label": "API Token (optional)",
                "type": "secret",
                "help": (
                    "Optional. Free signup at sslmate.com/signup?for=certspotter_api raises the "
                    "rate limit from 100 req/hr to 1000 req/hr. Works without a token but the "
                    "background refresher fills the cache more slowly."
                ),
            },
        }

    def is_configured(self) -> bool:
        # No required configuration — Certspotter accepts anonymous calls.
        return True

    def _test(self, config: dict[str, Any]) -> TestResult:
        token = get_secret("CERTSPOTTER_API_TOKEN")
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            resp = httpx.get(
                "https://api.certspotter.com/v1/issuances",
                params={"domain": "example.com", "include_subdomains": "false"},
                headers=headers,
                timeout=10,
            )
            if resp.status_code == 200:
                msg = (
                    "Authenticated — rate limit raised to ~1000 req/hr"
                    if token
                    else "Unauthenticated — rate limit ~100 req/hr. Add an API token for 10x."
                )
                return TestResult(success=True, message=msg)
            if resp.status_code == 429:
                return TestResult(
                    success=False,
                    message="Rate limit reached. Wait an hour or add an API token to raise the cap.",
                )
            return TestResult(
                success=False,
                message=f"Certspotter returned HTTP {resp.status_code}",
            )
        except Exception as exc:
            return TestResult(success=False, message=str(exc))

    def index_lookup(self, domain: str, config: dict[str, Any]) -> PhaseResult:
        """Read CT data from the local ct_query_cache. Never hits the API.

        The cache is filled by the ct_refresher background task and by the
        target-add hook (which calls cert_transparency.prime_cache for the
        new target's first run). A cache miss here just means CT data
        isn't available yet for this domain.
        """
        from app.services.discovery import cert_transparency
        owned_domains: frozenset[str] = config.get("_owned_domains") or frozenset()
        return cert_transparency.run(domain, owned_domains=owned_domains)
