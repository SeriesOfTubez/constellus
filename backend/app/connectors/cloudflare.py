import httpx
from typing import Any

from app.connectors.base import (
    DNS_KEEP_TYPES,
    DNSDiscoveryConnector,
    DiscoveredAsset,
    PhaseResult,
    TestResult,
    is_dns_policy_name,
    is_provider_managed_mx,
)
from app.connectors.http import connector_get
from app.core.secrets import get_secret
from app.models.asset import AssetType

_BASE = "https://api.cloudflare.com/client/v4"


class CloudflareConnector(DNSDiscoveryConnector):
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
        }

    def is_configured(self) -> bool:
        return bool(get_secret("CLOUDFLARE_API_TOKEN"))

    def _test(self, config: dict) -> TestResult:
        # Direct httpx — fast failure preferred for UI test button
        token = get_secret("CLOUDFLARE_API_TOKEN")
        if not token:
            return TestResult(success=False, message="API token not configured")
        try:
            response = httpx.get(
                f"{_BASE}/user/tokens/verify",
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

    def list_domains(self, config: dict[str, Any]) -> list[str]:
        token = get_secret("CLOUDFLARE_API_TOKEN")
        if not token:
            return []
        headers = {"Authorization": f"Bearer {token}"}
        excluded: set[str] = set(config.get("excluded_zones", []))
        try:
            domains: list[str] = []
            page = 1
            while True:
                resp = connector_get(
                    f"{_BASE}/zones",
                    headers=headers,
                    params={"per_page": 50, "page": page, "status": "active"},
                    timeout=10,
                )
                data = resp.json()
                domains.extend(
                    z["name"] for z in data.get("result", [])
                    if z["name"] not in excluded
                )
                info = data.get("result_info", {})
                if page >= info.get("total_pages", 1):
                    break
                page += 1
            return sorted(domains)
        except Exception:
            return []

    def discover(self, domain: str, config: dict[str, Any]) -> PhaseResult:
        token = get_secret("CLOUDFLARE_API_TOKEN")
        if not token:
            return PhaseResult()

        headers = {"Authorization": f"Bearer {token}"}

        try:
            zone_id = self._find_zone(headers, domain)
            if not zone_id:
                return PhaseResult()
            records = self._list_records(headers, zone_id)
        except Exception:
            return PhaseResult()

        assets: list[DiscoveredAsset] = []
        seen_ips: set[str] = set()

        for record in records:
            rtype: str = record["type"]
            if rtype not in DNS_KEEP_TYPES:
                continue

            fqdn: str = record["name"]
            if is_dns_policy_name(fqdn):
                continue
            content: str = record["content"]
            metadata: dict = {
                "sources": ["cloudflare"],
                "record_type": rtype,
                "content": content,
                "ttl": record.get("ttl"),
                "proxied": record.get("proxied", False),
                "zone_id": zone_id,
            }

            if rtype == "MX" and is_provider_managed_mx(content):
                metadata["provider_mx"] = True

            assets.append(DiscoveredAsset(
                asset_type=AssetType.DNS_RECORD,
                value=fqdn,
                parent_value=domain if fqdn != domain else None,
                asset_metadata=metadata,
            ))

            if rtype in {"A", "AAAA"} and content not in seen_ips:
                seen_ips.add(content)
                assets.append(DiscoveredAsset(
                    asset_type=AssetType.IP_ADDRESS,
                    value=content,
                    parent_value=fqdn,
                    asset_metadata={
                        "sources": ["cloudflare"],
                        "proxied": record.get("proxied", False),
                    },
                ))

        return PhaseResult(assets=assets)

    # ── helpers ───────────────────────────────────────────────────────────────

    def _find_zone(self, headers: dict, domain: str) -> str | None:
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            resp = connector_get(
                f"{_BASE}/zones",
                headers=headers,
                params={"name": candidate, "status": "active"},
                timeout=10,
            )
            zones = resp.json().get("result", [])
            if zones:
                return zones[0]["id"]
        return None

    def _list_records(self, headers: dict, zone_id: str) -> list[dict]:
        records = []
        page = 1
        while True:
            resp = connector_get(
                f"{_BASE}/zones/{zone_id}/dns_records",
                headers=headers,
                params={"per_page": 100, "page": page},
                timeout=15,
            )
            data = resp.json()
            records.extend(data.get("result", []))
            info = data.get("result_info", {})
            if page >= info.get("total_pages", 1):
                break
            page += 1
        return records
