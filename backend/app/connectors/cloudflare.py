from typing import Any

from app.connectors.base import (
    DNSDiscoveryConnector,
    DiscoveredAsset,
    PhaseResult,
    TestResult,
)
from app.core.secrets import get_secret
from app.models.asset import AssetType

# Only these record types are meaningful for attack surface mapping
_KEEP_TYPES = {"A", "AAAA", "CNAME", "MX"}

# MX host suffixes that indicate provider-managed mail (not our infrastructure)
_PROVIDER_MX_SUFFIXES = (
    ".google.com",
    "googlemail.com",
    ".outlook.com",
    ".protection.outlook.com",
    ".pphosted.com",        # Proofpoint
    ".mimecast.com",
    ".sendgrid.net",
    ".amazonses.com",
    ".mailgun.org",
    ".messagelabs.com",     # Symantec/Broadcom
    ".barracudanetworks.com",
    ".ppe-hosted.com",      # Proofpoint PE
    ".spamh.com",
    ".mailhostbox.com",
)


def _is_provider_mx(mx_host: str) -> bool:
    host = mx_host.rstrip(".").lower()
    return any(host == s.lstrip(".") or host.endswith(s) for s in _PROVIDER_MX_SUFFIXES)


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

    def list_domains(self, config: dict[str, Any]) -> list[str]:
        token = get_secret("CLOUDFLARE_API_TOKEN")
        if not token:
            return []
        try:
            import httpx
            domains: list[str] = []
            page = 1
            while True:
                resp = httpx.get(
                    "https://api.cloudflare.com/client/v4/zones",
                    headers={"Authorization": f"Bearer {token}"},
                    params={"per_page": 50, "page": page, "status": "active"},
                    timeout=10,
                )
                data = resp.json()
                domains.extend(z["name"] for z in data.get("result", []))
                info = data.get("result_info", {})
                if page >= info.get("total_pages", 1):
                    break
                page += 1
            return sorted(domains)
        except Exception:
            return []

    def discover(self, domain: str, config: dict[str, Any]) -> PhaseResult:
        import httpx

        token = get_secret("CLOUDFLARE_API_TOKEN")
        if not token:
            return PhaseResult()

        headers = {"Authorization": f"Bearer {token}"}
        base = "https://api.cloudflare.com/client/v4"

        try:
            # Find the zone for this domain (exact match first, then suffix match)
            zone_id = self._find_zone(base, headers, domain)
            if not zone_id:
                return PhaseResult()

            # Paginate through all DNS records
            records = self._list_records(base, headers, zone_id)
        except Exception:
            return PhaseResult()

        assets: list[DiscoveredAsset] = []
        seen_ips: set[str] = set()

        for record in records:
            rtype: str = record["type"]
            if rtype not in _KEEP_TYPES:
                continue

            fqdn: str = record["name"]
            content: str = record["content"]
            metadata: dict = {
                "sources": ["cloudflare"],
                "record_type": rtype,
                "content": content,
                "ttl": record.get("ttl"),
                "proxied": record.get("proxied", False),
                "zone_id": zone_id,
            }

            if rtype == "MX" and _is_provider_mx(content):
                metadata["provider_mx"] = True

            assets.append(DiscoveredAsset(
                asset_type=AssetType.DNS_RECORD,
                value=fqdn,
                parent_value=domain if fqdn != domain else None,
                asset_metadata=metadata,
            ))

            # A / AAAA → also emit an ip_address asset
            if rtype in ("A", "AAAA") and content not in seen_ips:
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

    def _find_zone(self, base: str, headers: dict, domain: str) -> str | None:
        import httpx

        # Try exact match first, then strip one label at a time
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            resp = httpx.get(
                f"{base}/zones",
                headers=headers,
                params={"name": candidate, "status": "active"},
                timeout=10,
            )
            zones = resp.json().get("result", [])
            if zones:
                return zones[0]["id"]
        return None

    def _list_records(self, base: str, headers: dict, zone_id: str) -> list[dict]:
        import httpx

        records = []
        page = 1
        while True:
            resp = httpx.get(
                f"{base}/zones/{zone_id}/dns_records",
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
