"""
Subdomain brute-force via DNS resolution.

Resolves a wordlist of common subdomain prefixes against the target domain.
Uses concurrent socket lookups — no external tools required.
"""

import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.connectors.base import DiscoveredAsset, PhaseResult
from app.models.asset import AssetType

log = logging.getLogger(__name__)

WORDLISTS: dict[str, list[str]] = {
    "small": [
        "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
        "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal",
        "ns", "host", "support", "dev", "staging", "api", "cdn", "static",
        "media", "img", "images", "app", "apps", "git", "admin", "beta", "demo",
        "docs", "help", "status", "auth", "login", "dashboard", "panel", "web",
        "ssl", "mx", "pop", "pop3", "imap", "autodiscover", "autoconfig",
        "mobile", "cloud", "office", "crm", "jira", "confluence", "jenkins",
        "gitlab", "vpn2", "proxy", "gateway", "fw", "access", "citrix",
    ],
    "medium": [],  # populated below
    "large": [],   # populated below
}

# medium extends small with more common names
WORDLISTS["medium"] = WORDLISTS["small"] + [
    "api2", "api3", "v1", "v2", "internal", "intranet", "extranet", "corp",
    "exchange", "owa", "outlook", "sharepoint", "wiki", "forum", "community",
    "store", "checkout", "payment", "billing", "invoice", "reports", "analytics",
    "monitor", "monitoring", "nagios", "grafana", "kibana", "elastic", "search",
    "db", "database", "mysql", "postgres", "redis", "cache", "queue", "worker",
    "jobs", "scheduler", "cron", "backup", "archive", "old", "new", "legacy",
    "preprod", "uat", "qa", "ci", "cd", "build", "deploy", "release",
    "assets", "files", "upload", "uploads", "download", "downloads", "s3",
    "bucket", "storage", "data", "metrics", "logs", "logging", "trace",
]

WORDLISTS["large"] = WORDLISTS["medium"] + [
    f"api{i}" for i in range(4, 10)
] + [
    f"srv{i:02d}" for i in range(1, 20)
] + [
    f"web{i:02d}" for i in range(1, 20)
] + [
    f"mail{i}" for i in range(3, 10)
] + [
    "alpha", "bravo", "charlie", "delta", "echo", "foxtrot",
    "east", "west", "north", "south", "us", "eu", "ap", "au",
    "us-east", "us-west", "eu-west", "ap-southeast",
    "prod", "production", "sandbox", "playground", "experimental",
    "partner", "partners", "client", "clients", "customer", "customers",
    "api-v1", "api-v2", "api-v3", "graphql", "grpc", "ws", "wss",
    "cdn2", "cdn3", "static2", "assets2", "media2",
    "smtp2", "smtp3", "mx2", "mx3", "mail3",
]


def run(domain: str, wordlist_size: str = "small", max_workers: int = 50) -> PhaseResult:
    words = WORDLISTS.get(wordlist_size, WORDLISTS["small"])
    candidates = [f"{w}.{domain}" for w in words]

    resolved: list[DiscoveredAsset] = []
    seen_ips: set[str] = set()

    def check(fqdn: str) -> list[DiscoveredAsset] | None:
        try:
            results = socket.getaddrinfo(fqdn, None)
            ips = list({r[4][0] for r in results})
            assets = [DiscoveredAsset(
                asset_type=AssetType.DNS_RECORD,
                value=fqdn,
                parent_value=domain,
                asset_metadata={"sources": ["bruteforce"], "resolved_ips": ips},
            )]
            for ip in ips:
                assets.append(DiscoveredAsset(
                    asset_type=AssetType.IP_ADDRESS,
                    value=ip,
                    parent_value=fqdn,
                    asset_metadata={"sources": ["bruteforce"]},
                ))
            return assets
        except (socket.gaierror, socket.herror):
            return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check, c): c for c in candidates}
        for future in as_completed(futures):
            result = future.result()
            if result:
                for asset in result:
                    if asset.asset_type == AssetType.IP_ADDRESS:
                        if asset.value in seen_ips:
                            continue
                        seen_ips.add(asset.value)
                    resolved.append(asset)

    log.info("bruteforce found %d assets for %s (wordlist: %s)", len(resolved), domain, wordlist_size)
    return PhaseResult(assets=resolved)
