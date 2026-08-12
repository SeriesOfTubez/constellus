"""Nuclei tag-union filter — Session D / issue #12.

Maps detected services (zgrab2/banner_grab `service` field) and web
technologies (httpx/Wappalyzer `tech_stack[]`) to nuclei template tags, so
a scan only loads nuclei templates relevant to what's actually running
plus a fixed set of tech-agnostic baseline categories.

Designed to be extended — add new entries to _SERVICE_TAG_MAP /
_TECH_STACK_TAG_MAP as new zgrab2 modules / Wappalyzer techs become
relevant. Every value emitted by compute_tag_union() MUST also appear in
scanner-worker's `_INCLUDE_TAG_LOOKUP` allow-list (scanner-worker/main.py)
or it will be rejected with a 422 — the two lists are kept in sync
manually.
"""

from app.connectors.base import DiscoveredAsset

# Tech-agnostic categories that always run, regardless of detected tech.
# Deliberately excludes generic "cve"/"vuln" — including those would
# re-include every product's CVE templates via nuclei's OR tag-matching
# and defeat the filter. Product-specific CVE templates (tagged e.g.
# "cve,cve2023,wordpress,wp,...") are included only via their product tag,
# below.
BASELINE_TAGS: frozenset[str] = frozenset({
    "panel", "exposure", "misconfig", "default-login", "takeover",
    "unauth", "config", "network", "ssl", "tech",
})

# zgrab2/banner_grab `service` -> nuclei tag. Keys are lowercase; the union
# computation lowercases incoming values before lookup.
_SERVICE_TAG_MAP: dict[str, str] = {
    "ssh": "ssh",
    "ftp": "ftp",
    "smtp": "smtp",
    "pop3": "pop3",
    "imap": "imap",
    "mysql": "mysql",
    "redis": "redis",
    # zgrab2 service="postgres" -> nuclei tag "postgresql" (42 templates),
    # NOT "postgres" (only 5 templates).
    "postgres": "postgresql",
    "postgresql": "postgresql",
    "mssql": "mssql",
    "modbus": "modbus",
    "mongodb": "mongodb",
    "smb": "smb",
    "rdp": "rdp",
    "memcached": "memcached",
    "vnc": "vnc",
    "http": "http",
    "https": "http",
}

# httpx/Wappalyzer tech_stack[] name -> nuclei tag. Keys are lowercase;
# includes Wappalyzer's actual multi-word names alongside bare names.
_TECH_STACK_TAG_MAP: dict[str, str] = {
    "wordpress": "wordpress",
    "joomla": "joomla",
    "drupal": "drupal",
    "jenkins": "jenkins",
    "apache": "apache",
    "apache http server": "apache",
    "nginx": "nginx",
    "iis": "iis",
    "microsoft iis": "iis",
    "tomcat": "tomcat",
    "apache tomcat": "tomcat",
    "grafana": "grafana",
    "gitlab": "gitlab",
    "confluence": "confluence",
    "atlassian confluence": "confluence",
    "jira": "jira",
    "atlassian jira": "jira",
    "magento": "magento",
    "php": "php",
    "node.js": "nodejs",
    "nodejs": "nodejs",
    "express": "nodejs",
    "mysql": "mysql",
    "redis": "redis",
    "mongodb": "mongodb",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "microsoft sql server": "mssql",
    "mssql": "mssql",
}


def _normalize(value: str) -> str:
    return value.strip().lower()


def compute_tag_union(all_assets: list[DiscoveredAsset]) -> set[str]:
    """Scan-wide union of detected-tech nuclei tags, plus BASELINE_TAGS.

    Walks every IP_ADDRESS asset's `asset_metadata["open_ports"]`, mapping
    each entry's `service` (via _SERVICE_TAG_MAP) and each `tech_stack[]`
    entry (via _TECH_STACK_TAG_MAP) to a nuclei tag. Unknown/unmapped
    values are silently ignored. Always non-empty (BASELINE_TAGS).
    """
    from app.models.asset import AssetType

    tags: set[str] = set(BASELINE_TAGS)

    for asset in all_assets:
        if asset.asset_type != AssetType.IP_ADDRESS:
            continue
        open_ports = (asset.asset_metadata or {}).get("open_ports") or []
        if not isinstance(open_ports, list):
            continue
        for entry in open_ports:
            if not isinstance(entry, dict):
                continue

            service = entry.get("service")
            if isinstance(service, str) and service:
                mapped = _SERVICE_TAG_MAP.get(_normalize(service))
                if mapped:
                    tags.add(mapped)

            tech_stack = entry.get("tech_stack")
            if isinstance(tech_stack, list):
                for tech in tech_stack:
                    if not isinstance(tech, str) or not tech:
                        continue
                    mapped = _TECH_STACK_TAG_MAP.get(_normalize(tech))
                    if mapped:
                        tags.add(mapped)

    return tags
