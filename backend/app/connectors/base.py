import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ConnectorPhase(str, Enum):
    DISCOVERY = "discovery"
    ENRICHMENT = "enrichment"
    SCANNING = "scanning"
    NOTIFICATION = "notification"


class ConnectorStatus(str, Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    ERROR = "error"
    UNCONFIGURED = "unconfigured"


@dataclass
class TestResult:
    success: bool
    message: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class DiscoveredAsset:
    asset_type: str  # AssetType enum value
    value: str
    parent_value: str | None = None
    asset_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DiscoveredFinding:
    asset_value: str
    finding_type: str
    source: str
    severity: str
    title: str
    description: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    # Explicit finding category. When None, finding_writer derives it from
    # cve_id / Nuclei tags. Set it directly for analyzers with no tags to
    # categorize from (e.g. exposure analyzer → "exposure").
    category: str | None = None
    # Enrichment data that connectors can populate directly (e.g. Nuclei classification block)
    cve_id: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    cwe: str | None = None
    # Explicit asset override. Set this when the producer already holds the
    # specific AssetCanonical row (e.g. an analyzer iterating dns_record rows
    # it queried itself) — it bypasses finding_writer's (asset_type, value)
    # lookup entirely, which cannot distinguish multiple dns_record rows that
    # share the same hostname (A vs AAAA vs MX vs CNAME, etc.) and would
    # otherwise resolve to an arbitrary one of them.
    asset_id: uuid.UUID | None = None


@dataclass
class PhaseResult:
    """Unified result type returned by every connector phase."""
    assets: list[DiscoveredAsset] = field(default_factory=list)
    findings: list[DiscoveredFinding] = field(default_factory=list)


class BaseConnector(ABC):
    name: str
    description: str
    version: str = "0.1.0"
    env_key_map: dict[str, str] = {}
    # Connectors whose absence visibly degrades core product value (active
    # scanning, service ID, vuln intelligence) — surfaced as a "Core
    # capability" badge in Admin → Connectors and grouped first in the setup
    # wizard. Not a hard gate: nothing blocks on this, it's about setting
    # expectations for result quality.
    core: bool = False

    def test(self, config: dict[str, Any] | None = None) -> TestResult:
        """Validate credentials and connectivity. Called by the UI Test button.
        Config is passed for connectors that don't use the env-var override layer."""
        return self._test(config or {})

    def _test(self, config: dict[str, Any]) -> TestResult:
        raise NotImplementedError

    @abstractmethod
    def get_config_schema(self) -> dict[str, Any]:
        """Return the configuration fields required for this connector."""
        ...

    @abstractmethod
    def is_configured(self) -> bool:
        """Return True if all required credentials are present."""
        ...


# ── DNS filtering constants (shared across all DNS connectors) ─────────────────
#
# Only these record types map to scannable infrastructure. TXT, DKIM, DMARC,
# NS, SOA are policy/metadata records with no hosts to scan.
DNS_KEEP_TYPES: frozenset[str] = frozenset({"A", "AAAA", "CNAME", "MX"})

# DKIM and DMARC are technically CNAMEs/TXT records and slip past the
# DNS_KEEP_TYPES filter because they happen to use the CNAME type when
# delegated (Google Workspace etc.). Skip names with these prefixes —
# they're policy records with no scannable host.
DNS_SKIP_PREFIXES: tuple[str, ...] = (
    "_domainkey.",
    "_dmarc.",
)


def is_dns_policy_name(name: str) -> bool:
    """Return True for hostnames that are pure DNS policy records (DKIM /
    DMARC delegations). Apply *after* the DNS_KEEP_TYPES filter, since
    these records often carry CNAME types and would otherwise sneak
    through as fake subdomains."""
    n = (name or "").lstrip(".").lower()
    if not n:
        return False
    if any(prefix in n for prefix in DNS_SKIP_PREFIXES):
        return True
    return False

# MX host suffixes that indicate provider-managed mail. These are not customer
# infrastructure — tag them provider_mx and skip active scanning.
DNS_PROVIDER_MX_SUFFIXES: tuple[str, ...] = (
    ".google.com",
    "googlemail.com",
    ".outlook.com",
    ".protection.outlook.com",
    ".pphosted.com",         # Proofpoint
    ".mimecast.com",
    ".sendgrid.net",
    ".amazonses.com",
    ".mailgun.org",
    ".messagelabs.com",      # Symantec/Broadcom
    ".barracudanetworks.com",
    ".ppe-hosted.com",       # Proofpoint PE
    ".spamh.com",
    ".mailhostbox.com",
)


def is_provider_managed_mx(mx_host: str) -> bool:
    """Return True if the MX hostname belongs to a known managed mail provider."""
    host = mx_host.rstrip(".").lower()
    return any(host == s.lstrip(".") or host.endswith(s) for s in DNS_PROVIDER_MX_SUFFIXES)


def cdn_scan_targets(assets: list["DiscoveredAsset"]) -> dict[str, dict]:
    """Map customer hostname -> its dns_record identity fields
    ({"record_type", "content"}) for records annotated as CDN-fronted
    (metadata 'cdn').

    The terminal CDN IP is suppressed, so there's no ip_address asset to read
    ports from — the web enrichers (tlsx, httpx) probe these hostnames directly,
    with correct SNI, on the standard web ports and write the observed results
    back to the dns_record.

    The identity fields matter: the dns_record canonical key is
    (value, record_type, content), so a result patch MUST echo them or the
    writer treats it as a new record and creates a duplicate bare row instead
    of merging into the existing CNAME."""
    out: dict[str, dict] = {}
    for a in assets:
        if a.asset_type == "dns_record" and (a.asset_metadata or {}).get("cdn"):
            md = a.asset_metadata or {}
            # First annotated record per hostname wins; a hostname has one CNAME.
            out.setdefault(a.value, {
                "record_type": md.get("record_type"),
                "content": md.get("content"),
            })
    return out


class DNSDiscoveryConnector(BaseConnector, ABC):
    """
    Connector that enumerates DNS records for a given apex domain.
    Implement one subclass per DNS provider (Cloudflare, Route53, Azure DNS, etc.).

    All implementations MUST apply DNS_KEEP_TYPES filtering and use
    is_provider_managed_mx() to tag provider-managed MX records. This ensures
    consistent asset ingestion behaviour across all DNS sources, including any
    future manual zone upload option.
    """
    phase = ConnectorPhase.DISCOVERY

    @abstractmethod
    def discover(self, domain: str, config: dict[str, Any]) -> PhaseResult:
        """
        Given an apex domain, return all discovered DNS records and any
        IP addresses derived from them.
        """
        ...

    @abstractmethod
    def list_domains(self, config: dict[str, Any]) -> list[str]:
        """
        Return all apex domains/zones this connector has access to.
        Used to auto-populate the scan scope on first configure and
        to show available domains in the new scan dialog.
        """
        ...


class EnrichmentConnector(BaseConnector, ABC):
    """
    Connector that enriches a list of discovered assets with additional context
    (cloud metadata, firewall rules, vulnerability findings, etc.).
    Implement one subclass per enrichment source (Tenable, Wiz, FortiManager, etc.).
    """
    phase = ConnectorPhase.ENRICHMENT

    @abstractmethod
    def enrich(self, assets: list[DiscoveredAsset], config: dict[str, Any]) -> PhaseResult:
        """
        Given a list of already-discovered assets, return enrichment context
        (additional assets and/or findings from this source).
        """
        ...


class ScanningConnector(BaseConnector, ABC):
    """
    Connector that actively probes targets and returns security findings.
    Implement one subclass per scanner (Nuclei, etc.).
    """
    phase = ConnectorPhase.SCANNING

    @abstractmethod
    def scan(self, targets: list[str], config: dict[str, Any]) -> PhaseResult:
        """
        Given a list of targets (hostnames / IPs), run security checks
        and return findings.
        """
        ...


class NotificationConnector(BaseConnector, ABC):
    """
    Connector that sends outbound notifications (email, chat, webhooks).
    Implement one subclass per channel (Mailtrap, SendGrid, Slack, etc.).
    """
    phase = ConnectorPhase.NOTIFICATION

    @abstractmethod
    def send(
        self,
        subject: str,
        body_text: str,
        recipients: list[str],
        config: dict[str, Any],
        body_html: str | None = None,
    ) -> bool:
        """Send a notification. Returns True on success."""
        ...
