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
    # Enrichment data that connectors can populate directly (e.g. Nuclei classification block)
    cve_id: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    cwe: str | None = None


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


class DNSDiscoveryConnector(BaseConnector, ABC):
    """
    Connector that enumerates DNS records for a given apex domain.
    Implement one subclass per DNS provider (Cloudflare, Route53, Azure DNS, etc.).
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
