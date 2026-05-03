from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


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


class BaseConnector(ABC):
    """
    All connectors implement this interface.
    Credentials are never stored here — they are fetched from the
    configured secrets provider at runtime via get_secret().
    """

    name: str
    description: str
    version: str = "0.1.0"

    @abstractmethod
    def test(self) -> TestResult:
        """Validate credentials and connectivity. Called by the UI Test button."""
        ...

    @abstractmethod
    def get_config_schema(self) -> dict[str, Any]:
        """
        Return the configuration fields required for this connector.
        Used to render the configuration form in the UI.
        """
        ...

    @abstractmethod
    def is_configured(self) -> bool:
        """Return True if all required credentials are present."""
        ...
