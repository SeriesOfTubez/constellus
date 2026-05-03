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
    name: str
    description: str
    version: str = "0.1.0"
    env_key_map: dict[str, str] = {}

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
