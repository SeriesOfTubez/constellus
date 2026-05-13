# Adding a Connector

Connectors live in `backend/app/connectors/`. Each connector extends a base class that corresponds to its phase.

## Base classes

```python
from app.connectors.base import (
    DNSDiscoveryConnector,   # Phase: discovery
    EnrichmentConnector,     # Phase: enrichment
    ScanningConnector,       # Phase: scanning
    NotificationConnector,   # Phase: notification
)
```

## Minimal example (Discovery)

```python
class MyConnector(DNSDiscoveryConnector):
    name = "My Service"
    description = "Short description shown in the UI"
    env_key_map = {"api_key": "MY_SERVICE_API_KEY"}

    def get_config_schema(self) -> dict:
        return {
            "api_key": {"label": "API Key", "type": "secret"},
        }

    def is_configured(self) -> bool:
        return bool(get_secret("MY_SERVICE_API_KEY"))

    def _test(self, config: dict) -> TestResult:
        # Validate credentials, return TestResult(success=True/False, message="...")
        ...

    def list_domains(self, config: dict) -> list[str]:
        # Return list of apex domains
        ...

    def discover(self, domain: str, config: dict) -> PhaseResult:
        # Return PhaseResult(assets=[...]) for this domain
        ...
```

## Registering the connector

Add it to the `REGISTRY` in `backend/app/api/connectors.py`:

```python
REGISTRY: dict = {
    ...
    "myservice": MyServiceConnector(),
}
```

## Config schema field types

| Type | UI element |
|---|---|
| `string` | Text input |
| `secret` | Password input — masked, stored encrypted |
| `select` | Dropdown — provide `options: [...]` |
| `multiselect` | Multi-select — provide `options: [...]` |
