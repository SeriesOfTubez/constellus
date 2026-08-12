import os
from typing import Optional

_db_overrides: dict[str, str] = {}


def set_db_override(key: str, value: Optional[str]) -> None:
    if value is None:
        _db_overrides.pop(key, None)
    else:
        _db_overrides[key] = value


def get_secret(key: str) -> Optional[str]:
    """
    Retrieve a secret. DB-stored connector config takes precedence over env vars,
    allowing UI-configured credentials to override environment defaults.
    """
    if key in _db_overrides:
        return _db_overrides[key]

    provider = os.getenv("SECRETS_PROVIDER", "env").lower()
    if provider == "env":
        return os.getenv(key)

    raise ValueError(f"Unknown secrets provider: {provider}")
