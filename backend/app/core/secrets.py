import os
from typing import Optional

# Imported for its side effect: populates os.environ from the repo-root
# `.env`, which is where connector credentials live. `secrets` is
# importable without `config`, so this module has to load it too rather
# than relying on config having been imported first (planning#157).
from app.core import env as _env  # noqa: F401

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
