import os
from typing import Optional

# Imported for its side effect: populates os.environ from the repo-root
# `.env`. `secrets` is importable without `config`, so this module has to
# load it too rather than relying on config having been imported first
# (planning#157).
from app.core import env as _env  # noqa: F401


def get_secret(key: str) -> Optional[str]:
    """Retrieve a deployment secret from the environment.

    Environment only. Connector credentials do NOT come through here: each
    connector reads them from the config of the connector instance it is
    called for (planning#284); the environment is consulted for those only
    by the one-time seeding in `app.services.connector_instances`. What is
    left for `get_secret` is keys that are not connectors, e.g. PDCP_API_KEY.
    """
    provider = os.getenv("SECRETS_PROVIDER", "env").lower()
    if provider == "env":
        return os.getenv(key)

    raise ValueError(f"Unknown secrets provider: {provider}")
