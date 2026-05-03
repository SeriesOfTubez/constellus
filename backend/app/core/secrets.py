import os
from typing import Optional


def get_secret(key: str) -> Optional[str]:
    """
    Retrieve a secret by name from the configured secrets provider.
    Falls back to environment variables for local dev and simple deployments.
    Future: route through Azure KeyVault, AWS Secrets Manager, HashiCorp Vault, etc.
    based on SECRETS_PROVIDER setting.
    """
    provider = os.getenv("SECRETS_PROVIDER", "env").lower()

    if provider == "env":
        return _from_env(key)

    # Additional providers wired in here as implemented
    raise ValueError(f"Unknown secrets provider: {provider}")


def _from_env(key: str) -> Optional[str]:
    return os.getenv(key)
