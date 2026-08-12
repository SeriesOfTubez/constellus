from pydantic_settings import BaseSettings

DEFAULT_SECRET_KEY = "change-me-in-production"


class Settings(BaseSettings):
    app_name: str = "Constellus"
    debug: bool = False
    allowed_origins: list[str] = ["http://localhost:3000"]
    database_url: str = "postgresql://constellus:constellus@localhost:5432/constellus"
    secrets_provider: str = "env"
    secret_key: str = DEFAULT_SECRET_KEY

    class Config:
        env_file = ".env"


settings = Settings()


def require_configured_secret_key() -> None:
    """Refuse to start on the well-known placeholder secret_key outside debug
    mode. secret_key signs every JWT and (see connector_config.py) is the
    root of the key material that encrypts every stored connector
    credential — shipping the placeholder in a reachable deployment lets
    anyone forge an admin session and decrypt stored API keys."""
    if settings.debug:
        return
    if settings.secret_key == DEFAULT_SECRET_KEY:
        raise RuntimeError(
            "secret_key is still the default placeholder "
            f"({DEFAULT_SECRET_KEY!r}). Set a unique secret_key "
            "(env var SECRET_KEY) before starting outside debug mode — it "
            "signs JWTs and encrypts stored connector credentials."
        )
