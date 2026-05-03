from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "Sextant"
    debug: bool = False
    allowed_origins: list[str] = ["http://localhost:3000"]
    database_url: str = "postgresql://sextant:sextant@localhost:5432/sextant"
    secrets_provider: str = "env"
    secret_key: str = "change-me-in-production"

    class Config:
        env_file = ".env"


settings = Settings()
