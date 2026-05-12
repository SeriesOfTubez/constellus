from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "Constellus"
    debug: bool = False
    allowed_origins: list[str] = ["http://localhost:3000"]
    database_url: str = "postgresql://constellus:constellus@localhost:5432/constellus"
    secrets_provider: str = "env"
    secret_key: str = "change-me-in-production"

    class Config:
        env_file = ".env"


settings = Settings()
