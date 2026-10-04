from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings, read from environment variables (and `.env`)."""

    model_config = SettingsConfigDict(env_file=".env", env_prefix="THREATLENS_", extra="ignore")

    app_name: str = "ThreatLens"
    environment: str = "development"
    database_url: str = "postgresql+psycopg://threatlens:threatlens@localhost:55432/threatlens"
    database_echo: bool = False
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Optional LLM provider for the investigation assistant (Phase 11).
    # The deterministic fallback is used whenever no key is configured.
    llm_api_key: str | None = None
    llm_model: str = "claude-sonnet-5-5"


@lru_cache
def get_settings() -> Settings:
    return Settings()
