from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration loaded from environment variables / .env."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = "postgresql+asyncpg://flareguard:flareguard@localhost:5432/flareguard"

    # Google Web Risk Lookup API. Left unset the provider reports "not_configured"
    # and the rest of the pipeline still runs.
    google_web_risk_api_key: str | None = None
    web_risk_enabled: bool = True

    # External request / caching tuning.
    provider_timeout_seconds: float = 5.0
    rdap_timeout_seconds: float = 4.0
    rdap_cache_ttl_seconds: int = 86_400
    assessment_cache_ttl_seconds: int = 1_800

    # Input limits.
    max_url_length: int = 2_048

    @property
    def web_risk_configured(self) -> bool:
        return bool(self.google_web_risk_api_key)


@lru_cache
def get_settings() -> Settings:
    return Settings()
