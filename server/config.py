"""Application configuration loaded from the environment."""

import secrets
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="CS_", extra="ignore")

    app_name: str = "Code-Shield"
    environment: str = "development"
    debug: bool = False

    secret_key: str = ""
    access_token_minutes: int = Field(default=45, ge=5, le=720)
    refresh_token_days: int = Field(default=7, ge=1, le=30)
    cookie_secure: bool = False
    cookie_domain: str | None = None

    database_url: str = "sqlite:///./data/codeshield.db"
    allowed_origins: str = "http://127.0.0.1:8000,http://localhost:8000,http://127.0.0.1:12000"

    max_code_bytes: int = Field(default=200_000, ge=1_000, le=2_000_000)
    scan_timeout_seconds: int = Field(default=15, ge=2, le=60)

    rate_limit_per_minute: int = Field(default=240, ge=10)
    auth_rate_limit_per_minute: int = Field(default=12, ge=3)
    login_max_failures: int = Field(default=5, ge=3)
    login_lockout_minutes: int = Field(default=15, ge=1)

    model_dir: str = "data/models"
    admin_email: str = ""
    admin_password: str = ""

    @property
    def origins(self) -> list[str]:
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod"}


@lru_cache
def get_settings() -> Settings:
    return Settings()


def resolve_secret_key(settings: Settings) -> str:
    """Return the signing key, failing closed in production when it is unset."""
    if settings.secret_key:
        if len(settings.secret_key) < 32:
            raise RuntimeError("CS_SECRET_KEY must be at least 32 characters long")
        return settings.secret_key

    if settings.is_production:
        raise RuntimeError("CS_SECRET_KEY is required when CS_ENVIRONMENT=production")

    key_file = Path(settings.model_dir).parent / ".secret_key"
    key_file.parent.mkdir(parents=True, exist_ok=True)
    if key_file.exists():
        return key_file.read_text().strip()

    generated = secrets.token_urlsafe(48)
    key_file.write_text(generated)
    key_file.chmod(0o600)
    return generated
