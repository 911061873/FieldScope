from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables (FIELDSCOPE_*)."""

    model_config = SettingsConfigDict(
        env_prefix="FIELDSCOPE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "FieldScope"
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8000

    # Database: SQLite by default for zero-config local dev; compatible with PostgreSQL asyncpg.
    database_url: str = "sqlite+aiosqlite:///./fieldscope.db"

    # Security keys (MUST be overridden via env vars in production)
    secret_key: str = "dev-insecure-jwt-secret-change-me-in-production-32bytes"
    encryption_key: str = "dev-insecure-encryption-key-change-me-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60 * 12

    # Bootstrap initial admin account (created only when users table is empty)
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = "admin123456"
    bootstrap_admin_display_name: str = "System Administrator"

    # CORS & optional built Vue 3 SPA static assets directory
    cors_origins: list[str] = Field(default_factory=lambda: ["*"])
    static_dir: str = "web/dist"

    @property
    def resolved_static_dir(self) -> Path:
        return Path(self.static_dir).resolve()


def get_settings() -> Settings:
    return Settings()
