from __future__ import annotations

import logging
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("fieldscope.security")

DEFAULT_SECRET_KEY = "dev-insecure-jwt-secret-change-me-in-production-32bytes"
DEFAULT_ENCRYPTION_KEY = "dev-insecure-encryption-key-change-me-in-production"
DEFAULT_BOOTSTRAP_ADMIN_PASSWORD = "admin123456"


class Settings(BaseSettings):
    """Application settings loaded from environment variables (FIELDSCOPE_*)."""

    model_config = SettingsConfigDict(
        env_prefix="FIELDSCOPE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "FieldScope"
    environment: str = "dev"  # "dev" | "test" | "staging" | "prod"
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8000

    # Database: SQLite by default for zero-config local dev; compatible with PostgreSQL asyncpg.
    database_url: str = "sqlite+aiosqlite:///./fieldscope.db"

    # Security keys (MUST be overridden via env vars in production)
    secret_key: str = DEFAULT_SECRET_KEY
    encryption_key: str = DEFAULT_ENCRYPTION_KEY
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60 * 12

    # Bootstrap initial admin account (created only when users table is empty)
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = DEFAULT_BOOTSTRAP_ADMIN_PASSWORD
    bootstrap_admin_display_name: str = "System Administrator"

    # Runtime security & performance controls
    login_rate_limit_max_attempts: int = 10
    login_rate_limit_window_seconds: int = 60
    last_used_debounce_seconds: int = 60

    # CORS & optional built Vue 3 SPA static assets directory
    cors_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:5173", "http://127.0.0.1:5173"]
    )
    static_dir: str = "web/dist"

    @property
    def is_dev_or_test(self) -> bool:
        return self.environment.strip().lower() in ("dev", "development", "test")

    def validate_runtime_security(self) -> list[str]:
        """Validate secret/credential settings; refuse startup in non-dev if defaults remain."""
        issues: list[str] = []
        if self.secret_key == DEFAULT_SECRET_KEY or len(self.secret_key) < 32:
            issues.append(
                "FIELDSCOPE_SECRET_KEY uses insecure default or is shorter than 32 characters"
            )
        if self.encryption_key == DEFAULT_ENCRYPTION_KEY or len(self.encryption_key) < 16:
            issues.append(
                "FIELDSCOPE_ENCRYPTION_KEY uses insecure default or is shorter than 16 characters"
            )
        if self.bootstrap_admin_password == DEFAULT_BOOTSTRAP_ADMIN_PASSWORD:
            issues.append("FIELDSCOPE_BOOTSTRAP_ADMIN_PASSWORD uses insecure default password")

        if issues:
            if not self.is_dev_or_test:
                raise RuntimeError(
                    "Refusing to start FieldScope in non-dev environment with insecure defaults: "
                    + "; ".join(issues)
                )
            for issue in issues:
                logger.warning("SECURITY WARNING (%s): %s", self.environment, issue)
        return issues

    @property
    def resolved_static_dir(self) -> Path:
        raw = Path(self.static_dir)
        if raw.is_absolute():
            return raw.resolve()
        cwd_candidate = raw.resolve()
        if cwd_candidate.exists():
            return cwd_candidate
        # Fallback relative to repository root (src/fieldscope/core/config.py -> repo root)
        repo_candidate = (Path(__file__).resolve().parents[3] / raw).resolve()
        return repo_candidate if repo_candidate.exists() else cwd_candidate


def get_settings() -> Settings:
    return Settings()
