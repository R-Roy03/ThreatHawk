"""
Configuration management for SentinelEye Agent.

Loads settings from:
1. config/default.yaml (base config)
2. .env file (secrets & overrides)
"""

from pathlib import Path
from typing import Any

import yaml
from pydantic_settings import BaseSettings


# Project root folder path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def load_yaml_config() -> dict[str, Any]:
    """Load the YAML configuration file."""
    config_path = PROJECT_ROOT / "config" / "default.yaml"

    if not config_path.exists():
        return {}

    with open(config_path, "r") as file:
        return yaml.safe_load(file) or {}


class Settings(BaseSettings):
    """Application settings with type validation."""

    # App Settings
    app_name: str = "ThreatHawk"
    app_version: str = "1.0.0"
    debug: bool = True

    # Security
    secret_key: str = "change-this-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 30

    # Database
    database_url: str = f"sqlite+aiosqlite:///{PROJECT_ROOT}/sentineleye.db"

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # Logging
    log_level: str = "INFO"
    log_file: str = str(PROJECT_ROOT / "logs" / "sentineleye.log")

    class Config:
        env_file = ".env"
        extra = "ignore"


# Singleton - ek baar banta hai, phir reuse hota hai
_settings = None


def get_settings() -> Settings:
    """Get application settings."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings