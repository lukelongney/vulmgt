# app/config.py
from pydantic_settings import BaseSettings
from functools import lru_cache
from datetime import datetime
from typing import Optional


class Settings(BaseSettings):
    # Database
    database_url: str = "sqlite:///./data/vulmgt.db"

    # Jira
    jira_url: str = ""
    jira_email: str = ""
    jira_api_token: str = ""
    jira_project_key: str = ""

    # Claude
    anthropic_api_key: str = ""

    # SLA defaults (days)
    sla_critical: int = 14
    sla_high: int = 14
    sla_medium: int = 90
    sla_low: int = 180

    # Escalation
    escalation_threshold_percent: int = 75

    class Config:
        env_file = ".env"


@lru_cache
def get_settings() -> Settings:
    return Settings()


# Global simulated date (None = use real time)
_simulated_date: Optional[datetime] = None


def get_effective_date() -> datetime:
    """Get the effective current date (simulated or real)."""
    if _simulated_date is not None:
        return _simulated_date
    return datetime.now()


def set_simulated_date(date: Optional[datetime]) -> None:
    """Set or clear the simulated date."""
    global _simulated_date
    _simulated_date = date


def get_simulated_date() -> Optional[datetime]:
    """Get the current simulated date (None if using real time)."""
    return _simulated_date
