# app/config.py
from pydantic_settings import BaseSettings
from functools import lru_cache


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
