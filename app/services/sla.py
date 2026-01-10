# app/services/sla.py
from datetime import datetime, timedelta
from app.models import Severity
from app.config import get_settings, get_effective_date


def get_sla_days(severity: Severity) -> int:
    """Get SLA days for a given severity level."""
    settings = get_settings()
    sla_map = {
        Severity.CRITICAL: settings.sla_critical,
        Severity.HIGH: settings.sla_high,
        Severity.MEDIUM: settings.sla_medium,
        Severity.LOW: settings.sla_low,
        Severity.INFO: 365,  # Info level gets 1 year
    }
    return sla_map.get(severity, 90)


def calculate_sla_deadline(severity: Severity, first_seen: datetime) -> datetime:
    """Calculate SLA deadline based on severity and first seen date."""
    days = get_sla_days(severity)
    return first_seen + timedelta(days=days)


def calculate_sla_status(first_seen: datetime, deadline: datetime) -> tuple[int, float]:
    """
    Calculate SLA status using effective date (supports time simulation).
    Returns: (days_remaining, percent_elapsed)
    """
    now = get_effective_date()
    total_days = (deadline - first_seen).days
    elapsed_days = (now - first_seen).days
    days_remaining = (deadline - now).days

    if total_days > 0:
        percent_elapsed = (elapsed_days / total_days) * 100
    else:
        percent_elapsed = 100.0

    return days_remaining, percent_elapsed


def is_approaching_sla(first_seen: datetime, deadline: datetime, threshold_percent: int = 75) -> bool:
    """Check if vulnerability is approaching SLA threshold."""
    _, percent_elapsed = calculate_sla_status(first_seen, deadline)
    return percent_elapsed >= threshold_percent
