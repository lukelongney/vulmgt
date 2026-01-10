# tests/test_sla.py
from datetime import datetime, timedelta
from app.services.sla import calculate_sla_deadline, calculate_sla_status
from app.models import Severity


def test_calculate_sla_deadline_critical():
    first_seen = datetime(2026, 1, 10, 12, 0, 0)
    deadline = calculate_sla_deadline(Severity.CRITICAL, first_seen)
    expected = datetime(2026, 1, 24, 12, 0, 0)  # 14 days
    assert deadline == expected


def test_calculate_sla_deadline_medium():
    first_seen = datetime(2026, 1, 10, 12, 0, 0)
    deadline = calculate_sla_deadline(Severity.MEDIUM, first_seen)
    expected = datetime(2026, 4, 10, 12, 0, 0)  # 90 days
    assert deadline == expected


def test_calculate_sla_status_approaching():
    first_seen = datetime.now() - timedelta(days=12)
    deadline = first_seen + timedelta(days=14)
    days_remaining, percent_elapsed = calculate_sla_status(first_seen, deadline)
    # Allow for timing variance (1-2 days remaining)
    assert 1 <= days_remaining <= 2
    assert percent_elapsed > 75  # Should trigger escalation


def test_calculate_sla_status_overdue():
    first_seen = datetime.now() - timedelta(days=20)
    deadline = first_seen + timedelta(days=14)
    days_remaining, percent_elapsed = calculate_sla_status(first_seen, deadline)
    assert days_remaining < 0
    assert percent_elapsed > 100
