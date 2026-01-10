# tests/test_parser.py
import pytest
from pathlib import Path
from app.services.parser import parse_qualys_report, parse_tenable_report, normalize_severity
from app.models import Severity


def test_normalize_severity_qualys():
    assert normalize_severity("5", "qualys") == Severity.CRITICAL
    assert normalize_severity("4", "qualys") == Severity.HIGH
    assert normalize_severity("3", "qualys") == Severity.MEDIUM
    assert normalize_severity("2", "qualys") == Severity.LOW
    assert normalize_severity("1", "qualys") == Severity.INFO


def test_normalize_severity_tenable():
    assert normalize_severity("Critical", "tenable") == Severity.CRITICAL
    assert normalize_severity("High", "tenable") == Severity.HIGH
    assert normalize_severity("Medium", "tenable") == Severity.MEDIUM
    assert normalize_severity("Low", "tenable") == Severity.LOW
    assert normalize_severity("Info", "tenable") == Severity.INFO
