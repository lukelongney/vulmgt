# tests/test_jira_client.py
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime
from app.services.jira_client import create_vulnerability_ticket, format_ticket_description
from app.models import Severity, Scanner


def test_format_ticket_description():
    desc = format_ticket_description(
        cve="CVE-2024-1234",
        scanner=Scanner.QUALYS,
        scanner_id="12345",
        severity_score=9.8,
        host="webserver01",
        first_seen=datetime(2026, 1, 10),
        sla_deadline=datetime(2026, 1, 24),
        description="Remote code execution vulnerability",
        solution="Update to latest version",
        remediation_guidance="1. Run apt update\n2. Restart service"
    )

    assert "CVE-2024-1234" in desc
    assert "webserver01" in desc
    assert "9.8" in desc
    assert "apt update" in desc


@patch("app.services.jira_client.settings")
@patch("app.services.jira_client.JIRA")
def test_create_vulnerability_ticket(mock_jira_class, mock_settings):
    # Setup settings mock
    mock_settings.jira_url = "https://test.atlassian.net"
    mock_settings.jira_email = "test@test.com"
    mock_settings.jira_api_token = "test-token"
    mock_settings.jira_project_key = "VULN"

    # Setup Jira mock
    mock_jira = MagicMock()
    mock_jira_class.return_value = mock_jira
    mock_jira.create_issue.return_value = MagicMock(
        key="VULN-123",
        permalink=lambda: "https://test.atlassian.net/browse/VULN-123"
    )

    ticket_id, ticket_url = create_vulnerability_ticket(
        cve="CVE-2024-1234",
        title="Apache RCE",
        severity=Severity.CRITICAL,
        host="webserver01",
        scanner=Scanner.QUALYS,
        scanner_id="12345",
        severity_score=9.8,
        first_seen=datetime(2026, 1, 10),
        sla_deadline=datetime(2026, 1, 24),
        description="RCE vulnerability",
        solution="Update Apache",
        remediation_guidance="1. Update\n2. Restart"
    )

    assert ticket_id == "VULN-123"
    assert "VULN-123" in ticket_url
