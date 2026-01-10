# tests/test_claude_client.py
import pytest
from unittest.mock import patch, MagicMock
from app.models import Severity


@patch("app.services.claude_client.settings")
@patch("app.services.claude_client.anthropic.Anthropic")
def test_generate_remediation_guidance(mock_anthropic, mock_settings):
    # Setup settings mock
    mock_settings.anthropic_api_key = "test-api-key"

    # Setup Anthropic client mock
    mock_client = MagicMock()
    mock_anthropic.return_value = mock_client
    mock_client.messages.create.return_value = MagicMock(
        content=[MagicMock(text="1. Update Apache\n2. Restart service")]
    )

    # Import after patching
    from app.services.claude_client import generate_remediation_guidance

    result = generate_remediation_guidance(
        cve="CVE-2024-1234",
        title="Apache HTTP Server RCE",
        description="Remote code execution vulnerability",
        solution="Update to version 2.4.52",
        severity=Severity.CRITICAL,
        host="webserver01",
        os="CentOS 7"
    )

    assert "Update Apache" in result or "Apache" in result
    mock_client.messages.create.assert_called_once()
