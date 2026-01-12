# app/services/jira_client.py
import logging
from jira import JIRA
from datetime import datetime
from app.config import get_settings
from app.models import Severity, Scanner

settings = get_settings()
logger = logging.getLogger(__name__)


def get_jira_client() -> JIRA | None:
    """Get authenticated Jira client."""
    if not all([settings.jira_url, settings.jira_email, settings.jira_api_token]):
        return None

    return JIRA(
        server=settings.jira_url,
        basic_auth=(settings.jira_email, settings.jira_api_token)
    )


def format_ticket_description(
    cve: str | None,
    scanner: Scanner,
    scanner_id: str | None,
    severity_score: float | None,
    host: str,
    first_seen: datetime,
    sla_deadline: datetime,
    description: str | None,
    solution: str | None,
    remediation_guidance: str | None
) -> str:
    """Format the Jira ticket description."""

    return f"""h3. Vulnerability Details

||Field||Value||
|CVE|{cve or 'N/A'}|
|Scanner|{scanner.value.title()}|
|Scanner ID|{scanner_id or 'N/A'}|
|CVSS Score|{severity_score or 'N/A'}|
|Host|{host}|
|First Detected|{first_seen.strftime('%Y-%m-%d')}|
|SLA Deadline|{sla_deadline.strftime('%Y-%m-%d')}|

h3. Scanner Description

{description or 'Not provided'}

h3. Scanner Solution

{solution or 'Not provided'}

h3. AI Remediation Guidance

{remediation_guidance or 'Not available'}
"""


def create_vulnerability_ticket(
    cve: str | None,
    title: str,
    severity: Severity,
    host: str,
    scanner: Scanner,
    scanner_id: str | None,
    severity_score: float | None,
    first_seen: datetime,
    sla_deadline: datetime,
    description: str | None,
    solution: str | None,
    remediation_guidance: str | None
) -> tuple[str, str]:
    """Create a Jira ticket for a vulnerability."""

    jira = get_jira_client()
    if not jira:
        raise ValueError("Jira not configured")

    summary = f"[{severity.value.upper()}] {cve or 'No CVE'} on {host}"
    if len(summary) > 255:
        summary = summary[:252] + "..."

    ticket_description = format_ticket_description(
        cve=cve,
        scanner=scanner,
        scanner_id=scanner_id,
        severity_score=severity_score,
        host=host,
        first_seen=first_seen,
        sla_deadline=sla_deadline,
        description=description,
        solution=solution,
        remediation_guidance=remediation_guidance
    )

    # Map severity to priority
    priority_map = {
        Severity.CRITICAL: "Highest",
        Severity.HIGH: "High",
        Severity.MEDIUM: "Medium",
        Severity.LOW: "Low",
        Severity.INFO: "Lowest",
    }

    issue_dict = {
        "project": {"key": settings.jira_project_key},
        "summary": summary,
        "description": ticket_description,
        "issuetype": {"name": "Task"},
        "priority": {"name": priority_map.get(severity, "Medium")},
        "duedate": sla_deadline.strftime("%Y-%m-%d"),
        "labels": ["vulnerability", severity.value, cve.replace("-", "_") if cve else "no_cve"],
    }

    issue = jira.create_issue(fields=issue_dict)

    return issue.key, issue.permalink()


def close_ticket(ticket_id: str) -> bool:
    """Close a Jira ticket."""
    jira = get_jira_client()
    if not jira:
        logger.debug("Jira client not configured, skipping ticket close")
        return False

    try:
        issue = jira.issue(ticket_id)
        # Find "Done" transition
        transitions = jira.transitions(issue)
        for t in transitions:
            if t["name"].lower() in ["done", "closed", "resolved"]:
                jira.transition_issue(issue, t["id"])
                logger.info(f"Closed Jira ticket {ticket_id}")
                return True
        logger.warning(f"No suitable close transition found for ticket {ticket_id}")
        return False
    except Exception as e:
        logger.error(f"Failed to close Jira ticket {ticket_id}: {str(e)}")
        return False


def sync_ticket_status(ticket_id: str) -> dict | None:
    """Sync status from Jira ticket."""
    jira = get_jira_client()
    if not jira:
        logger.debug("Jira client not configured, skipping status sync")
        return None

    try:
        issue = jira.issue(ticket_id)
        status_info = {
            "status": str(issue.fields.status),
            "assignee": str(issue.fields.assignee) if issue.fields.assignee else None,
        }
        logger.debug(f"Synced Jira ticket {ticket_id}: status={status_info['status']}")
        return status_info
    except Exception as e:
        logger.error(f"Failed to sync Jira ticket {ticket_id}: {str(e)}")
        return None
