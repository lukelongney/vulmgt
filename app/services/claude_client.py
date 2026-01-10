# app/services/claude_client.py
import anthropic
from app.config import get_settings
from app.models import Severity

settings = get_settings()


def generate_remediation_guidance(
    cve: str | None,
    title: str,
    description: str | None,
    solution: str | None,
    severity: Severity,
    host: str,
    os: str | None = None
) -> str:
    """Generate AI-powered remediation guidance using Claude."""

    if not settings.anthropic_api_key:
        return "AI remediation guidance unavailable - API key not configured."

    client = anthropic.Anthropic(api_key=settings.anthropic_api_key)

    prompt = f"""You are a security expert providing remediation guidance for a vulnerability.

Vulnerability Details:
- CVE: {cve or 'N/A'}
- Title: {title}
- Severity: {severity.value.upper()}
- Host: {host}
- Operating System: {os or 'Unknown'}
- Scanner Description: {description or 'Not provided'}
- Scanner Solution: {solution or 'Not provided'}

Provide clear, actionable remediation steps that a system administrator can follow.
Include:
1. Specific commands to run (with OS-appropriate syntax)
2. Files or configurations to check
3. How to verify the fix was successful
4. Any precautions or backup steps

Keep the response concise and practical (under 300 words).
Format as numbered steps."""

    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[
            {"role": "user", "content": prompt}
        ]
    )

    return message.content[0].text


def generate_insights(vulnerabilities: list[dict]) -> dict:
    """Generate AI insights analyzing vulnerability patterns."""

    if not settings.anthropic_api_key:
        return {"error": "AI insights unavailable - API key not configured."}

    if not vulnerabilities:
        return {"patterns": [], "recommendations": [], "training_opportunities": []}

    client = anthropic.Anthropic(api_key=settings.anthropic_api_key)

    # Summarize vulnerabilities for analysis
    vuln_summary = []
    for v in vulnerabilities[:100]:  # Limit to 100 for token efficiency
        vuln_summary.append(f"- {v.get('severity', 'unknown').upper()}: {v.get('title', 'Unknown')} on {v.get('host', 'unknown')} (CVE: {v.get('cve', 'N/A')})")

    prompt = f"""Analyze these open vulnerabilities and identify patterns:

{chr(10).join(vuln_summary)}

Provide analysis in this JSON format:
{{
  "patterns": [
    {{"type": "recurring_issue", "description": "...", "affected_hosts": ["host1", "host2"], "recommendation": "..."}},
  ],
  "training_opportunities": [
    {{"topic": "...", "reason": "...", "affected_count": N}}
  ],
  "priority_actions": [
    {{"action": "...", "impact": "resolves N vulnerabilities", "effort": "low/medium/high"}}
  ]
}}

Focus on:
1. Recurring CVEs across multiple hosts
2. Common vulnerability types (injection, misconfig, outdated software)
3. Training needs (patterns suggesting knowledge gaps)
4. High-impact fixes (one action resolving many vulns)"""

    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2048,
        messages=[
            {"role": "user", "content": prompt}
        ]
    )

    # Parse JSON response
    import json
    try:
        return json.loads(message.content[0].text)
    except json.JSONDecodeError:
        return {"raw_analysis": message.content[0].text}
