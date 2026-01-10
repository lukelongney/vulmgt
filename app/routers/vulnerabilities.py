# app/routers/vulnerabilities.py
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime
from typing import Optional

from app.database import get_db
from app.models import Vulnerability, Status, Severity
from app.schemas import VulnerabilityResponse, VulnerabilityUpdate
from app.services.sla import calculate_sla_status
from app.config import get_settings

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])
settings = get_settings()


def enrich_vulnerability(vuln: Vulnerability) -> dict:
    """Add computed fields to vulnerability."""
    data = {
        "id": vuln.id,
        "host": vuln.host,
        "cve": vuln.cve,
        "scanner": vuln.scanner,
        "scanner_id": vuln.scanner_id,
        "severity": vuln.severity,
        "severity_score": vuln.severity_score,
        "vpr_score": vuln.vpr_score,
        "title": vuln.title,
        "description": vuln.description,
        "solution": vuln.solution,
        "remediation_guidance": vuln.remediation_guidance,
        "port": vuln.port,
        "protocol": vuln.protocol,
        "service": vuln.service,
        "os": vuln.os,
        "first_seen": vuln.first_seen,
        "last_seen": vuln.last_seen,
        "status": vuln.status,
        "sla_deadline": vuln.sla_deadline,
        "jira_ticket_id": vuln.jira_ticket_id,
        "jira_ticket_url": vuln.jira_ticket_url,
        "jira_status": vuln.jira_status,
        "jira_assignee": vuln.jira_assignee,
        "resolved_date": vuln.resolved_date,
    }

    if vuln.sla_deadline and vuln.first_seen:
        days_remaining, percent_elapsed = calculate_sla_status(
            vuln.first_seen, vuln.sla_deadline
        )
        data["days_remaining"] = days_remaining
        data["sla_percent_elapsed"] = round(percent_elapsed, 1)

    return data


@router.get("/", response_model=list[VulnerabilityResponse])
async def list_vulnerabilities(
    status: Optional[Status] = None,
    severity: Optional[Severity] = None,
    host: Optional[str] = None,
    approaching_sla: bool = False,
    limit: int = Query(default=100, le=500),
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """List vulnerabilities with optional filters."""
    query = db.query(Vulnerability)

    if status:
        query = query.filter(Vulnerability.status == status)
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    if host:
        query = query.filter(Vulnerability.host.ilike(f"%{host}%"))
    if approaching_sla:
        # Filter to open vulns approaching SLA
        query = query.filter(
            Vulnerability.status.in_([Status.OPEN, Status.IN_PROGRESS])
        )

    vulns = query.order_by(Vulnerability.sla_deadline.asc()).offset(offset).limit(limit).all()

    result = [enrich_vulnerability(v) for v in vulns]

    if approaching_sla:
        threshold = settings.escalation_threshold_percent
        result = [v for v in result if v.get("sla_percent_elapsed", 0) >= threshold]

    return result


@router.get("/stats")
async def get_stats(db: Session = Depends(get_db)):
    """Get vulnerability statistics."""

    # Count by severity for open vulns
    severity_counts = db.query(
        Vulnerability.severity,
        func.count(Vulnerability.id)
    ).filter(
        Vulnerability.status.in_([Status.OPEN, Status.IN_PROGRESS])
    ).group_by(Vulnerability.severity).all()

    counts = {s.value: 0 for s in Severity}
    for sev, count in severity_counts:
        counts[sev.value] = count

    return {
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "info": counts.get("info", 0),
        "total_open": sum(counts.values())
    }


@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(vuln_id: str, db: Session = Depends(get_db)):
    """Get a single vulnerability by ID."""
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return enrich_vulnerability(vuln)


@router.patch("/{vuln_id}", response_model=VulnerabilityResponse)
async def update_vulnerability(
    vuln_id: str,
    update: VulnerabilityUpdate,
    db: Session = Depends(get_db)
):
    """Update vulnerability status."""
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    update_data = update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(vuln, field, value)

    db.commit()
    db.refresh(vuln)
    return enrich_vulnerability(vuln)
