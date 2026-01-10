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
        # Risk acceptance fields
        "egrc_number": vuln.egrc_number,
        "egrc_expiry_date": vuln.egrc_expiry_date,
        "risk_accepted_date": vuln.risk_accepted_date,
        "risk_accepted_reason": vuln.risk_accepted_reason,
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

    # Count risk accepted
    risk_accepted_count = db.query(func.count(Vulnerability.id)).filter(
        Vulnerability.status == Status.ACCEPTED_RISK
    ).scalar()

    # Count resolved
    resolved_count = db.query(func.count(Vulnerability.id)).filter(
        Vulnerability.status == Status.RESOLVED
    ).scalar()

    return {
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "info": counts.get("info", 0),
        "total_open": sum(counts.values()),
        "risk_accepted": risk_accepted_count,
        "resolved": resolved_count
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


@router.delete("/{vuln_id}")
async def delete_vulnerability(vuln_id: str, db: Session = Depends(get_db)):
    """Delete a single vulnerability and close its Jira ticket."""
    from app.services.jira_client import close_ticket

    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    # Close Jira ticket if exists
    jira_closed = False
    if vuln.jira_ticket_id:
        try:
            jira_closed = close_ticket(vuln.jira_ticket_id)
        except Exception:
            pass  # Continue even if Jira close fails

    db.delete(vuln)
    db.commit()
    return {
        "message": f"Deleted vulnerability {vuln_id}",
        "jira_closed": jira_closed
    }


@router.post("/{vuln_id}/accept-risk", response_model=VulnerabilityResponse)
async def accept_risk(
    vuln_id: str,
    egrc_number: str = Query(..., description="EGRC reference number"),
    egrc_expiry_date: str = Query(..., description="Expiry date (YYYY-MM-DD)"),
    reason: Optional[str] = Query(None, description="Reason for acceptance"),
    db: Session = Depends(get_db)
):
    """Mark a vulnerability as risk accepted with EGRC details."""
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    vuln.status = Status.ACCEPTED_RISK
    vuln.egrc_number = egrc_number
    vuln.egrc_expiry_date = datetime.fromisoformat(egrc_expiry_date)
    vuln.risk_accepted_date = datetime.now()
    vuln.risk_accepted_reason = reason

    db.commit()
    db.refresh(vuln)
    return enrich_vulnerability(vuln)


def map_jira_to_vuln_status(jira_status: str) -> Status | None:
    """Map Jira status to vulnerability status."""
    jira_status_lower = jira_status.lower() if jira_status else ""

    # Done/Closed/Resolved -> RESOLVED
    if jira_status_lower in ["done", "closed", "resolved"]:
        return Status.RESOLVED
    # In Progress -> IN_PROGRESS
    elif jira_status_lower in ["in progress", "in-progress"]:
        return Status.IN_PROGRESS
    # To Do/Open/Backlog -> OPEN
    elif jira_status_lower in ["to do", "todo", "open", "backlog", "new"]:
        return Status.OPEN

    return None


@router.post("/{vuln_id}/sync-jira", response_model=VulnerabilityResponse)
async def sync_jira_status(vuln_id: str, db: Session = Depends(get_db)):
    """Sync status from Jira for a single vulnerability."""
    from app.services.jira_client import sync_ticket_status

    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    if not vuln.jira_ticket_id:
        raise HTTPException(status_code=400, detail="No Jira ticket linked")

    status = sync_ticket_status(vuln.jira_ticket_id)
    if status:
        vuln.jira_status = status.get("status")
        vuln.jira_assignee = status.get("assignee")

        # Map Jira status to vulnerability status
        new_status = map_jira_to_vuln_status(vuln.jira_status)
        if new_status and vuln.status != Status.ACCEPTED_RISK and vuln.status != new_status:
            vuln.status = new_status
            if new_status == Status.RESOLVED:
                vuln.resolved_date = datetime.now()
            else:
                vuln.resolved_date = None  # Clear if reopened

        db.commit()
        db.refresh(vuln)

    return enrich_vulnerability(vuln)


@router.post("/sync-all-jira")
async def sync_all_jira(db: Session = Depends(get_db)):
    """Sync Jira status for all vulnerabilities with tickets."""
    from app.services.jira_client import sync_ticket_status

    # Include RESOLVED to allow reopening if Jira ticket is reopened
    vulns = db.query(Vulnerability).filter(
        Vulnerability.jira_ticket_id.isnot(None),
        Vulnerability.status.in_([Status.OPEN, Status.IN_PROGRESS, Status.RESOLVED])
    ).all()

    updated = 0
    status_changes = {"resolved": 0, "in_progress": 0, "open": 0}
    for vuln in vulns:
        try:
            status = sync_ticket_status(vuln.jira_ticket_id)
            if status:
                vuln.jira_status = status.get("status")
                vuln.jira_assignee = status.get("assignee")

                # Map Jira status to vulnerability status
                new_status = map_jira_to_vuln_status(vuln.jira_status)
                if new_status and vuln.status != new_status:
                    vuln.status = new_status
                    if new_status == Status.RESOLVED:
                        vuln.resolved_date = datetime.now()
                        status_changes["resolved"] += 1
                    elif new_status == Status.IN_PROGRESS:
                        vuln.resolved_date = None  # Clear if reopened
                        status_changes["in_progress"] += 1
                    elif new_status == Status.OPEN:
                        vuln.resolved_date = None  # Clear if reopened
                        status_changes["open"] += 1

                updated += 1
        except Exception:
            pass

    db.commit()
    return {
        "message": f"Synced {updated} of {len(vulns)} vulnerabilities",
        "status_changes": status_changes
    }


@router.delete("/")
async def delete_all_vulnerabilities(
    confirm: bool = Query(..., description="Must be true to confirm deletion"),
    db: Session = Depends(get_db)
):
    """Delete ALL vulnerabilities. Requires confirm=true."""
    if not confirm:
        raise HTTPException(status_code=400, detail="Must set confirm=true to delete all")

    from app.models import Import
    count = db.query(Vulnerability).count()
    db.query(Vulnerability).delete()
    db.query(Import).delete()
    db.commit()
    return {"message": f"Deleted {count} vulnerabilities and all import records"}
