# app/routers/imports.py
from fastapi import APIRouter, UploadFile, File, Form, Depends, HTTPException
from sqlalchemy.orm import Session
from pathlib import Path
from datetime import datetime
import tempfile

from app.database import get_db
from app.models import Vulnerability, Import, Scanner, Status
from app.schemas import ImportResponse, ImportRequest
from app.services.parser import parse_qualys_report, parse_tenable_report
from app.services.sla import calculate_sla_deadline
from app.services.claude_client import generate_remediation_guidance
from app.services.jira_client import create_vulnerability_ticket, close_ticket

router = APIRouter(prefix="/api/imports", tags=["imports"])


@router.post("/upload", response_model=ImportResponse)
async def upload_report(
    file: UploadFile = File(...),
    scanner: Scanner = Form(...),
    db: Session = Depends(get_db)
):
    """Upload and process a vulnerability report."""

    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx") as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        # Parse based on scanner type
        if scanner == Scanner.QUALYS:
            vulns = list(parse_qualys_report(tmp_path))
        else:
            vulns = list(parse_tenable_report(tmp_path))

        new_count = 0
        existing_count = 0

        # Get all current open vulns for this scanner to track resolved
        current_vuln_keys = set()

        for vuln_data in vulns:
            # Create unique key
            key = (vuln_data.host, vuln_data.cve)
            current_vuln_keys.add(key)

            # Check if vulnerability already exists
            existing = db.query(Vulnerability).filter(
                Vulnerability.host == vuln_data.host,
                Vulnerability.cve == vuln_data.cve
            ).first()

            if existing:
                # Update last_seen
                existing.last_seen = datetime.now()
                existing_count += 1
            else:
                # New vulnerability
                first_seen = datetime.now()
                sla_deadline = calculate_sla_deadline(vuln_data.severity, first_seen)

                # Generate AI remediation guidance
                remediation = generate_remediation_guidance(
                    cve=vuln_data.cve,
                    title=vuln_data.title,
                    description=vuln_data.description,
                    solution=vuln_data.solution,
                    severity=vuln_data.severity,
                    host=vuln_data.host,
                    os=vuln_data.os
                )

                # Create Jira ticket
                try:
                    ticket_id, ticket_url = create_vulnerability_ticket(
                        cve=vuln_data.cve,
                        title=vuln_data.title,
                        severity=vuln_data.severity,
                        host=vuln_data.host,
                        scanner=vuln_data.scanner,
                        scanner_id=vuln_data.scanner_id,
                        severity_score=vuln_data.severity_score,
                        first_seen=first_seen,
                        sla_deadline=sla_deadline,
                        description=vuln_data.description,
                        solution=vuln_data.solution,
                        remediation_guidance=remediation
                    )
                except Exception as e:
                    ticket_id = None
                    ticket_url = None

                # Create database record
                new_vuln = Vulnerability(
                    host=vuln_data.host,
                    cve=vuln_data.cve,
                    scanner=vuln_data.scanner,
                    scanner_id=vuln_data.scanner_id,
                    severity=vuln_data.severity,
                    severity_score=vuln_data.severity_score,
                    vpr_score=vuln_data.vpr_score,
                    title=vuln_data.title,
                    description=vuln_data.description,
                    solution=vuln_data.solution,
                    remediation_guidance=remediation,
                    port=vuln_data.port,
                    protocol=vuln_data.protocol,
                    service=vuln_data.service,
                    os=vuln_data.os,
                    first_seen=first_seen,
                    last_seen=first_seen,
                    sla_deadline=sla_deadline,
                    jira_ticket_id=ticket_id,
                    jira_ticket_url=ticket_url,
                )
                db.add(new_vuln)
                new_count += 1

        # Mark vulnerabilities not in report as resolved
        resolved_count = 0
        open_vulns = db.query(Vulnerability).filter(
            Vulnerability.scanner == scanner,
            Vulnerability.status.in_([Status.OPEN, Status.IN_PROGRESS])
        ).all()

        for vuln in open_vulns:
            key = (vuln.host, vuln.cve)
            if key not in current_vuln_keys:
                vuln.status = Status.RESOLVED
                vuln.resolved_date = datetime.now()
                # Close Jira ticket
                if vuln.jira_ticket_id:
                    close_ticket(vuln.jira_ticket_id)
                resolved_count += 1

        # Create import record
        import_record = Import(
            filename=file.filename,
            scanner=scanner,
            new_count=new_count,
            existing_count=existing_count,
            resolved_count=resolved_count
        )
        db.add(import_record)
        db.commit()
        db.refresh(import_record)

        return import_record

    finally:
        # Cleanup temp file
        tmp_path.unlink(missing_ok=True)


@router.get("/", response_model=list[ImportResponse])
async def list_imports(
    limit: int = 10,
    db: Session = Depends(get_db)
):
    """List recent imports."""
    imports = db.query(Import).order_by(Import.imported_at.desc()).limit(limit).all()
    return imports
