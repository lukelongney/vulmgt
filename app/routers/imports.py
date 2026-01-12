# app/routers/imports.py
from fastapi import APIRouter, UploadFile, File, Form, Depends, HTTPException
from sqlalchemy.orm import Session
from pathlib import Path
from datetime import datetime
import tempfile
import logging
import zipfile

from app.database import get_db
from app.models import Vulnerability, Import, Scanner, Status
from app.schemas import ImportResponse, ImportRequest
from app.services.parser import parse_qualys_report, parse_tenable_report
from app.services.sla import calculate_sla_deadline
from app.services.claude_client import generate_remediation_guidance
from app.services.jira_client import create_vulnerability_ticket, close_ticket

router = APIRouter(prefix="/api/imports", tags=["imports"])
logger = logging.getLogger(__name__)

# Security: File upload limits
MAX_FILE_SIZE_MB = 50
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024  # 50 MB
ALLOWED_EXTENSIONS = {'.xlsx', '.xls'}
# Excel magic bytes (ZIP format for xlsx, OLE2 for xls)
XLSX_MAGIC = b'PK\x03\x04'
XLS_MAGIC = b'\xd0\xcf\x11\xe0'

# In-memory log storage for UI display
_import_logs: list[dict] = []
MAX_LOGS = 100


def add_log(level: str, message: str, details: str = None):
    """Add a log entry."""
    # Sanitize details to avoid leaking sensitive information
    safe_details = details[:500] if details else None  # Truncate long details
    _import_logs.append({
        "timestamp": datetime.now().isoformat(),
        "level": level,
        "message": message,
        "details": safe_details
    })
    # Keep only last MAX_LOGS
    while len(_import_logs) > MAX_LOGS:
        _import_logs.pop(0)
    # Also log to console
    getattr(logger, level.lower(), logger.info)(f"{message} - {safe_details}")


def validate_excel_file(content: bytes, filename: str) -> None:
    """
    Validate that the uploaded file is a legitimate Excel file.
    Raises HTTPException if validation fails.
    """
    # Check file size
    if len(content) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size is {MAX_FILE_SIZE_MB}MB"
        )

    if len(content) == 0:
        raise HTTPException(
            status_code=400,
            detail="Empty file uploaded"
        )

    # Check file extension
    file_ext = Path(filename).suffix.lower() if filename else ''
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    # Check magic bytes (file signature)
    if file_ext == '.xlsx':
        if not content.startswith(XLSX_MAGIC):
            raise HTTPException(
                status_code=400,
                detail="File content does not match .xlsx format"
            )
        # Verify it's a valid ZIP (xlsx is a ZIP archive)
        try:
            import io
            with zipfile.ZipFile(io.BytesIO(content), 'r') as zf:
                # Check for required Excel structure
                namelist = zf.namelist()
                if not any('xl/' in name for name in namelist):
                    raise HTTPException(
                        status_code=400,
                        detail="Invalid Excel file structure"
                    )
        except zipfile.BadZipFile:
            raise HTTPException(
                status_code=400,
                detail="Corrupted or invalid .xlsx file"
            )
    elif file_ext == '.xls':
        if not content.startswith(XLS_MAGIC):
            raise HTTPException(
                status_code=400,
                detail="File content does not match .xls format"
            )


@router.post("/upload", response_model=ImportResponse)
async def upload_report(
    file: UploadFile = File(...),
    scanner: Scanner = Form(...),
    db: Session = Depends(get_db)
):
    """Upload and process a vulnerability report."""

    # Read file content
    content = await file.read()

    # Security: Validate file before processing
    validate_excel_file(content, file.filename)

    # Save validated file temporarily
    file_ext = Path(file.filename).suffix.lower() if file.filename else '.xlsx'
    with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        add_log("INFO", f"Starting import", f"File: {file.filename}, Scanner: {scanner.value}")

        # Parse based on scanner type
        if scanner == Scanner.QUALYS:
            vulns = list(parse_qualys_report(tmp_path))
        else:
            vulns = list(parse_tenable_report(tmp_path))

        add_log("INFO", f"Parsed {len(vulns)} vulnerabilities from file")

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
                try:
                    remediation = generate_remediation_guidance(
                        cve=vuln_data.cve,
                        title=vuln_data.title,
                        description=vuln_data.description,
                        solution=vuln_data.solution,
                        severity=vuln_data.severity,
                        host=vuln_data.host,
                        os=vuln_data.os
                    )
                except Exception as e:
                    # Log detailed error internally, but don't expose to users
                    logger.error(f"Failed to generate AI remediation: {str(e)}")
                    add_log("ERROR", "Failed to generate AI remediation", "Internal error - check server logs")
                    remediation = None

                # Create Jira ticket
                ticket_id = None
                ticket_url = None
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
                    add_log("INFO", f"Created Jira ticket {ticket_id}", f"CVE: {vuln_data.cve}, Host: {vuln_data.host}")
                except ValueError as e:
                    add_log("WARNING", "Jira not configured", "Configure JIRA_URL, JIRA_EMAIL, and JIRA_API_TOKEN")
                except Exception as e:
                    # Log detailed error internally, sanitize for UI
                    logger.error(f"Failed to create Jira ticket for CVE {vuln_data.cve}: {str(e)}")
                    add_log("ERROR", "Failed to create Jira ticket", f"CVE: {vuln_data.cve or 'N/A'}")

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

        add_log("INFO", f"Import complete", f"New: {new_count}, Existing: {existing_count}, Resolved: {resolved_count}")

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


@router.get("/logs")
async def get_logs():
    """Get import logs for debugging."""
    return {"logs": list(reversed(_import_logs))}


@router.delete("/logs")
async def clear_logs():
    """Clear all logs."""
    _import_logs.clear()
    return {"message": "Logs cleared"}
