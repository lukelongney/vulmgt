# app/schemas.py
from pydantic import BaseModel
from datetime import datetime
from typing import Optional
from app.models import Scanner, Severity, Status


class VulnerabilityBase(BaseModel):
    host: str
    cve: Optional[str] = None
    scanner: Scanner
    scanner_id: Optional[str] = None
    severity: Severity
    severity_score: Optional[float] = None
    vpr_score: Optional[float] = None
    title: str
    description: Optional[str] = None
    solution: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    service: Optional[str] = None
    os: Optional[str] = None


class VulnerabilityCreate(VulnerabilityBase):
    pass


class VulnerabilityUpdate(BaseModel):
    status: Optional[Status] = None
    jira_status: Optional[str] = None
    jira_assignee: Optional[str] = None
    resolved_date: Optional[datetime] = None


class VulnerabilityResponse(VulnerabilityBase):
    id: str
    first_seen: datetime
    last_seen: datetime
    status: Status
    sla_deadline: Optional[datetime] = None
    jira_ticket_id: Optional[str] = None
    jira_ticket_url: Optional[str] = None
    jira_status: Optional[str] = None
    jira_assignee: Optional[str] = None
    remediation_guidance: Optional[str] = None
    resolved_date: Optional[datetime] = None
    days_remaining: Optional[int] = None
    sla_percent_elapsed: Optional[float] = None

    class Config:
        from_attributes = True


class ImportResponse(BaseModel):
    id: str
    filename: str
    scanner: Scanner
    imported_at: datetime
    new_count: int
    existing_count: int
    resolved_count: int

    class Config:
        from_attributes = True


class DashboardStats(BaseModel):
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    approaching_sla: list[VulnerabilityResponse]
    recent_imports: list[ImportResponse]


class ImportRequest(BaseModel):
    scanner: Scanner
