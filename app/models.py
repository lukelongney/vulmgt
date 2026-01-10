# app/models.py
from sqlalchemy import Column, String, Integer, Float, DateTime, Enum, Text
from sqlalchemy.sql import func
from app.database import Base
import enum
import uuid


def generate_uuid():
    return str(uuid.uuid4())


class Scanner(str, enum.Enum):
    QUALYS = "qualys"
    TENABLE = "tenable"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Status(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    ACCEPTED_RISK = "accepted_risk"


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(String, primary_key=True, default=generate_uuid)
    host = Column(String, nullable=False, index=True)
    cve = Column(String, index=True)
    scanner = Column(Enum(Scanner), nullable=False)
    scanner_id = Column(String)  # QID or Plugin ID
    severity = Column(Enum(Severity), nullable=False, index=True)
    severity_score = Column(Float)
    vpr_score = Column(Float)
    title = Column(String, nullable=False)
    description = Column(Text)
    solution = Column(Text)
    remediation_guidance = Column(Text)
    port = Column(Integer)
    protocol = Column(String)
    service = Column(String)
    os = Column(String)
    first_seen = Column(DateTime, default=func.now())
    last_seen = Column(DateTime, default=func.now(), onupdate=func.now())
    status = Column(Enum(Status), default=Status.OPEN, index=True)
    sla_deadline = Column(DateTime)
    jira_ticket_id = Column(String)
    jira_ticket_url = Column(String)
    jira_status = Column(String)
    jira_assignee = Column(String)
    resolved_date = Column(DateTime)

    __table_args__ = (
        # Unique constraint on host + cve
        {"sqlite_autoincrement": True},
    )


class Import(Base):
    __tablename__ = "imports"

    id = Column(String, primary_key=True, default=generate_uuid)
    filename = Column(String, nullable=False)
    scanner = Column(Enum(Scanner), nullable=False)
    imported_at = Column(DateTime, default=func.now())
    new_count = Column(Integer, default=0)
    existing_count = Column(Integer, default=0)
    resolved_count = Column(Integer, default=0)


class SLAConfig(Base):
    __tablename__ = "sla_config"

    severity = Column(Enum(Severity), primary_key=True)
    days = Column(Integer, nullable=False)
