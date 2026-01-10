# Vulnerability Management App Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a vulnerability management app that ingests Qualys/Tenable XLS reports, creates Jira tickets with AI remediation guidance, and provides a dashboard with SLA tracking.

**Architecture:** FastAPI backend with SQLite database, serving a vanilla JS frontend. Services handle parsing, Jira integration, and Claude API calls. Designed for easy Docker/AKS migration.

**Tech Stack:** Python 3.11+, FastAPI, SQLAlchemy, SQLite, openpyxl, jira-python, anthropic SDK, HTML/Tailwind CSS

---

## Phase 1: Project Skeleton

### Task 1: Create requirements.txt

**Files:**
- Create: `requirements.txt`

**Step 1: Create requirements file**

```txt
fastapi==0.109.0
uvicorn[standard]==0.27.0
sqlalchemy==2.0.25
openpyxl==3.1.2
jira==3.6.0
anthropic==0.18.1
python-multipart==0.0.6
pydantic==2.5.3
pydantic-settings==2.1.0
python-dotenv==1.0.0
pytest==7.4.4
httpx==0.26.0
```

**Step 2: Commit**

```bash
git add requirements.txt
git commit -m "chore: add requirements.txt with core dependencies"
```

---

### Task 2: Create FastAPI entry point

**Files:**
- Create: `app/__init__.py`
- Create: `app/main.py`

**Step 1: Create package init**

```python
# app/__init__.py
```

**Step 2: Create main.py with basic FastAPI app**

```python
# app/main.py
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path

app = FastAPI(title="Vulnerability Management", version="0.1.0")

static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/")
async def root():
    index_path = static_dir / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return {"status": "ok", "message": "Vulnerability Management API"}


@app.get("/health")
async def health():
    return {"status": "healthy"}
```

**Step 3: Create static directory placeholder**

```bash
mkdir -p app/static
```

**Step 4: Commit**

```bash
git add app/
git commit -m "feat: add FastAPI entry point with health endpoint"
```

---

### Task 3: Create configuration management

**Files:**
- Create: `app/config.py`
- Create: `.env.example`

**Step 1: Create config.py**

```python
# app/config.py
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # Database
    database_url: str = "sqlite:///./data/vulmgt.db"

    # Jira
    jira_url: str = ""
    jira_email: str = ""
    jira_api_token: str = ""
    jira_project_key: str = ""

    # Claude
    anthropic_api_key: str = ""

    # SLA defaults (days)
    sla_critical: int = 14
    sla_high: int = 14
    sla_medium: int = 90
    sla_low: int = 180

    # Escalation
    escalation_threshold_percent: int = 75

    class Config:
        env_file = ".env"


@lru_cache
def get_settings() -> Settings:
    return Settings()
```

**Step 2: Create .env.example**

```env
# Database
DATABASE_URL=sqlite:///./data/vulmgt.db

# Jira Configuration
JIRA_URL=https://yourcompany.atlassian.net
JIRA_EMAIL=your.email@company.com
JIRA_API_TOKEN=your-api-token
JIRA_PROJECT_KEY=VULN

# Claude API
ANTHROPIC_API_KEY=sk-ant-...

# SLA Configuration (days)
SLA_CRITICAL=14
SLA_HIGH=14
SLA_MEDIUM=90
SLA_LOW=180

# Escalation threshold (percent of SLA elapsed)
ESCALATION_THRESHOLD_PERCENT=75
```

**Step 3: Commit**

```bash
git add app/config.py .env.example
git commit -m "feat: add configuration management with pydantic-settings"
```

---

## Phase 2: Database Models

### Task 4: Create database models

**Files:**
- Create: `app/database.py`
- Create: `app/models.py`

**Step 1: Create database.py with engine setup**

```python
# app/database.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from pathlib import Path
from app.config import get_settings

settings = get_settings()

# Ensure data directory exists
db_path = settings.database_url.replace("sqlite:///", "")
Path(db_path).parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False}  # SQLite specific
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

**Step 2: Create models.py with all tables**

```python
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
```

**Step 3: Add database initialization to main.py**

Edit `app/main.py` to add at the top after imports:

```python
from app.database import engine, Base

# Create tables on startup
Base.metadata.create_all(bind=engine)
```

**Step 4: Commit**

```bash
git add app/database.py app/models.py app/main.py
git commit -m "feat: add SQLAlchemy database models for vulnerabilities and imports"
```

---

### Task 5: Create Pydantic schemas

**Files:**
- Create: `app/schemas.py`

**Step 1: Create schemas.py**

```python
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
```

**Step 2: Commit**

```bash
git add app/schemas.py
git commit -m "feat: add Pydantic schemas for API request/response validation"
```

---

## Phase 3: Core Services

### Task 6: Create SLA service

**Files:**
- Create: `app/services/__init__.py`
- Create: `app/services/sla.py`
- Create: `tests/__init__.py`
- Create: `tests/test_sla.py`

**Step 1: Create services package**

```python
# app/services/__init__.py
```

**Step 2: Write failing test for SLA calculation**

```python
# tests/__init__.py
```

```python
# tests/test_sla.py
from datetime import datetime, timedelta
from app.services.sla import calculate_sla_deadline, calculate_sla_status
from app.models import Severity


def test_calculate_sla_deadline_critical():
    first_seen = datetime(2026, 1, 10, 12, 0, 0)
    deadline = calculate_sla_deadline(Severity.CRITICAL, first_seen)
    expected = datetime(2026, 1, 24, 12, 0, 0)  # 14 days
    assert deadline == expected


def test_calculate_sla_deadline_medium():
    first_seen = datetime(2026, 1, 10, 12, 0, 0)
    deadline = calculate_sla_deadline(Severity.MEDIUM, first_seen)
    expected = datetime(2026, 4, 10, 12, 0, 0)  # 90 days
    assert deadline == expected


def test_calculate_sla_status_approaching():
    first_seen = datetime.now() - timedelta(days=12)
    deadline = first_seen + timedelta(days=14)
    days_remaining, percent_elapsed = calculate_sla_status(first_seen, deadline)
    assert days_remaining == 2
    assert percent_elapsed > 75  # Should trigger escalation


def test_calculate_sla_status_overdue():
    first_seen = datetime.now() - timedelta(days=20)
    deadline = first_seen + timedelta(days=14)
    days_remaining, percent_elapsed = calculate_sla_status(first_seen, deadline)
    assert days_remaining < 0
    assert percent_elapsed > 100
```

**Step 3: Run test to verify it fails**

```bash
pytest tests/test_sla.py -v
```

Expected: FAIL with "ModuleNotFoundError"

**Step 4: Implement SLA service**

```python
# app/services/sla.py
from datetime import datetime, timedelta
from app.models import Severity
from app.config import get_settings


def get_sla_days(severity: Severity) -> int:
    """Get SLA days for a given severity level."""
    settings = get_settings()
    sla_map = {
        Severity.CRITICAL: settings.sla_critical,
        Severity.HIGH: settings.sla_high,
        Severity.MEDIUM: settings.sla_medium,
        Severity.LOW: settings.sla_low,
        Severity.INFO: 365,  # Info level gets 1 year
    }
    return sla_map.get(severity, 90)


def calculate_sla_deadline(severity: Severity, first_seen: datetime) -> datetime:
    """Calculate SLA deadline based on severity and first seen date."""
    days = get_sla_days(severity)
    return first_seen + timedelta(days=days)


def calculate_sla_status(first_seen: datetime, deadline: datetime) -> tuple[int, float]:
    """
    Calculate SLA status.
    Returns: (days_remaining, percent_elapsed)
    """
    now = datetime.now()
    total_days = (deadline - first_seen).days
    elapsed_days = (now - first_seen).days
    days_remaining = (deadline - now).days

    if total_days > 0:
        percent_elapsed = (elapsed_days / total_days) * 100
    else:
        percent_elapsed = 100.0

    return days_remaining, percent_elapsed


def is_approaching_sla(first_seen: datetime, deadline: datetime, threshold_percent: int = 75) -> bool:
    """Check if vulnerability is approaching SLA threshold."""
    _, percent_elapsed = calculate_sla_status(first_seen, deadline)
    return percent_elapsed >= threshold_percent
```

**Step 5: Run tests to verify they pass**

```bash
pytest tests/test_sla.py -v
```

Expected: 4 PASSED

**Step 6: Commit**

```bash
git add app/services/ tests/
git commit -m "feat: add SLA calculation service with tests"
```

---

### Task 7: Create XLS parser service

**Files:**
- Create: `app/services/parser.py`
- Create: `tests/test_parser.py`
- Create: `tests/fixtures/sample_qualys.xlsx`
- Create: `tests/fixtures/sample_tenable.xlsx`

**Step 1: Write failing test**

```python
# tests/test_parser.py
import pytest
from pathlib import Path
from app.services.parser import parse_qualys_report, parse_tenable_report, normalize_severity
from app.models import Severity


def test_normalize_severity_qualys():
    assert normalize_severity("5", "qualys") == Severity.CRITICAL
    assert normalize_severity("4", "qualys") == Severity.HIGH
    assert normalize_severity("3", "qualys") == Severity.MEDIUM
    assert normalize_severity("2", "qualys") == Severity.LOW
    assert normalize_severity("1", "qualys") == Severity.INFO


def test_normalize_severity_tenable():
    assert normalize_severity("Critical", "tenable") == Severity.CRITICAL
    assert normalize_severity("High", "tenable") == Severity.HIGH
    assert normalize_severity("Medium", "tenable") == Severity.MEDIUM
    assert normalize_severity("Low", "tenable") == Severity.LOW
    assert normalize_severity("Info", "tenable") == Severity.INFO
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_parser.py -v
```

Expected: FAIL

**Step 3: Implement parser service**

```python
# app/services/parser.py
from pathlib import Path
from typing import Generator
import openpyxl
from app.models import Scanner, Severity
from app.schemas import VulnerabilityCreate


# Column mappings for each scanner
QUALYS_COLUMNS = {
    "host": ["IP Address", "Hostname", "DNS Name"],
    "cve": ["CVE ID"],
    "scanner_id": ["QID"],
    "severity": ["Severity"],
    "severity_score": ["CVSS Base Score", "CVSS3 Base Score"],
    "vpr_score": ["QDS"],
    "title": ["Title"],
    "description": ["Threat", "Impact"],
    "solution": ["Solution"],
    "port": ["Port"],
    "protocol": ["Protocol"],
    "service": ["Service"],
    "os": ["Operating System", "OS"],
}

TENABLE_COLUMNS = {
    "host": ["Host", "DNS Name", "IP Address"],
    "cve": ["CVE"],
    "scanner_id": ["Plugin ID"],
    "severity": ["Risk", "Severity"],
    "severity_score": ["CVSS v3.0 Base Score", "CVSS v2.0 Base Score"],
    "vpr_score": ["VPR"],
    "title": ["Name", "Plugin Name"],
    "description": ["Description"],
    "solution": ["Solution"],
    "port": ["Port"],
    "protocol": ["Protocol"],
    "service": ["Plugin Family"],
    "os": ["CPE"],
}


def normalize_severity(value: str, scanner: str) -> Severity:
    """Normalize severity from scanner-specific format to standard enum."""
    if not value:
        return Severity.INFO

    value = str(value).strip().lower()

    if scanner == "qualys":
        mapping = {
            "5": Severity.CRITICAL,
            "4": Severity.HIGH,
            "3": Severity.MEDIUM,
            "2": Severity.LOW,
            "1": Severity.INFO,
        }
        return mapping.get(value, Severity.INFO)

    elif scanner == "tenable":
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
            "none": Severity.INFO,
        }
        return mapping.get(value, Severity.INFO)

    return Severity.INFO


def find_column_index(headers: list[str], possible_names: list[str]) -> int | None:
    """Find column index by checking possible column names."""
    headers_lower = [h.lower().strip() if h else "" for h in headers]
    for name in possible_names:
        if name.lower() in headers_lower:
            return headers_lower.index(name.lower())
    return None


def get_cell_value(row: tuple, index: int | None) -> str | None:
    """Safely get cell value from row."""
    if index is None or index >= len(row):
        return None
    value = row[index]
    if value is None:
        return None
    return str(value).strip()


def parse_excel_report(
    file_path: Path,
    scanner: Scanner,
    column_mapping: dict
) -> Generator[VulnerabilityCreate, None, None]:
    """Parse an Excel vulnerability report."""
    wb = openpyxl.load_workbook(file_path, read_only=True, data_only=True)
    ws = wb.active

    rows = ws.iter_rows(values_only=True)
    headers = next(rows, None)

    if not headers:
        return

    # Build index mapping
    indices = {}
    for field, possible_names in column_mapping.items():
        indices[field] = find_column_index(list(headers), possible_names)

    for row in rows:
        host = get_cell_value(row, indices.get("host"))
        if not host:
            continue

        title = get_cell_value(row, indices.get("title"))
        if not title:
            continue

        severity_raw = get_cell_value(row, indices.get("severity"))
        severity = normalize_severity(severity_raw, scanner.value)

        # Parse numeric fields
        severity_score = None
        score_raw = get_cell_value(row, indices.get("severity_score"))
        if score_raw:
            try:
                severity_score = float(score_raw)
            except ValueError:
                pass

        vpr_raw = get_cell_value(row, indices.get("vpr_score"))
        vpr_score = None
        if vpr_raw:
            try:
                vpr_score = float(vpr_raw)
            except ValueError:
                pass

        port_raw = get_cell_value(row, indices.get("port"))
        port = None
        if port_raw:
            try:
                port = int(float(port_raw))
            except ValueError:
                pass

        yield VulnerabilityCreate(
            host=host,
            cve=get_cell_value(row, indices.get("cve")),
            scanner=scanner,
            scanner_id=get_cell_value(row, indices.get("scanner_id")),
            severity=severity,
            severity_score=severity_score,
            vpr_score=vpr_score,
            title=title,
            description=get_cell_value(row, indices.get("description")),
            solution=get_cell_value(row, indices.get("solution")),
            port=port,
            protocol=get_cell_value(row, indices.get("protocol")),
            service=get_cell_value(row, indices.get("service")),
            os=get_cell_value(row, indices.get("os")),
        )

    wb.close()


def parse_qualys_report(file_path: Path) -> Generator[VulnerabilityCreate, None, None]:
    """Parse a Qualys XLS report."""
    return parse_excel_report(file_path, Scanner.QUALYS, QUALYS_COLUMNS)


def parse_tenable_report(file_path: Path) -> Generator[VulnerabilityCreate, None, None]:
    """Parse a Tenable XLS report."""
    return parse_excel_report(file_path, Scanner.TENABLE, TENABLE_COLUMNS)
```

**Step 4: Run tests to verify they pass**

```bash
pytest tests/test_parser.py -v
```

Expected: 2 PASSED

**Step 5: Commit**

```bash
git add app/services/parser.py tests/test_parser.py
git commit -m "feat: add XLS parser for Qualys and Tenable reports"
```

---

### Task 8: Create Claude client for remediation guidance

**Files:**
- Create: `app/services/claude_client.py`
- Create: `tests/test_claude_client.py`

**Step 1: Write failing test (mocked)**

```python
# tests/test_claude_client.py
import pytest
from unittest.mock import patch, MagicMock
from app.services.claude_client import generate_remediation_guidance
from app.models import Severity


@patch("app.services.claude_client.anthropic.Anthropic")
def test_generate_remediation_guidance(mock_anthropic):
    # Setup mock
    mock_client = MagicMock()
    mock_anthropic.return_value = mock_client
    mock_client.messages.create.return_value = MagicMock(
        content=[MagicMock(text="1. Update Apache\n2. Restart service")]
    )

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
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_claude_client.py -v
```

Expected: FAIL

**Step 3: Implement Claude client**

```python
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
```

**Step 4: Run tests**

```bash
pytest tests/test_claude_client.py -v
```

Expected: 1 PASSED

**Step 5: Commit**

```bash
git add app/services/claude_client.py tests/test_claude_client.py
git commit -m "feat: add Claude client for remediation guidance and insights"
```

---

### Task 9: Create Jira client

**Files:**
- Create: `app/services/jira_client.py`
- Create: `tests/test_jira_client.py`

**Step 1: Write failing test (mocked)**

```python
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


@patch("app.services.jira_client.JIRA")
def test_create_vulnerability_ticket(mock_jira_class):
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
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_jira_client.py -v
```

Expected: FAIL

**Step 3: Implement Jira client**

```python
# app/services/jira_client.py
from jira import JIRA
from datetime import datetime
from app.config import get_settings
from app.models import Severity, Scanner

settings = get_settings()


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
        return False

    try:
        issue = jira.issue(ticket_id)
        # Find "Done" transition
        transitions = jira.transitions(issue)
        for t in transitions:
            if t["name"].lower() in ["done", "closed", "resolved"]:
                jira.transition_issue(issue, t["id"])
                return True
        return False
    except Exception:
        return False


def sync_ticket_status(ticket_id: str) -> dict | None:
    """Sync status from Jira ticket."""
    jira = get_jira_client()
    if not jira:
        return None

    try:
        issue = jira.issue(ticket_id)
        return {
            "status": str(issue.fields.status),
            "assignee": str(issue.fields.assignee) if issue.fields.assignee else None,
        }
    except Exception:
        return None
```

**Step 4: Run tests**

```bash
pytest tests/test_jira_client.py -v
```

Expected: 2 PASSED

**Step 5: Commit**

```bash
git add app/services/jira_client.py tests/test_jira_client.py
git commit -m "feat: add Jira client for ticket creation and sync"
```

---

## Phase 4: API Routes

### Task 10: Create import router

**Files:**
- Create: `app/routers/__init__.py`
- Create: `app/routers/imports.py`

**Step 1: Create routers package**

```python
# app/routers/__init__.py
```

**Step 2: Create imports router**

```python
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
```

**Step 3: Register router in main.py**

Add to `app/main.py` after the imports:

```python
from app.routers import imports

app.include_router(imports.router)
```

**Step 4: Commit**

```bash
git add app/routers/ app/main.py
git commit -m "feat: add import router for uploading vulnerability reports"
```

---

### Task 11: Create vulnerabilities router

**Files:**
- Create: `app/routers/vulnerabilities.py`

**Step 1: Create vulnerabilities router**

```python
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
```

**Step 2: Register router in main.py**

Add to `app/main.py`:

```python
from app.routers import imports, vulnerabilities

app.include_router(imports.router)
app.include_router(vulnerabilities.router)
```

**Step 3: Commit**

```bash
git add app/routers/vulnerabilities.py app/main.py
git commit -m "feat: add vulnerabilities router with filtering and stats"
```

---

### Task 12: Create insights router

**Files:**
- Create: `app/routers/insights.py`

**Step 1: Create insights router**

```python
# app/routers/insights.py
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Vulnerability, Status
from app.services.claude_client import generate_insights

router = APIRouter(prefix="/api/insights", tags=["insights"])


@router.get("/")
async def get_insights(db: Session = Depends(get_db)):
    """Generate AI insights from current vulnerabilities."""

    # Get all open vulnerabilities
    vulns = db.query(Vulnerability).filter(
        Vulnerability.status.in_([Status.OPEN, Status.IN_PROGRESS])
    ).all()

    # Convert to dict for analysis
    vuln_data = [
        {
            "host": v.host,
            "cve": v.cve,
            "severity": v.severity.value,
            "title": v.title,
            "os": v.os,
        }
        for v in vulns
    ]

    insights = generate_insights(vuln_data)
    return insights


@router.get("/summary")
async def get_summary(db: Session = Depends(get_db)):
    """Get a quick summary without AI analysis."""

    vulns = db.query(Vulnerability).filter(
        Vulnerability.status.in_([Status.OPEN, Status.IN_PROGRESS])
    ).all()

    # Group by CVE
    cve_counts = {}
    for v in vulns:
        if v.cve:
            cve_counts[v.cve] = cve_counts.get(v.cve, 0) + 1

    # Find recurring CVEs (appearing on 3+ hosts)
    recurring = [
        {"cve": cve, "host_count": count}
        for cve, count in cve_counts.items()
        if count >= 3
    ]
    recurring.sort(key=lambda x: x["host_count"], reverse=True)

    # Group by host
    host_counts = {}
    for v in vulns:
        host_counts[v.host] = host_counts.get(v.host, 0) + 1

    # Most vulnerable hosts
    top_hosts = sorted(
        [{"host": h, "vuln_count": c} for h, c in host_counts.items()],
        key=lambda x: x["vuln_count"],
        reverse=True
    )[:10]

    return {
        "recurring_cves": recurring[:10],
        "top_vulnerable_hosts": top_hosts,
        "total_unique_cves": len(cve_counts),
        "total_hosts": len(host_counts),
    }
```

**Step 2: Register router in main.py**

Add to `app/main.py`:

```python
from app.routers import imports, vulnerabilities, insights

app.include_router(imports.router)
app.include_router(vulnerabilities.router)
app.include_router(insights.router)
```

**Step 3: Commit**

```bash
git add app/routers/insights.py app/main.py
git commit -m "feat: add insights router for AI-powered vulnerability analysis"
```

---

## Phase 5: Frontend Dashboard

### Task 13: Create dashboard HTML

**Files:**
- Create: `app/static/index.html`

**Step 1: Create index.html**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vulnerability Management Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    .severity-critical { background-color: #dc2626; color: white; }
    .severity-high { background-color: #ea580c; color: white; }
    .severity-medium { background-color: #ca8a04; color: white; }
    .severity-low { background-color: #16a34a; color: white; }
    .severity-info { background-color: #6b7280; color: white; }
  </style>
</head>
<body class="bg-gray-100 min-h-screen">
  <div class="container mx-auto px-4 py-8">
    <!-- Header -->
    <div class="flex justify-between items-center mb-8">
      <h1 class="text-3xl font-bold text-gray-800">Vulnerability Dashboard</h1>
      <button onclick="openImportModal()" class="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700">
        Import Report
      </button>
    </div>

    <!-- Stats Cards -->
    <div class="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8" id="stats">
      <div class="bg-white rounded-lg shadow p-4 text-center">
        <div class="text-3xl font-bold text-red-600" id="stat-critical">-</div>
        <div class="text-gray-500">Critical</div>
      </div>
      <div class="bg-white rounded-lg shadow p-4 text-center">
        <div class="text-3xl font-bold text-orange-600" id="stat-high">-</div>
        <div class="text-gray-500">High</div>
      </div>
      <div class="bg-white rounded-lg shadow p-4 text-center">
        <div class="text-3xl font-bold text-yellow-600" id="stat-medium">-</div>
        <div class="text-gray-500">Medium</div>
      </div>
      <div class="bg-white rounded-lg shadow p-4 text-center">
        <div class="text-3xl font-bold text-green-600" id="stat-low">-</div>
        <div class="text-gray-500">Low</div>
      </div>
      <div class="bg-white rounded-lg shadow p-4 text-center">
        <div class="text-3xl font-bold text-gray-600" id="stat-total">-</div>
        <div class="text-gray-500">Total Open</div>
      </div>
    </div>

    <!-- Approaching SLA Warning -->
    <div class="bg-amber-50 border-l-4 border-amber-500 rounded-lg shadow mb-8 p-4" id="sla-warning">
      <h2 class="text-lg font-semibold text-amber-800 mb-2">Approaching SLA Deadline</h2>
      <div id="sla-list" class="space-y-2">Loading...</div>
    </div>

    <!-- Tabs -->
    <div class="bg-white rounded-lg shadow">
      <div class="border-b">
        <nav class="flex">
          <button onclick="showTab('vulns')" id="tab-vulns" class="px-6 py-3 border-b-2 border-blue-600 text-blue-600 font-medium">
            Vulnerabilities
          </button>
          <button onclick="showTab('insights')" id="tab-insights" class="px-6 py-3 text-gray-500 hover:text-gray-700">
            AI Insights
          </button>
          <button onclick="showTab('imports')" id="tab-imports" class="px-6 py-3 text-gray-500 hover:text-gray-700">
            Import History
          </button>
        </nav>
      </div>

      <!-- Vulnerabilities Tab -->
      <div id="content-vulns" class="p-4">
        <div class="flex gap-4 mb-4">
          <select id="filter-severity" onchange="loadVulnerabilities()" class="border rounded px-3 py-2">
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select id="filter-status" onchange="loadVulnerabilities()" class="border rounded px-3 py-2">
            <option value="">All Statuses</option>
            <option value="open">Open</option>
            <option value="in_progress">In Progress</option>
            <option value="resolved">Resolved</option>
          </select>
          <input type="text" id="filter-host" placeholder="Filter by host..."
                 onkeyup="loadVulnerabilities()" class="border rounded px-3 py-2 flex-1">
        </div>
        <div id="vuln-table" class="overflow-x-auto">Loading...</div>
      </div>

      <!-- Insights Tab -->
      <div id="content-insights" class="p-4 hidden">
        <button onclick="loadInsights()" class="bg-purple-600 text-white px-4 py-2 rounded mb-4 hover:bg-purple-700">
          Generate AI Insights
        </button>
        <div id="insights-content">Click button to generate insights...</div>
      </div>

      <!-- Imports Tab -->
      <div id="content-imports" class="p-4 hidden">
        <div id="imports-list">Loading...</div>
      </div>
    </div>
  </div>

  <!-- Import Modal -->
  <div id="import-modal" class="fixed inset-0 bg-black bg-opacity-50 hidden items-center justify-center">
    <div class="bg-white rounded-lg p-6 w-full max-w-md">
      <h2 class="text-xl font-bold mb-4">Import Vulnerability Report</h2>
      <form id="import-form" onsubmit="submitImport(event)">
        <div class="mb-4">
          <label class="block text-gray-700 mb-2">Scanner Type</label>
          <select name="scanner" required class="w-full border rounded px-3 py-2">
            <option value="qualys">Qualys</option>
            <option value="tenable">Tenable</option>
          </select>
        </div>
        <div class="mb-4">
          <label class="block text-gray-700 mb-2">Report File (.xlsx)</label>
          <input type="file" name="file" accept=".xlsx,.xls" required class="w-full">
        </div>
        <div class="flex justify-end gap-2">
          <button type="button" onclick="closeImportModal()" class="px-4 py-2 border rounded">Cancel</button>
          <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">Import</button>
        </div>
      </form>
    </div>
  </div>

  <script src="/static/app.js"></script>
</body>
</html>
```

**Step 2: Commit**

```bash
git add app/static/index.html
git commit -m "feat: add dashboard HTML with stats, filters, and import modal"
```

---

### Task 14: Create dashboard JavaScript

**Files:**
- Create: `app/static/app.js`

**Step 1: Create app.js**

```javascript
// Vulnerability Management Dashboard JS

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  loadStats();
  loadApproachingSLA();
  loadVulnerabilities();
  loadImports();
});

// Load statistics
async function loadStats() {
  try {
    const res = await fetch('/api/vulnerabilities/stats');
    const stats = await res.json();

    document.getElementById('stat-critical').textContent = stats.critical;
    document.getElementById('stat-high').textContent = stats.high;
    document.getElementById('stat-medium').textContent = stats.medium;
    document.getElementById('stat-low').textContent = stats.low;
    document.getElementById('stat-total').textContent = stats.total_open;
  } catch (err) {
    console.error('Failed to load stats:', err);
  }
}

// Load vulnerabilities approaching SLA
async function loadApproachingSLA() {
  try {
    const res = await fetch('/api/vulnerabilities/?approaching_sla=true&limit=10');
    const vulns = await res.json();

    const list = document.getElementById('sla-list');
    if (vulns.length === 0) {
      list.innerHTML = '<p class="text-green-600">No vulnerabilities approaching SLA deadline</p>';
      return;
    }

    list.innerHTML = vulns.map(v => `
      <div class="flex justify-between items-center bg-white rounded p-2">
        <div>
          <span class="px-2 py-1 rounded text-xs font-bold severity-${v.severity}">${v.severity.toUpperCase()}</span>
          <span class="ml-2 font-medium">${v.cve || 'No CVE'}</span>
          <span class="text-gray-500">on ${v.host}</span>
        </div>
        <div class="text-right">
          <span class="text-red-600 font-bold">${v.days_remaining} days left</span>
          ${v.jira_ticket_url ? `<a href="${v.jira_ticket_url}" target="_blank" class="ml-2 text-blue-600">${v.jira_ticket_id}</a>` : ''}
        </div>
      </div>
    `).join('');
  } catch (err) {
    console.error('Failed to load SLA warnings:', err);
  }
}

// Load vulnerabilities list
async function loadVulnerabilities() {
  try {
    const severity = document.getElementById('filter-severity').value;
    const status = document.getElementById('filter-status').value;
    const host = document.getElementById('filter-host').value;

    let url = '/api/vulnerabilities/?limit=50';
    if (severity) url += `&severity=${severity}`;
    if (status) url += `&status=${status}`;
    if (host) url += `&host=${encodeURIComponent(host)}`;

    const res = await fetch(url);
    const vulns = await res.json();

    const table = document.getElementById('vuln-table');
    if (vulns.length === 0) {
      table.innerHTML = '<p class="text-gray-500">No vulnerabilities found</p>';
      return;
    }

    table.innerHTML = `
      <table class="w-full text-sm">
        <thead class="bg-gray-50">
          <tr>
            <th class="px-4 py-2 text-left">Severity</th>
            <th class="px-4 py-2 text-left">CVE</th>
            <th class="px-4 py-2 text-left">Host</th>
            <th class="px-4 py-2 text-left">Title</th>
            <th class="px-4 py-2 text-left">Status</th>
            <th class="px-4 py-2 text-left">SLA</th>
            <th class="px-4 py-2 text-left">Jira</th>
          </tr>
        </thead>
        <tbody>
          ${vulns.map(v => `
            <tr class="border-t hover:bg-gray-50">
              <td class="px-4 py-2">
                <span class="px-2 py-1 rounded text-xs font-bold severity-${v.severity}">${v.severity.toUpperCase()}</span>
              </td>
              <td class="px-4 py-2 font-mono text-sm">${v.cve || '-'}</td>
              <td class="px-4 py-2">${v.host}</td>
              <td class="px-4 py-2 max-w-xs truncate" title="${v.title}">${v.title}</td>
              <td class="px-4 py-2">
                <span class="px-2 py-1 bg-gray-100 rounded text-xs">${v.status}</span>
              </td>
              <td class="px-4 py-2 ${v.days_remaining < 0 ? 'text-red-600 font-bold' : v.days_remaining < 7 ? 'text-amber-600' : ''}">
                ${v.days_remaining !== null ? v.days_remaining + 'd' : '-'}
              </td>
              <td class="px-4 py-2">
                ${v.jira_ticket_url ? `<a href="${v.jira_ticket_url}" target="_blank" class="text-blue-600 hover:underline">${v.jira_ticket_id}</a>` : '-'}
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  } catch (err) {
    console.error('Failed to load vulnerabilities:', err);
  }
}

// Load import history
async function loadImports() {
  try {
    const res = await fetch('/api/imports/');
    const imports = await res.json();

    const list = document.getElementById('imports-list');
    if (imports.length === 0) {
      list.innerHTML = '<p class="text-gray-500">No imports yet</p>';
      return;
    }

    list.innerHTML = `
      <table class="w-full text-sm">
        <thead class="bg-gray-50">
          <tr>
            <th class="px-4 py-2 text-left">Date</th>
            <th class="px-4 py-2 text-left">File</th>
            <th class="px-4 py-2 text-left">Scanner</th>
            <th class="px-4 py-2 text-left">New</th>
            <th class="px-4 py-2 text-left">Existing</th>
            <th class="px-4 py-2 text-left">Resolved</th>
          </tr>
        </thead>
        <tbody>
          ${imports.map(i => `
            <tr class="border-t">
              <td class="px-4 py-2">${new Date(i.imported_at).toLocaleString()}</td>
              <td class="px-4 py-2">${i.filename}</td>
              <td class="px-4 py-2 capitalize">${i.scanner}</td>
              <td class="px-4 py-2 text-green-600">+${i.new_count}</td>
              <td class="px-4 py-2">${i.existing_count}</td>
              <td class="px-4 py-2 text-blue-600">${i.resolved_count}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  } catch (err) {
    console.error('Failed to load imports:', err);
  }
}

// Load AI insights
async function loadInsights() {
  const content = document.getElementById('insights-content');
  content.innerHTML = '<p class="text-gray-500">Generating insights...</p>';

  try {
    const res = await fetch('/api/insights/');
    const insights = await res.json();

    if (insights.error) {
      content.innerHTML = `<p class="text-red-600">${insights.error}</p>`;
      return;
    }

    let html = '';

    if (insights.patterns && insights.patterns.length > 0) {
      html += `
        <div class="mb-6">
          <h3 class="font-bold text-lg mb-2">Patterns Detected</h3>
          ${insights.patterns.map(p => `
            <div class="bg-gray-50 rounded p-3 mb-2">
              <div class="font-medium">${p.type.replace(/_/g, ' ').toUpperCase()}</div>
              <p>${p.description}</p>
              <p class="text-sm text-gray-600">Recommendation: ${p.recommendation}</p>
            </div>
          `).join('')}
        </div>
      `;
    }

    if (insights.training_opportunities && insights.training_opportunities.length > 0) {
      html += `
        <div class="mb-6">
          <h3 class="font-bold text-lg mb-2">Training Opportunities</h3>
          ${insights.training_opportunities.map(t => `
            <div class="bg-blue-50 rounded p-3 mb-2">
              <div class="font-medium">${t.topic}</div>
              <p class="text-sm">${t.reason} (${t.affected_count} affected)</p>
            </div>
          `).join('')}
        </div>
      `;
    }

    if (insights.priority_actions && insights.priority_actions.length > 0) {
      html += `
        <div class="mb-6">
          <h3 class="font-bold text-lg mb-2">Priority Actions</h3>
          ${insights.priority_actions.map(a => `
            <div class="bg-green-50 rounded p-3 mb-2 flex justify-between">
              <span>${a.action}</span>
              <span class="text-sm text-gray-600">${a.impact} | Effort: ${a.effort}</span>
            </div>
          `).join('')}
        </div>
      `;
    }

    if (insights.raw_analysis) {
      html = `<pre class="bg-gray-50 p-4 rounded whitespace-pre-wrap">${insights.raw_analysis}</pre>`;
    }

    content.innerHTML = html || '<p class="text-gray-500">No insights available</p>';
  } catch (err) {
    content.innerHTML = `<p class="text-red-600">Failed to load insights: ${err.message}</p>`;
  }
}

// Tab switching
function showTab(tab) {
  // Hide all content
  document.querySelectorAll('[id^="content-"]').forEach(el => el.classList.add('hidden'));
  // Reset tab styles
  document.querySelectorAll('[id^="tab-"]').forEach(el => {
    el.classList.remove('border-b-2', 'border-blue-600', 'text-blue-600');
    el.classList.add('text-gray-500');
  });

  // Show selected content
  document.getElementById(`content-${tab}`).classList.remove('hidden');
  // Highlight selected tab
  const tabEl = document.getElementById(`tab-${tab}`);
  tabEl.classList.add('border-b-2', 'border-blue-600', 'text-blue-600');
  tabEl.classList.remove('text-gray-500');
}

// Import modal
function openImportModal() {
  document.getElementById('import-modal').classList.remove('hidden');
  document.getElementById('import-modal').classList.add('flex');
}

function closeImportModal() {
  document.getElementById('import-modal').classList.add('hidden');
  document.getElementById('import-modal').classList.remove('flex');
}

async function submitImport(event) {
  event.preventDefault();

  const form = event.target;
  const formData = new FormData(form);

  try {
    const res = await fetch('/api/imports/upload', {
      method: 'POST',
      body: formData
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Import failed');
    }

    const result = await res.json();
    alert(`Import complete!\nNew: ${result.new_count}\nExisting: ${result.existing_count}\nResolved: ${result.resolved_count}`);

    closeImportModal();
    form.reset();

    // Refresh data
    loadStats();
    loadApproachingSLA();
    loadVulnerabilities();
    loadImports();
  } catch (err) {
    alert('Import failed: ' + err.message);
  }
}
```

**Step 2: Commit**

```bash
git add app/static/app.js
git commit -m "feat: add dashboard JavaScript for data loading and interactions"
```

---

## Phase 6: Final Integration

### Task 15: Update main.py with all routers

**Files:**
- Modify: `app/main.py`

**Step 1: Final main.py**

```python
# app/main.py
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path

from app.database import engine, Base
from app.routers import imports, vulnerabilities, insights

# Create tables on startup
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Vulnerability Management", version="0.1.0")

# Include routers
app.include_router(imports.router)
app.include_router(vulnerabilities.router)
app.include_router(insights.router)

# Static files
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/")
async def root():
    index_path = static_dir / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return {"status": "ok", "message": "Vulnerability Management API"}


@app.get("/health")
async def health():
    return {"status": "healthy"}
```

**Step 2: Commit**

```bash
git add app/main.py
git commit -m "feat: integrate all routers and finalize main.py"
```

---

### Task 16: Create Dockerfile

**Files:**
- Create: `Dockerfile`

**Step 1: Create Dockerfile**

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app/ ./app/

# Create data directory
RUN mkdir -p data

# Expose port
EXPOSE 8000

# Run application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**Step 2: Create .dockerignore**

```
__pycache__
*.pyc
*.pyo
.env
.git
.gitignore
*.md
tests/
.worktrees/
data/*.db
```

**Step 3: Commit**

```bash
git add Dockerfile .dockerignore
git commit -m "chore: add Dockerfile for container deployment"
```

---

### Task 17: Run and verify

**Step 1: Install dependencies**

```bash
pip install -r requirements.txt
```

**Step 2: Create .env file**

```bash
cp .env.example .env
# Edit .env with your actual credentials
```

**Step 3: Run the application**

```bash
python -m uvicorn app.main:app --reload
```

**Step 4: Verify in browser**

Open http://localhost:8000 and verify:
- Dashboard loads with stats cards
- Import modal opens
- Tabs switch correctly
- API endpoints work (try http://localhost:8000/docs)

**Step 5: Final commit**

```bash
git add -A
git commit -m "chore: ready for testing"
```

---

## Summary

**Total Tasks:** 17
**Estimated Implementation Time:** 3-4 hours

**What's Built:**
- FastAPI backend with SQLite database
- XLS parser for Qualys and Tenable reports
- Jira integration for ticket creation
- Claude integration for remediation guidance
- Dashboard with stats, SLA warnings, and filtering
- AI insights engine
- Docker-ready for AKS deployment

**Next Steps After Implementation:**
1. Test with real Qualys/Tenable reports
2. Configure Jira project and API token
3. Add Claude API key
4. Deploy to AKS when validated
