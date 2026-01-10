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
