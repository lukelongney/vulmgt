"""Generate sample Qualys and Tenable XLSX files for testing.

Creates 3 weeks of data for each scanner to simulate vulnerability lifecycle:
- Week 1: Initial scan with 10 vulnerabilities (baseline)
- Week 2: +10% new issues (1 new = 11 total)
- Week 3: -20% resolved (2 closed) + 5% new (1 new) = 10 total
"""
import openpyxl
from pathlib import Path

# Base vulnerability data - 10 vulnerabilities for clean percentage math
BASE_VULNS = [
    {
        "host": "192.168.1.10",
        "cve": "CVE-2024-1234",
        "title": "Apache HTTP Server Remote Code Execution",
        "description": "A remote code execution vulnerability exists in Apache HTTP Server versions prior to 2.4.52.",
        "solution": "Update Apache HTTP Server to version 2.4.52 or later.",
        "severity_qualys": "5",
        "severity_tenable": "Critical",
        "cvss": 9.8,
        "port": 443,
        "protocol": "TCP",
        "service": "HTTPS",
        "os": "CentOS 7",
        "qid": "12345",
        "plugin_id": "98765",
    },
    {
        "host": "192.168.1.10",
        "cve": "CVE-2024-5678",
        "title": "OpenSSL Buffer Overflow",
        "description": "A buffer overflow vulnerability in OpenSSL could allow remote attackers to execute arbitrary code.",
        "solution": "Update OpenSSL to version 3.0.8 or later.",
        "severity_qualys": "5",
        "severity_tenable": "Critical",
        "cvss": 9.1,
        "port": 443,
        "protocol": "TCP",
        "service": "HTTPS",
        "os": "CentOS 7",
        "qid": "12346",
        "plugin_id": "98766",
    },
    {
        "host": "192.168.1.20",
        "cve": "CVE-2024-2345",
        "title": "SQL Server Elevation of Privilege",
        "description": "An elevation of privilege vulnerability exists in Microsoft SQL Server.",
        "solution": "Apply the latest SQL Server security update.",
        "severity_qualys": "4",
        "severity_tenable": "High",
        "cvss": 8.1,
        "port": 1433,
        "protocol": "TCP",
        "service": "MSSQL",
        "os": "Windows Server 2019",
        "qid": "23456",
        "plugin_id": "87654",
    },
    {
        "host": "192.168.1.30",
        "cve": "CVE-2024-3456",
        "title": "Nginx Information Disclosure",
        "description": "An information disclosure vulnerability in Nginx allows remote attackers to read sensitive data.",
        "solution": "Update Nginx to version 1.24.0 or later.",
        "severity_qualys": "3",
        "severity_tenable": "Medium",
        "cvss": 5.3,
        "port": 80,
        "protocol": "TCP",
        "service": "HTTP",
        "os": "Ubuntu 22.04",
        "qid": "34567",
        "plugin_id": "76543",
    },
    {
        "host": "192.168.1.40",
        "cve": "CVE-2024-4567",
        "title": "SSH Weak Cipher Support",
        "description": "The SSH server supports weak encryption ciphers that could be exploited.",
        "solution": "Disable weak ciphers in SSH configuration.",
        "severity_qualys": "2",
        "severity_tenable": "Low",
        "cvss": 3.7,
        "port": 22,
        "protocol": "TCP",
        "service": "SSH",
        "os": "Debian 11",
        "qid": "45678",
        "plugin_id": "65432",
    },
    {
        "host": "192.168.1.50",
        "cve": "CVE-2024-6789",
        "title": "PostgreSQL Authentication Bypass",
        "description": "An authentication bypass vulnerability in PostgreSQL allows unauthorized database access.",
        "solution": "Update PostgreSQL and review pg_hba.conf settings.",
        "severity_qualys": "5",
        "severity_tenable": "Critical",
        "cvss": 9.8,
        "port": 5432,
        "protocol": "TCP",
        "service": "PostgreSQL",
        "os": "Ubuntu 20.04",
        "qid": "56789",
        "plugin_id": "54321",
    },
    {
        "host": "192.168.1.20",
        "cve": "CVE-2024-7890",
        "title": "Windows RDP BlueKeep Variant",
        "description": "A remote code execution vulnerability in Remote Desktop Services.",
        "solution": "Apply Windows security updates and enable NLA.",
        "severity_qualys": "5",
        "severity_tenable": "Critical",
        "cvss": 9.8,
        "port": 3389,
        "protocol": "TCP",
        "service": "RDP",
        "os": "Windows Server 2019",
        "qid": "67890",
        "plugin_id": "43210",
    },
    {
        "host": "192.168.1.60",
        "cve": "CVE-2024-8901",
        "title": "Docker Container Escape",
        "description": "A container escape vulnerability allows attackers to break out of Docker containers.",
        "solution": "Update Docker Engine to the latest version.",
        "severity_qualys": "4",
        "severity_tenable": "High",
        "cvss": 8.8,
        "port": 2375,
        "protocol": "TCP",
        "service": "Docker",
        "os": "Ubuntu 22.04",
        "qid": "78901",
        "plugin_id": "32109",
    },
    {
        "host": "192.168.1.70",
        "cve": "CVE-2024-9012",
        "title": "Redis Unauthorized Access",
        "description": "Redis server allows unauthorized access due to missing authentication.",
        "solution": "Enable AUTH in Redis configuration.",
        "severity_qualys": "4",
        "severity_tenable": "High",
        "cvss": 7.5,
        "port": 6379,
        "protocol": "TCP",
        "service": "Redis",
        "os": "Ubuntu 22.04",
        "qid": "89012",
        "plugin_id": "21098",
    },
    {
        "host": "192.168.1.80",
        "cve": "CVE-2024-0123",
        "title": "Kubernetes API Server RBAC Bypass",
        "description": "A bypass vulnerability in Kubernetes RBAC allows privilege escalation.",
        "solution": "Update Kubernetes to the latest patched version.",
        "severity_qualys": "5",
        "severity_tenable": "Critical",
        "cvss": 9.1,
        "port": 6443,
        "protocol": "TCP",
        "service": "Kubernetes",
        "os": "Ubuntu 22.04",
        "qid": "90123",
        "plugin_id": "10987",
    },
]

# Week 2: +10% new issues (1 new vulnerability)
WEEK2_NEW = [
    {
        "host": "192.168.1.90",
        "cve": "CVE-2024-1111",
        "title": "MongoDB NoSQL Injection",
        "description": "A NoSQL injection vulnerability in MongoDB allows data exfiltration.",
        "solution": "Update MongoDB and sanitize user inputs.",
        "severity_qualys": "4",
        "severity_tenable": "High",
        "cvss": 8.2,
        "port": 27017,
        "protocol": "TCP",
        "service": "MongoDB",
        "os": "Ubuntu 22.04",
        "qid": "91111",
        "plugin_id": "11111",
    },
]

# Week 3: +5% new issues (1 new vulnerability based on week 2 total of 11)
WEEK3_NEW = [
    {
        "host": "192.168.1.100",
        "cve": "CVE-2024-2222",
        "title": "Elasticsearch Remote Code Execution",
        "description": "A scripting vulnerability in Elasticsearch allows remote code execution.",
        "solution": "Disable dynamic scripting or update Elasticsearch.",
        "severity_qualys": "5",
        "severity_tenable": "Critical",
        "cvss": 9.8,
        "port": 9200,
        "protocol": "TCP",
        "service": "Elasticsearch",
        "os": "CentOS 8",
        "qid": "92222",
        "plugin_id": "22222",
    },
]

# Week 3: 20% resolved (2 vulnerabilities closed from week 2's 11 total)
# Resolving: Apache RCE and OpenSSL Buffer Overflow (the two criticals on 192.168.1.10)
RESOLVED_WEEK3 = ["CVE-2024-1234", "CVE-2024-5678"]


def get_week_vulns(week: int) -> list:
    """Get vulnerabilities for a specific week."""
    if week == 1:
        # Week 1: 10 baseline vulnerabilities
        return BASE_VULNS.copy()
    elif week == 2:
        # Week 2: All baseline + 10% new (1 new) = 11 total
        vulns = BASE_VULNS.copy()
        vulns.extend(WEEK2_NEW)
        return vulns
    elif week == 3:
        # Week 3: Week 2 - 20% resolved (2) + 5% new (1) = 10 total
        vulns = [v for v in BASE_VULNS if v["cve"] not in RESOLVED_WEEK3]
        vulns.extend(WEEK2_NEW)  # MongoDB from week 2 still present
        vulns.extend(WEEK3_NEW)  # New Elasticsearch vuln
        return vulns
    return []


def create_qualys_report(vulns: list, output_path: Path):
    """Create a Qualys format report."""
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Vulnerabilities"

    headers = [
        "IP Address", "DNS Name", "QID", "Severity", "CVSS Base Score",
        "QDS", "Title", "Threat", "Solution", "Port", "Protocol",
        "Service", "Operating System", "CVE ID"
    ]
    ws.append(headers)

    for vuln in vulns:
        ws.append([
            vuln["host"],
            f"{vuln['host'].replace('.', '-')}.internal.local",
            vuln["qid"],
            vuln["severity_qualys"],
            vuln["cvss"],
            vuln["cvss"] * 10,
            vuln["title"],
            vuln["description"],
            vuln["solution"],
            vuln["port"],
            vuln["protocol"],
            vuln["service"],
            vuln["os"],
            vuln["cve"],
        ])

    wb.save(output_path)
    print(f"Created: {output_path} ({len(vulns)} vulnerabilities)")


def create_tenable_report(vulns: list, output_path: Path):
    """Create a Tenable format report."""
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Vulnerabilities"

    headers = [
        "Host", "DNS Name", "Plugin ID", "Risk", "CVSS v3.0 Base Score",
        "VPR", "Name", "Description", "Solution", "Port", "Protocol",
        "Plugin Family", "CPE", "CVE"
    ]
    ws.append(headers)

    for vuln in vulns:
        ws.append([
            vuln["host"],
            f"{vuln['host'].replace('.', '-')}.internal.local",
            vuln["plugin_id"],
            vuln["severity_tenable"],
            vuln["cvss"],
            vuln["cvss"],
            vuln["title"],
            vuln["description"],
            vuln["solution"],
            vuln["port"],
            vuln["protocol"],
            vuln["service"],
            f"cpe:/o:{vuln['os'].lower().replace(' ', '_')}",
            vuln["cve"],
        ])

    wb.save(output_path)
    print(f"Created: {output_path} ({len(vulns)} vulnerabilities)")


if __name__ == "__main__":
    fixtures_dir = Path(__file__).parent
    fixtures_dir.mkdir(exist_ok=True)

    print("Generating sample vulnerability reports...\n")

    for week in [1, 2, 3]:
        vulns = get_week_vulns(week)
        create_qualys_report(vulns, fixtures_dir / f"sample_qualys_week{week}.xlsx")
        create_tenable_report(vulns, fixtures_dir / f"sample_tenable_week{week}.xlsx")

    print("\nSummary:")
    print("- Week 1: 10 baseline vulnerabilities")
    print("- Week 2: +10% new (1 MongoDB) = 11 total")
    print("- Week 3: -20% resolved (2 Apache/OpenSSL) +5% new (1 Elasticsearch) = 10 total")
    print("\nDone!")
