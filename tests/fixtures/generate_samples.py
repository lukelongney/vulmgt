"""Generate sample Qualys and Tenable XLSX files for testing."""
import openpyxl
from pathlib import Path

# Sample vulnerability data
SAMPLE_VULNS = [
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
]


def create_qualys_sample(output_path: Path):
    """Create a sample Qualys report."""
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Vulnerabilities"

    # Headers matching Qualys format
    headers = [
        "IP Address", "DNS Name", "QID", "Severity", "CVSS Base Score",
        "QDS", "Title", "Threat", "Solution", "Port", "Protocol",
        "Service", "Operating System", "CVE ID"
    ]
    ws.append(headers)

    # Add data
    for vuln in SAMPLE_VULNS:
        ws.append([
            vuln["host"],
            f"{vuln['host'].replace('.', '-')}.internal.local",
            vuln["qid"],
            vuln["severity_qualys"],
            vuln["cvss"],
            vuln["cvss"] * 10,  # QDS score
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
    print(f"Created: {output_path}")


def create_tenable_sample(output_path: Path):
    """Create a sample Tenable report."""
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Vulnerabilities"

    # Headers matching Tenable format
    headers = [
        "Host", "DNS Name", "Plugin ID", "Risk", "CVSS v3.0 Base Score",
        "VPR", "Name", "Description", "Solution", "Port", "Protocol",
        "Plugin Family", "CPE", "CVE"
    ]
    ws.append(headers)

    # Add data
    for vuln in SAMPLE_VULNS:
        ws.append([
            vuln["host"],
            f"{vuln['host'].replace('.', '-')}.internal.local",
            vuln["plugin_id"],
            vuln["severity_tenable"],
            vuln["cvss"],
            vuln["cvss"],  # VPR score
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
    print(f"Created: {output_path}")


if __name__ == "__main__":
    fixtures_dir = Path(__file__).parent
    fixtures_dir.mkdir(exist_ok=True)

    create_qualys_sample(fixtures_dir / "sample_qualys.xlsx")
    create_tenable_sample(fixtures_dir / "sample_tenable.xlsx")
    print("Done! Sample files created.")
