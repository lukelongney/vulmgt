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
