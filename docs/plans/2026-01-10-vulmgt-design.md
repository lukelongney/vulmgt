# Vulnerability Management App Design

## Overview

A Python-based vulnerability management application that ingests weekly XLS reports from Qualys and Tenable, tracks vulnerabilities, automatically creates Jira tickets with AI-generated remediation guidance, and provides a dashboard with escalation monitoring and AI-powered insights.

## Goals

- Ingest weekly vulnerability reports from Qualys and Tenable (XLS format)
- Identify new, existing, and resolved vulnerabilities
- Automatically create Jira tickets for new vulnerabilities with Claude-generated remediation guidance
- Track Jira ticket status with daily sync
- Dashboard showing vulnerability status, SLA tracking, and escalation warnings
- AI insights to identify patterns, training opportunities, and systemic issues
- Start as desktop app (localhost), migrate to Docker/AKS

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Web Browser                            │
│                  (localhost:8000)                           │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                 FastAPI Backend                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ Import      │  │ Dashboard   │  │ Escalation          │  │
│  │ Service     │  │ API         │  │ Monitor             │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ Jira        │  │ Claude      │  │ Report              │  │
│  │ Client      │  │ Client      │  │ Generator           │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                   SQLite Database                           │
│         (vulnerabilities, imports, config)                  │
└─────────────────────────────────────────────────────────────┘
```

## Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Python 3.11+ / FastAPI |
| Database | SQLite (PostgreSQL for AKS) |
| Frontend | HTML + Vanilla JS + Tailwind CSS |
| Excel Parsing | openpyxl |
| Jira Integration | jira-python |
| AI | Anthropic Claude API |

## Data Model

### vulnerabilities

| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Primary key |
| host | string | Hostname or IP address |
| cve | string | CVE ID (nullable for non-CVE findings) |
| scanner | enum | qualys \| tenable |
| scanner_id | string | QID (Qualys) or Plugin ID (Tenable) |
| severity | enum | critical \| high \| medium \| low \| info |
| severity_score | float | CVSS base score |
| vpr_score | float | Tenable VPR or Qualys QDS (nullable) |
| title | string | Vulnerability name |
| description | text | Detailed description |
| solution | text | Scanner-provided remediation |
| remediation_guidance | text | Claude-generated guidance |
| port | integer | Affected port (nullable) |
| protocol | string | Network protocol (nullable) |
| service | string | Affected service (nullable) |
| os | string | Host operating system |
| first_seen | datetime | Date first imported |
| last_seen | datetime | Date last seen in report |
| status | enum | open \| in_progress \| resolved \| accepted_risk |
| sla_deadline | datetime | Calculated: first_seen + SLA days |
| jira_ticket_id | string | e.g., "VULN-123" |
| jira_ticket_url | string | Full Jira ticket URL |
| jira_status | string | Synced from Jira |
| jira_assignee | string | Synced from Jira |
| resolved_date | datetime | When resolved (nullable) |

**Unique constraint:** `(host, cve)` - one entry per host+CVE combination

### imports

| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Primary key |
| filename | string | Original filename |
| scanner | enum | qualys \| tenable |
| imported_at | datetime | When imported |
| new_count | integer | New vulns found |
| existing_count | integer | Already tracked |
| resolved_count | integer | No longer in report |

### sla_config

| Field | Type | Description |
|-------|------|-------------|
| severity | enum | critical \| high \| medium \| low |
| days | integer | SLA deadline in days |

**Default SLAs:**
- Critical: 14 days
- High: 14 days
- Medium: 90 days
- Low: 180 days

## Scanner Field Mappings

### Qualys XLS Columns

| App Field | Qualys Column |
|-----------|---------------|
| host | IP Address or Hostname |
| cve | CVE ID |
| scanner_id | QID |
| severity | Severity (map 1-5 to critical/high/medium/low/info) |
| severity_score | CVSS Base Score |
| vpr_score | QDS |
| title | Title |
| description | Threat + Impact |
| solution | Solution |
| port | Port |
| protocol | Protocol |
| service | Service |
| os | Operating System |
| first_seen | First Detected |
| last_seen | Last Detected |

**Qualys Severity Mapping:**
- 5 = critical
- 4 = high
- 3 = medium
- 2 = low
- 1 = info

### Tenable XLS Columns

| App Field | Tenable Column |
|-----------|----------------|
| host | Host or DNS Name |
| cve | CVE |
| scanner_id | Plugin ID |
| severity | Risk (already Critical/High/Medium/Low/Info) |
| severity_score | CVSS v3.0 Base Score (fallback to v2.0) |
| vpr_score | VPR |
| title | Name (Plugin Name) |
| description | Description |
| solution | Solution |
| port | Port |
| protocol | Protocol |
| service | (derived from Plugin Family) |
| os | (derived from CPE) |
| first_seen | First Discovered |
| last_seen | Last Seen |

## Import Workflow

```
1. UPLOAD
   └── User uploads XLS file, selects scanner type (Qualys/Tenable)

2. PARSE
   └── Extract rows using configured column mappings
   └── Normalize to common schema
   └── Map severity levels to standard enum

3. DIFF
   └── Compare against existing vulnerabilities (by host+CVE)
   └── Categorize: NEW | EXISTING | RESOLVED

4. FOR EACH NEW VULNERABILITY:
   ├── Generate remediation guidance via Claude API
   ├── Calculate SLA deadline (first_seen + severity SLA)
   ├── Create Jira ticket with details + guidance
   └── Store in database with Jira link

5. FOR EACH EXISTING:
   └── Update last_seen date

6. FOR EACH RESOLVED (missing from report):
   └── Mark status = resolved, set resolved_date
   └── Auto-close Jira ticket

7. SUMMARY
   └── Display import results: X new, Y existing, Z resolved
```

## Jira Integration

### Configuration

- Instance: Jira Cloud (https://lukelongney.atlassian.net)
- Project: Single project for all vulnerabilities
- Sync: Daily poll for inbound status updates

### Ticket Format

```
Title: [{SEVERITY}] {CVE} on {HOST}

Summary: {TITLE}

Severity: {SEVERITY}
Host: {HOST}
CVE: {CVE}
Scanner: {SCANNER}
Scanner ID: {SCANNER_ID}
CVSS Score: {SEVERITY_SCORE}
First Detected: {FIRST_SEEN}
SLA Deadline: {SLA_DEADLINE}

── Scanner Description ──
{DESCRIPTION}

── Scanner Solution ──
{SOLUTION}

── AI Remediation Guidance ──
{REMEDIATION_GUIDANCE}

Labels: vulnerability, {severity}, {cve}
Due Date: {SLA_DEADLINE}
```

### Sync Behavior

- **Outbound:** Create ticket on new vuln, close ticket on resolved
- **Inbound:** Daily poll to sync status, assignee back to app

## Dashboard

### Main View

```
┌─────────────────────────────────────────────────────────────┐
│  VULNERABILITY DASHBOARD                        [Import XLS]│
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │ Critical │ │   High   │ │  Medium  │ │   Low    │       │
│  │    12    │ │    34    │ │    89    │ │    45    │       │
│  │ ▲3 new   │ │ ▼2 fixed │ │ ▲5 new   │ │ =        │       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
│                                                             │
│  ⚠️  APPROACHING SLA (7 items)                              │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ CRIT │ CVE-2024-1234 │ webserver01 │ 2 days left │VULN-45│
│  │ HIGH │ CVE-2024-5678 │ db-prod-02  │ 3 days left │VULN-52│
│  └─────────────────────────────────────────────────────────┘│
│                                                             │
│  RECENT IMPORTS                    ALL VULNERABILITIES [→]  │
│  ┌─────────────────────────────┐  ┌────────────────────────┐│
│  │ Jan 10 - qualys.xls         │  │ Filter: [Severity ▼]  ││
│  │ +12 new, 5 resolved         │  │ [Host] [Status] [Age] ││
│  └─────────────────────────────┘  └────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

### Features

- At-a-glance counts by severity with trend indicators
- SLA warnings prominently displayed, sorted by urgency
- Escalation threshold: 75% of SLA elapsed
- Click-through to Jira tickets
- Filterable table of all vulnerabilities
- Export to CSV/PDF for reporting

## AI Insights Engine

### Purpose

Analyze the entire vulnerability estate to identify patterns, recurring issues, and opportunities for systemic improvement.

### Insights View

```
┌─────────────────────────────────────────────────────────────┐
│  🔍 AI INSIGHTS                            [Refresh Analysis]│
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  PATTERNS DETECTED                                          │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ 🔁 RECURRING ISSUE                                      ││
│  │ "Outdated OpenSSL versions across 23 Linux hosts.       ││
│  │  Suggests patching process gap for third-party libs."   ││
│  │  Affected: webserver01, webserver02, api-prod-*, ...    ││
│  │  [View All] [Draft Comms]                               ││
│  ├─────────────────────────────────────────────────────────┤│
│  │ 📚 TRAINING OPPORTUNITY                                 ││
│  │ "15 SQL injection findings in internal apps. Consider   ││
│  │  secure coding training for development team."          ││
│  │  [View All] [Draft Comms]                               ││
│  ├─────────────────────────────────────────────────────────┤│
│  │ ⚙️ CONFIGURATION DRIFT                                  ││
│  │ "SMBv1 enabled on 8 Windows servers. Group Policy       ││
│  │  may not be applying consistently."                     ││
│  │  [View All] [Draft Comms]                               ││
│  └─────────────────────────────────────────────────────────┘│
│                                                             │
│  SUGGESTED ACTIONS                                          │
│  • Prioritize OpenSSL patching - single fix resolves 23 vulns│
│  • Schedule AppSec training - recurring injection patterns  │
│  • Review GPO inheritance for server OUs                    │
│                                                             │
│  [Generate Executive Summary]  [Generate Team Report]       │
└─────────────────────────────────────────────────────────────┘
```

### Analysis Types

- **Recurring CVEs:** Same vulnerability across multiple hosts
- **Vulnerability Classes:** Patterns like injection, misconfiguration, outdated software
- **Team/System Patterns:** Trends by host group or environment
- **Root Cause Indicators:** Patching gaps, config drift, training needs

### Generated Communications

- **Draft Comms:** Ready-to-send email/message for specific issues
- **Executive Summary:** High-level report for leadership
- **Team Report:** Technical details for remediation teams

## Settings & Configuration

```
┌─────────────────────────────────────────────────────────────┐
│  SETTINGS                                                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  JIRA CONNECTION                                            │
│  Instance URL: https://lukelongney.atlassian.net            │
│  Project Key: [configurable]                                │
│  API Token: [encrypted]                                     │
│  Email: [user email]                                        │
│                                                             │
│  CLAUDE API                                                 │
│  API Key: [encrypted]                                       │
│                                                             │
│  SLA DEADLINES (days)                                       │
│  Critical: 14 | High: 14 | Medium: 90 | Low: 180            │
│                                                             │
│  ESCALATION                                                 │
│  Warning threshold: 75%                                     │
│                                                             │
│  COLUMN MAPPING                                             │
│  Qualys and Tenable field mappings (editable)               │
└─────────────────────────────────────────────────────────────┘
```

## Project Structure

```
vulmgt/
├── app/
│   ├── main.py              # FastAPI entry point
│   ├── config.py            # Settings management
│   ├── database.py          # SQLite/SQLAlchemy models
│   ├── routers/
│   │   ├── imports.py       # Upload & parse XLS
│   │   ├── vulnerabilities.py
│   │   ├── dashboard.py
│   │   ├── insights.py      # AI analysis endpoints
│   │   └── settings.py
│   ├── services/
│   │   ├── parser.py        # Qualys/Tenable XLS parsing
│   │   ├── jira_client.py   # Jira API wrapper
│   │   ├── claude_client.py # Remediation & insights
│   │   └── sla.py           # Deadline calculations
│   └── static/
│       ├── index.html       # Dashboard SPA
│       ├── app.js
│       └── styles.css
├── data/
│   └── vulmgt.db            # SQLite database
├── Dockerfile
├── requirements.txt
└── README.md
```

## Running the App

### Local Development

```bash
cd vulmgt
pip install -r requirements.txt
python -m uvicorn app.main:app --reload
# Open http://localhost:8000
```

### Docker (AKS Migration)

```bash
docker build -t vulmgt .
docker run -p 8000:8000 vulmgt
```

## Future Considerations

- PostgreSQL for AKS deployment
- Multi-user authentication
- Role-based access control
- Scheduled report imports (watch folder or email integration)
- Slack/Teams notifications for escalations
- Additional scanner support (Rapid7, etc.)
