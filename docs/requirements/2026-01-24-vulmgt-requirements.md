# Vulnerability Management (vulmgt) Application Requirements

## Overview

The Vulnerability Management (vulmgt) application is an intelligent vulnerability tracking and remediation system that automates the workflow from scanner report ingestion through to remediation completion. It integrates vulnerability data from security scanners, enriches findings with AI-generated remediation guidance, automates ticket creation and tracking via Jira, and enforces SLA compliance with escalation visibility.

This document serves as:
- **Baseline documentation** - Capturing current functionality
- **Gap analysis** - Identifying enhancements for future iterations
- **Compliance/audit reference** - Formal process documentation

## Stakeholders

| Stakeholder | Role | Primary Needs |
|-------------|------|---------------|
| Security Team | Analysts who triage and remediate vulnerabilities | Actionable vulnerability data, remediation guidance, SLA visibility, risk acceptance workflow |
| Compliance/Audit | Internal or external auditors reviewing security processes | Import history, risk acceptance records, data retention, formal process documentation |

## Success Metrics

- 100% of imported vulnerabilities tracked through to resolution or risk acceptance
- Zero vulnerabilities breaching SLA without documented risk acceptance
- Full audit trail of imports and risk acceptance decisions retained for 2-3 years

---

## Data Entities and Scanner Integration

### Vulnerability Data Model

| Field | Description |
|-------|-------------|
| CVE ID | Common Vulnerabilities and Exposures identifier |
| Host | Affected system hostname/IP |
| Severity | Critical, High, Medium, Low, Info |
| CVSS Score | Numeric vulnerability severity score |
| Title/Description | Vulnerability details from scanner |
| Affected Service/Port | Service and port information |
| First Seen | Date vulnerability first detected |
| Last Seen | Date vulnerability last appeared in scan |
| Status | Open, In Progress, Resolved, Risk Accepted |
| SLA Deadline | Calculated remediation due date |
| Jira Ticket Key | Linked Jira issue reference |
| EGRC Reference | Risk acceptance governance reference |
| Risk Acceptance Expiry | Date when accepted risk must be reviewed |
| Remediation Guidance | AI-generated fix instructions |

### Scanner Support

**Current:**
- Qualys (XLS report format)
- Tenable (XLS report format)

**Future Requirement:**
- Code scan results (SAST/DAST tools) for application vulnerability tracking
- Architecture should support adding new scanner types without major refactoring

### Deduplication

Vulnerabilities are deduplicated by `(host, CVE)` pairs. Existing vulnerabilities are updated with new last_seen dates; missing vulnerabilities are marked as resolved.

---

## Jira Integration and SLA Tracking

### Jira Integration

**Current Functionality:**
- Automatic ticket creation for new vulnerabilities
- Bidirectional status sync (Jira status reflected in app)
- Tickets include severity-mapped priority, scanner data, and AI remediation guidance
- Auto-closure of tickets when vulnerabilities are resolved in subsequent scans

**Ticket Creation Details:**

| Vulnerability Severity | Jira Priority |
|------------------------|---------------|
| Critical | Highest |
| High | High |
| Medium | Medium |
| Low | Low |

### SLA Tracking

**Current SLA Periods:**

| Severity | Remediation Deadline |
|----------|---------------------|
| Critical | 14 days |
| High | 14 days |
| Medium | 90 days |
| Low | 180 days |

**SLA Features:**
- Deadline calculated from first_seen date
- Escalation threshold at 75% of SLA elapsed (configurable)
- Dashboard highlights approaching and overdue vulnerabilities
- SLA deadline set as Jira ticket due date

**Gap - Admin Configuration:**
- SLA periods should be configurable via Admin UI (not hardcoded)
- Escalation threshold percentage should be configurable

---

## AI Features and Risk Acceptance

### AI-Powered Remediation Guidance

**Status:** Valuable but optional - system must function without AI availability

**Functionality:**
- Generates actionable remediation steps for each new vulnerability
- Provides OS-specific commands and verification procedures
- Includes precautions and backup recommendations
- Approximately 300 words of actionable guidance per vulnerability

**Graceful Degradation:**
- If AI service unavailable, vulnerabilities are still imported and tracked
- Remediation guidance field left empty; manual guidance can be added later

### AI-Powered Insights

**Functionality:**
- Pattern analysis across all vulnerabilities
- Identifies recurring CVEs across multiple hosts
- Detects common vulnerability types (injection, misconfiguration, outdated software)
- Suggests training opportunities based on vulnerability patterns
- Highlights high-impact fixes (one action resolves many vulnerabilities)

### Risk Acceptance Workflow

**Status:** Actively used - critical to governance process

**Functionality:**
- Mark vulnerabilities as "Accepted Risk"
- Required fields:
  - EGRC reference number (governance tracking)
  - Risk acceptance expiry date
  - Business justification
- Acceptance date automatically recorded
- Risk-accepted vulnerabilities tracked separately on dashboard
- Expiring risk acceptances should be visible for review

---

## Authentication, Authorization, and Admin UI

### Authentication

**Current:** SSO via Azure AD integration

**Requirements:**
- All users authenticate via Azure AD
- No local user accounts
- Session management handled by Azure AD tokens

### Authorization (RBAC)

**Current Roles:**

| Role | Capabilities |
|------|-------------|
| Viewer | Read-only access to dashboard, vulnerabilities, insights, and import history |
| Editor | All Viewer capabilities plus: import reports, update vulnerability status, accept risk, trigger Jira sync |

**Role Assignment:**
- Roles determined by Azure AD group membership
- AD groups mapped to application roles (e.g., "VulMgt-Editors" -> Editor role)

**Future Requirement:**
- Architecture should support adding new roles without major refactoring
- Potential future roles: Admin, Auditor, Team-scoped access

### Admin UI

**Gap - New Requirement:**

An Admin UI screen for authorized administrators to manage:

| Setting | Description |
|---------|-------------|
| SLA Periods | Configure days per severity level (Critical, High, Medium, Low) |
| Escalation Threshold | Percentage of SLA elapsed before escalation warning |
| Role Permissions | Define what capabilities each role has in the application |
| Role-to-AD-Group Mapping | Map Azure AD groups to application roles |

**Access:** Admin UI restricted to users with Admin role (future role to be added)

---

## Non-Functional Requirements

### Availability

- **Level:** Best effort
- Single instance deployment acceptable
- Occasional downtime for maintenance permitted
- No redundancy or failover required

### Performance

- Daily imports must complete before start of business
- Dashboard should load within reasonable time for typical data volumes
- No specific throughput requirements defined

### Data Retention

- **Period:** 2-3 years
- All vulnerability data retained for historical trending and compliance
- Import history preserved for audit trail
- Risk acceptance records retained with vulnerability data
- Archive or purge strategy to be defined for data beyond retention period

### Audit Trail

- **Current:** Import history tracking (what was imported, when, by whom)
- Records maintained: filename, scanner type, import date, counts (new/existing/resolved)
- Risk acceptance decisions logged with date, user, EGRC reference

### Security

- All access via SSO/Azure AD (no anonymous access)
- RBAC enforced on all write operations
- Sensitive data (Jira credentials, API keys) stored in Azure Key Vault
- HTTPS enforced for all traffic

### Deployment

- **Platform:** Azure subscription
- **Compute:** AKS (Azure Kubernetes Service) container
- **Database:** PostgreSQL (production)
- **Development:** SQLite acceptable for local development
- Containerized via Docker
- Secrets managed in Azure Key Vault

---

## MoSCoW Prioritization

### Must Have

#### Epic: Vulnerability Import
**Story:** As a security analyst, I want to upload vulnerability scan reports, so that vulnerabilities are automatically tracked in the system.
- **Acceptance Criteria:**
  - [ ] Upload Qualys XLS reports and extract vulnerability data
  - [ ] Upload Tenable XLS reports and extract vulnerability data
  - [ ] Deduplicate by (host, CVE) - update existing, create new
  - [ ] Mark missing vulnerabilities as resolved
  - [ ] Record import history with counts

#### Epic: Jira Integration
**Story:** As a security analyst, I want vulnerabilities automatically created as Jira tickets, so that remediation is tracked in our standard workflow.
- **Acceptance Criteria:**
  - [ ] New vulnerabilities create Jira tickets with severity-mapped priority
  - [ ] Ticket includes scanner data and remediation guidance
  - [ ] SLA deadline set as ticket due date
  - [ ] Bidirectional sync updates vulnerability status from Jira
  - [ ] Resolved vulnerabilities auto-close linked tickets

#### Epic: SLA Tracking
**Story:** As a security analyst, I want to see SLA status for all vulnerabilities, so that I can prioritize remediation and avoid breaches.
- **Acceptance Criteria:**
  - [ ] SLA deadline calculated from first_seen + severity period
  - [ ] Dashboard shows approaching and overdue vulnerabilities
  - [ ] Escalation warning at 75% of SLA elapsed

#### Epic: Risk Acceptance
**Story:** As a security analyst, I want to mark vulnerabilities as accepted risk with governance tracking, so that business-justified exceptions are documented.
- **Acceptance Criteria:**
  - [ ] Mark vulnerability as Risk Accepted
  - [ ] Capture EGRC reference, expiry date, and justification
  - [ ] Risk-accepted items tracked separately on dashboard
  - [ ] Expiring acceptances visible for review

#### Epic: Authentication
**Story:** As a user, I want to log in via Azure AD, so that access is controlled by corporate identity.
- **Acceptance Criteria:**
  - [ ] SSO via Azure AD
  - [ ] No local user accounts
  - [ ] Role determined by AD group membership

---

### Should Have

#### Epic: AI Remediation Guidance
**Story:** As a security analyst, I want AI-generated remediation steps for each vulnerability, so that I have actionable fix instructions without manual research.
- **Acceptance Criteria:**
  - [ ] Remediation guidance generated for new vulnerabilities
  - [ ] Guidance includes OS-specific commands and verification steps
  - [ ] System functions normally if AI service unavailable
  - [ ] Manual guidance can be added/edited if AI unavailable

#### Epic: AI Insights
**Story:** As a security analyst, I want AI-powered pattern analysis, so that I can identify systemic security issues and prioritize high-impact fixes.
- **Acceptance Criteria:**
  - [ ] Identify recurring CVEs across multiple hosts
  - [ ] Detect common vulnerability types
  - [ ] Suggest training opportunities
  - [ ] Highlight fixes that resolve multiple vulnerabilities

#### Epic: Admin UI - SLA Configuration
**Story:** As an administrator, I want to configure SLA periods via the UI, so that I can adjust remediation deadlines without code changes.
- **Acceptance Criteria:**
  - [ ] Configure SLA days per severity (Critical, High, Medium, Low)
  - [ ] Configure escalation threshold percentage
  - [ ] Changes take effect immediately
  - [ ] Admin role required for access

#### Epic: Admin UI - RBAC Management
**Story:** As an administrator, I want to manage role permissions via the UI, so that I can control access without developer assistance.
- **Acceptance Criteria:**
  - [ ] Define permissions per role (Viewer, Editor, Admin)
  - [ ] Map Azure AD groups to application roles
  - [ ] Add new roles without code deployment
  - [ ] Audit log of permission changes

---

### Could Have

#### Epic: Code Scan Integration
**Story:** As a security analyst, I want to import code scan results (SAST/DAST), so that application vulnerabilities are tracked alongside infrastructure vulnerabilities.
- **Acceptance Criteria:**
  - [ ] Support at least one SAST/DAST tool format
  - [ ] Code vulnerabilities tracked with same workflow (SLA, Jira, risk acceptance)
  - [ ] Distinguish code vulnerabilities from infrastructure vulnerabilities on dashboard
  - [ ] Architecture supports adding additional scanner types

#### Epic: Extended Role Support
**Story:** As an administrator, I want additional roles beyond Viewer/Editor, so that I can implement more granular access control.
- **Acceptance Criteria:**
  - [ ] Auditor role (read-only including audit logs)
  - [ ] Team-scoped access (users see only their team's vulnerabilities)
  - [ ] Roles configurable via Admin UI

#### Epic: Additional Integrations
**Story:** As an administrator, I want the system designed for future integrations, so that we can connect to other tools as needs evolve.
- **Acceptance Criteria:**
  - [ ] Clean API layer for future integrations
  - [ ] Potential integrations: Email alerts, SIEM, BI tools, CMDB
  - [ ] No specific integrations required this iteration

#### Epic: Data Archival
**Story:** As a compliance owner, I want data older than the retention period archived or purged, so that storage is managed and compliance maintained.
- **Acceptance Criteria:**
  - [ ] Define archive/purge policy for data beyond 2-3 years
  - [ ] Archived data retrievable if needed for audit
  - [ ] Automated archival process

---

### Won't Have (This Iteration)

| Feature | Reason |
|---------|--------|
| Real-time scanner integration | Batch import via XLS meets current needs; API integrations add complexity |
| Custom vulnerability scoring | Use scanner-provided CVSS scores; no custom risk scoring engine |
| Automated remediation | System tracks and guides; actual patching is out of scope |
| Multi-tenancy | Single organization deployment; no tenant isolation required |
| Mobile app | Web dashboard sufficient for desktop-based security workflow |
| High availability / Failover | Best effort availability is acceptable |
| PDF/Excel report export | Import history tracking sufficient for current audit needs |
| Email notifications | No alerting integrations required this iteration |
| Vulnerability scanning | System tracks results; does not perform scans |

---

## Dependencies

| Dependency | Owner | Impact |
|------------|-------|--------|
| Azure AD tenant | IT/Identity Team | Required for SSO and AD group-based RBAC |
| Azure subscription | Cloud Team | AKS and PostgreSQL hosting |
| Jira Cloud instance | IT/DevOps | Ticket creation and status sync |
| Anthropic API access | Security Team | AI remediation guidance and insights |
| Qualys/Tenable access | Security Team | Weekly scan reports in XLS format |
| Azure Key Vault | Cloud Team | Secure storage for credentials and API keys |

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| AI service unavailable | Medium | System designed to function without AI; guidance field left empty, manual entry possible |
| Jira API rate limits | Medium | Batch ticket creation; implement retry with backoff |
| Scanner report format changes | High | Parser designed with flexible column mapping; alert on parse failures |
| PostgreSQL connection issues | High | Connection pooling; health checks; AKS restart policies |
| Azure AD integration failures | High | Graceful error handling; clear user messaging; fallback not possible (SSO required) |
| Large scan volumes slow imports | Medium | Optimize database queries; batch processing; monitor performance |
| RBAC misconfiguration | Medium | Audit log of permission changes; principle of least privilege defaults |
| Data retention compliance | Medium | Implement archival process before retention period reached |

---

## Open Questions

- [ ] Which SAST/DAST tools should be prioritized for future code scan integration?
- [ ] What are the specific Azure AD group names for role mapping?
- [ ] What is the exact data retention period - 2 years or 3 years?
- [ ] Should risk acceptance expiry trigger automatic notifications?
- [ ] What is the PostgreSQL sizing requirement for 2-3 years of data?
- [ ] Are there specific compliance frameworks (SOC2, ISO27001) driving audit requirements?
- [ ] What is the Admin role AD group name?

---

*Document created: 2026-01-24*
