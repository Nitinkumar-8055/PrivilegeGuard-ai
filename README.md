# PrivilegeGuard AI — Intelligent Privilege Abuse Detection and Security Monitoring System

![Platform](https://img.shields.io/badge/Platform-Windows%20Security%20%7C%20SOC%20Operations-06b6d4?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.11%2B%20%7C%203.14-blue?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-49%2F49%20Passing-10b981?style=flat-square)
![Collector](https://img.shields.io/badge/Collector-Native%20Windows%20wevtapi%20%2B%20Bookmarks-ec4899?style=flat-square)
![Persistence](https://img.shields.io/badge/Storage-SQLite%20(WAL%20Mode)%20%2B%20SQLAlchemy-8b5cf6?style=flat-square)
![Architecture](https://img.shields.io/badge/Architecture-Offline--First%20%2F%20Near--Real--Time-f59e0b?style=flat-square)



---

## 1. Executive Summary

**PrivilegeGuard AI** is a lightweight, high-performance cybersecurity platform designed to detect identity abuse, brute-force intrusions, unauthorized privilege escalations, and post-escalation sensitive resource exfiltration. 

Built specifically for high-assurance cybersecurity demonstrations, academic defense vivas, and SOC analyst workflows, the platform operates **100% locally and offline without requiring paid APIs, cloud services, Docker, or complex frontend frameworks**.

The platform couples **deterministic security rules** with an **explainable 0–100 risk scoring algorithm** and a **built-in expert cybersecurity intelligence engine** (with optional local Ollama LLM support), preventing hallucinations and ensuring transparent, audit-ready incident reports.

---

## 2. Key Architecture & Features

```
+-----------------------------------------------------------------------------------+
|                            PrivilegeGuard AI Platform                             |
+-----------------------------------------------------------------------------------+
|  [Ingestion Engine]    --> JSON & CSV Parsers, Strict Field Validation,           |
|                            Duplicate Suppression & Reject Auditing                |
+-----------------------------------------------------------------------------------+
|  [Detection Engine]    --> RULE-001: Repeated Failed Logins + Compromise          |
|                            RULE-002: Unexpected Privilege Escalation             |
|                            RULE-003: Unauthorized Privilege Grant                |
|                            RULE-004: Sensitive Resource Access Post-Escalation    |
|                            RULE-005: Access Denied Boundary Probing               |
+-----------------------------------------------------------------------------------+
|  [Risk Scorer]         --> Transparent Factor Breakdown (0 - 100 Scale)           |
|                            Low (0-29), Medium (30-59), High (60-79), Crit (80-100)|
+-----------------------------------------------------------------------------------+
|  [Correlation Engine]  --> Chronological Timeline Clustered by Identity & Session |
|                            Deduplication across overlapping alert batches         |
+-----------------------------------------------------------------------------------+
|  [Analysis Engine]     --> Built-in Expert Rule Intelligence (Offline Fallback)   |
|                            Optional Local Ollama LLM with Safe JSON Schema Guard  |
+-----------------------------------------------------------------------------------+
|  [SOC Dashboard]       --> Cyber Dark UI, Chart.js Visualizations,                |
|                            Simulated Containment Playbooks & Downloadable Reports |
+-----------------------------------------------------------------------------------+
```

### Core Capabilities
1. **Multi-Format Ingestion**: Ingests JSON arrays and CSV logs, enforcing required fields (`event_id`, `timestamp`, `username`, `event_type`, `outcome`), valid timestamps, and recognized access verbs. Rejects malformed and duplicate events with exact explanations.
2. **Deterministic Security Rules**: Independent, testable detection rules evaluating temporal windows, privilege hierarchies, and authorized role manager lists.
3. **Explainable Risk Scoring**: Quantifiable 0–100 risk score with mathematical point contributions for rule severity, target asset value, unauthorized actor status, and brute-force sequences.
4. **Non-Duplicating Incident Correlation**: Automatically associates related alerts and supporting forensic evidence into unified incident cases without creating duplicate tickets.
5. **Simulated SOC Containment Controls**: Allows security analysts to simulate response actions (Account Lockout, Active Session Revocation, Conditional Access Quarantine) which update incident status and log immutable audit entries.
6. **Downloadable Forensic Reports**: Generates both machine-readable JSON forensic evidence files and standalone, styled, printable HTML reports.

---

## 3. Supported Windows Security Event Mappings

PrivilegeGuard AI features a high-performance native event log parser translating raw Windows XML events into normalized identity access records:

| Windows Event ID | Event Description | Normalized Event Type | Target / Actor Mapping | Extracted Forensic Context |
| :---: | :--- | :--- | :--- | :--- |
| **`4624`** | Successful Logon | `login_success` | Target: `TargetUserName`<br>Actor: `SubjectUserName` | `LogonType` (2=Interactive, 3=Network, 10=RDP), `IpAddress`, `WorkstationName`, `TargetUserSid`, `LogonGuid` |
| **`4625`** | Failed Logon | `login_failure` | Target: `TargetUserName` | `Status`, `SubStatus` (e.g. `0xC000006A` = bad password), `IpAddress`, `WorkstationName` |
| **`4634`** | Logoff | `resource_access` | Target: `TargetUserName` | `LogonType`, `TargetUserSid` |
| **`4648`** | Logon with Explicit Credentials | `login_success` | Target: `TargetUserName`<br>Actor: `SubjectUserName` | `TargetServerName`, `IpAddress` (Flags potential lateral traversal / RunAs) |
| **`4672`** | Special Privileges Assigned | `permission_grant` | Target: `SubjectUserName` | `PrivilegeList` (`SeDebugPrivilege`, `SeTcbPrivilege`, `SeBackupPrivilege`, etc.) |
| **`4720`** | User Account Created | `role_change` | Target: `TargetUserName`<br>Actor: `SubjectUserName` | `TargetDomainName`, `TargetSid` (Persistence detection) |
| **`4722`** | User Account Enabled | `role_change` | Target: `TargetUserName`<br>Actor: `SubjectUserName` | Account reactivations outside standard provisioning |
| **`4728`** | Member Added to Global Group | `role_change` | Target: `MemberName`<br>Role: `TargetUserName` | Administrative tier modifications in Active Directory |
| **`4732`** | Member Added to Local Group | `role_change` | Target: `MemberName`<br>Role: `TargetUserName` | Escalation to `BUILTIN\Administrators` |
| **`4738`** | User Account Modified | `role_change` | Target: `TargetUserName`<br>Actor: `SubjectUserName` | Account property adjustments (MFA flags, password expiry) |
| **`4740`** | User Account Locked Out | `access_denied` | Target: `TargetUserName` | Account lockout following repeated authentication failures |
| **`1102`** | Security Audit Log Cleared | `access_denied` | Target: `SubjectUserName` | Critical anti-forensics / log tampering detection |

---

## 4. Security Threat Detection Rules

| Rule ID | Rule Name | Severity | Detection Logic | MITRE ATT&CK |
| :--- | :--- | :--- | :--- | :--- |
| `RULE-001` | **Repeated Failed Logins / Credential Stuffing** | Medium / High | Detects $\ge 3$ failed logins within a 15-minute window for the same user. If followed by a `login_success` from the same actor/IP, automatically escalates to High severity indicating account penetration. | T1110.001 |
| `RULE-002` | **Unexpected Privilege Escalation** | High / Critical | Detects a non-privileged user receiving a sensitive administrative tier (`admin`, `root`, `secops_admin`, etc.). Escalates to Critical if self-elevated. | T1078.003 |
| `RULE-003` | **Unauthorized Privilege Grant** | High | Detects role modifications or permission grants executed by an actor who is **not** listed in the authorized identity management governance policy. | T1098 |
| `RULE-004` | **Sensitive Access Following Escalation** | Critical | Correlates a privilege elevation with subsequent access to configured sensitive resources (`/api/v1/vault/keys`, `database://customer_pii`, `s3://financial-records`, `/etc/shadow`) within 30 minutes. | T1078 + TA0009 |
| `RULE-005` | **Access Denied Probing / Boundary Testing** | Medium | Detects clusters of $\ge 3$ access denials, flagging potential privilege boundary discovery or lateral traversal. | T1087 / T1069 |
| `RULE-006` | **Security Audit Log Cleared / Tampering** | Critical | Immediate alert upon detection of Windows Event `1102` or `security_audit_log_cleared`. Indicates active defense evasion. | T1070.001 |
| `RULE-007` | **Privileged Security Group Membership Addition** | High / Critical | Detects user accounts injected into privileged security groups (`Administrators`, `Domain Admins`, `Enterprise Admins`). Escalates to Critical if unapproved. | T1098 |
| `RULE-008` | **Suspicious Account Creation / Enablement** | Medium / High | Detects account creation (Event `4720`) or enablement (Event `4722`) initiated outside authorized IT governance systems. | T1136 |
| `RULE-009` | **Multi-Account Password Spraying** | High | Detects authentication failures originating from a single source host/IP targeting $\ge 3$ distinct user accounts within a 15-minute window. | T1110.003 |
| `RULE-010` | **Explicit Credential Abuse / Lateral Traversal** | Medium / High | Detects processes attempting logons using alternate explicit credentials (Event `4648`), flagging RunAs or lateral movement across administrative domains. | T1078.002 |


---

## 4. Risk Scoring Matrix

The risk scoring engine produces an integer score between **0 and 100** categorized into four standard severity bands:
- **0 – 29**: Low Severity (routine informational events)
- **30 – 59**: Medium Severity (isolated authentication failures, permission probing)
- **60 – 79**: High Severity (unauthorized role grants, brute-force penetration)
- **80 – 100**: Critical Severity (sensitive asset exfiltration post-escalation, self-assigned root)

### Explainable Point Decompositions
- **Alert Base Severity**: Critical (+45), High (+35), Medium (+20), Low (+10)
- **Compound Rule Concurrency**: Multi-alert incidents earn scaling bonus up to +15 pts
- **Sensitive Role Target**: Escalation into `admin`, `root`, `secops_admin` adds +15 pts
- **High-Value Target Asset**: Accessing cryptographic keys or customer PII adds +20 pts
- **Unauthorized Actor / Self-Elevation**: Actor policy violation or self-promotion adds +15 pts
- **Authentication Compromise Sequence**: Failed login cluster followed by success adds +25 pts

---

## 5. Project Directory Structure

```
privilegeguard-ai/
├── app.py                      # Application entry point & Flask factory
├── config.py                   # Security thresholds, role policies & settings
├── requirements.txt            # Minimal Python dependencies
├── README.md                   # Complete architectural and operational manual
├── .env.example                # Sample environment configuration
├── models/
│   ├── __init__.py             # SQLAlchemy instance and model exports
│   ├── events.py               # SecurityEvent model
│   ├── incidents.py            # Incident, IncidentEvent, DetectionAlert models
│   └── audit.py                # AuditLog model
├── services/
│   ├── ingestion.py            # JSON/CSV parsing, validation, and deduplication
│   ├── detection_engine.py     # Modular security detection rules & orchestrator
│   ├── correlation.py          # Incident clustering, timeline & deduplication
│   ├── risk_scoring.py         # Transparent 0-100 risk scoring engine
│   ├── ai_analysis.py          # Built-in expert analysis & optional Ollama bridge
│   └── reporting.py            # JSON and standalone HTML forensic report generators
├── routes/
│   ├── dashboard.py            # Overview metrics & real-time stats API
│   ├── events.py               # Event Explorer table, search, & modal API
│   ├── incidents.py            # Incident Center, detail view, & simulation API
│   ├── ingestion.py            # File upload, demo dataset generator, & clear DB
│   └── reports.py              # Forensic report download endpoints
├── templates/
│   ├── base.html               # Master cyber dark layout & navigation
│   ├── dashboard.html          # Operational overview & Chart.js widgets
│   ├── events.html             # Filterable and searchable Event Explorer
│   ├── incidents.html          # Incident management center
│   ├── incident_detail.html    # Deep-dive forensic timeline & response playbook
│   ├── ingestion.html          # File upload & synthetic dataset lab
│   └── reports.html            # Report download center
├── static/
│   ├── css/
│   │   └── style.css           # Custom dark cybersecurity theme
│   └── js/
│       ├── dashboard.js        # Dynamic metrics polling & Chart.js charts
│       └── incidents.js        # Status updates & containment simulation
├── data/
│   ├── sample_events.json      # Standalone JSON test dataset
│   └── sample_events.csv       # Standalone CSV test dataset
├── scripts/
│   ├── generate_dataset.py     # Synthetic scenario generator CLI
│   └── seed_demo_data.py       # One-step demo database seeding script
└── tests/
    ├── conftest.py             # Test fixtures & in-memory test database
    ├── test_ingestion.py       # Tests for JSON/CSV, validation, and duplicates
    ├── test_detection.py       # Tests for each detection rule & benign admin
    ├── test_correlation.py     # Tests for timeline clustering & deduplication
    ├── test_risk_scoring.py    # Tests for mathematical factor scoring
    ├── test_reporting.py       # Tests for JSON/HTML report generation
    ├── test_ai_fallback.py     # Tests for offline deterministic fallback
    └── test_routes.py          # Tests for web routes and containment simulation
```

---

## 6. Installation & Quickstart

### Prerequisites
- Python 3.11 or newer (tested on Python 3.14.3)
- Windows, macOS, or Linux

### 1. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 2. Run Automated Test Suite
Verify that all 23 security, correlation, ingestion, and reporting tests pass:
```powershell
python -m pytest -v
```

### 3. Seed Demonstration Data (Optional)
Populate the database with realistic attack scenarios and benign baselines:
```powershell
python scripts/seed_demo_data.py
```

### 4. Launch the Web Platform
```powershell
python app.py
```
Open your browser to: **`http://127.0.0.1:5000`**

---

## 7. Demonstration Guide for Academic Viva & Presentation

Follow this 5-minute walkthrough to demonstrate the system live:

### Step 1: Platform Overview (`/`)
1. Open `http://127.0.0.1:5000`.
2. Point out the real-time metric cards: **Total Events**, **Correlated Incidents**, **High & Critical Incidents**, and **Affected Identities**.
3. Highlight the **Incident Severity Distribution** (donut chart) and **Event Activity Timeline** (activity chart).
4. Explain that every metric is queried directly from actual database records.

### Step 2: Data Ingestion & Input Validation (`/ingestion`)
1. Navigate to the **Data Ingestion** tab.
2. Show the pre-configured attack scenarios and click **Generate Demo Dataset** (or upload `data/sample_events.json`).
3. Show the **Ingestion & Validation Report**:
   - `15 Accepted`: valid normal and attack events.
   - `4 Rejected`: malformed timestamps, blank usernames, and duplicate event IDs.
   - Point out the specific rejection reasons in the table, demonstrating input hygiene.

### Step 3: Event Explorer & Baselines (`/events`)
1. Navigate to **Event Explorer**.
2. Filter by `login_failure` to show how attackers probe accounts.
3. Search for benign user `emily.watson` to demonstrate routine legitimate activity that does **not** trigger alerts.
4. Click **Details** on any row to display the raw ingested JSON payload and structured parsed forensic attributes.

### Step 4: Incident Center & Explainable Risk Scoring (`/incidents`)
1. Navigate to **Incident Center**.
2. Show how 15 raw events were correlated into 4 distinct incidents:
   - `INC-2026-0001` (Score 60/100, High): Brute-force guessing followed by successful penetration (`alex.hunter`).
   - `INC-2026-0002` (Score 83/100, Critical): Self-assigned administrative role elevation (`clara.oswald`).
   - `INC-2026-0003` (Score 73/100, High): Unauthorized contractor granting administrative privileges (`dev.jordan`).
   - `INC-2026-0004` (Score 100/100, Critical): Post-escalation access to vault keys and customer PII (`marcus.vance`).
3. Point out that legitimate admin maintenance by `secops_admin` did **not** trigger false criticals.

### Step 5: Incident Deep Dive, AI Forensics & Containment (`/incidents/4`)
1. Click into `INC-2026-0004` (Marcus Vance - 100/100 Critical).
2. Review the **Correlated Event Timeline**: observe the role change to `root` followed 3 minutes later by access to `/api/v1/vault/keys` and `database://customer_pii`.
3. Inspect the **Risk Score Breakdown**: explain how each factor contributed (+45 Critical Rule, +20 Sensitive Asset, +15 Sensitive Role, etc.).
4. Review the **Security Intelligence Analysis**: show the "Why Flagged" rationale, "Potential Benign Explanation" (e.g., emergency break-glass maintenance), and "Analytical Uncertainties".
5. Click **Simulate Account Lockout** or **Simulate Session Invalidation** under the Response Playbook. Observe the real-time simulation toast, audit log entry, and automatic status update to `Contained`.
6. Click **Forensic Report (HTML)** in the top right to display the standalone printable forensic report.

---

---

## 8. Database Concurrency & SQLite Lock Resolution

### Diagnosis of the `OperationalError: database is locked` Error
Previous execution encountered SQLite locking during multi-alert correlation and batch writes. An in-depth code and trace audit revealed three compounding factors:
1. **Network I/O Inside Active Transactions**: In `IncidentCorrelationEngine.correlate_alerts`, calls to `AIAnalysisService.analyze_incident(...)` (Ollama HTTP queries or timeouts up to 120s) were executing synchronously while a database read query had opened a transaction and `flush()` had acquired row locks.
2. **OneDrive File Locking Contention**: On Windows, Microsoft OneDrive constantly monitors and locks `.db` files during rapid write bursts to synchronize delta changes to the cloud. Default SQLite settings gave up after a brief timeout.
3. **Default SQLite Journal Mode**: Default SQLite journal mode (`DELETE`) locks the entire database file against concurrent readers whenever a write is queued.

### Architectural Fixes Implemented
1. **Decoupled Three-Phase Correlation**:
   - **Phase 1 (Read-Only)**: Queries events and historical incidents cleanly in one batch.
   - **Phase 2 (In-Memory Intelligence)**: Risk scoring, heuristic rule checks, and Ollama/Deterministic AI generation run entirely in memory. Zero database write transactions or flushes are held during AI calls.
   - **Phase 3 (Atomic Fast Writes)**: Rapid, localized writes with immediate commit.
2. **WAL Mode & Busy Timeout Configuration**:
   - SQLite Write-Ahead Logging (`PRAGMA journal_mode=WAL;`) allows concurrent readers while a write is occurring.
   - Connection busy timeout set to 30,000 ms (`PRAGMA busy_timeout=30000;`) via SQLAlchemy Engine connect event hooks.
   - SQLite timeout configured to 30.0s in `SQLALCHEMY_ENGINE_OPTIONS`.
3. **Bounded Exponential Backoff Retries**:
   - Both `IngestionService` and `IncidentCorrelationEngine` feature bounded retries (up to 5 attempts with exponential backoff $0.1s \times 2^n$ + jitter) catching transient locks.
4. **Collision-Proof Incident IDs**:
   - `generate_incident_id` parses existing numeric sequence suffixes from the database and session reserved IDs, eliminating ID collisions.
5. **Strict Test Isolation**:
   - The test suite uses isolated in-memory SQLite with `StaticPool` (`TestConfig`), ensuring tests never touch or truncate the live `privilegeguard.db`.

---

## 9. OneDrive Synchronization Best Practices

Because the project folder resides in `OneDrive\Documents\privilegeguard-ai`, OneDrive will attempt to synchronize SQLite database files during writes:
- **Recommended Dev Setup**: If heavy continuous ingestion is performed, pause OneDrive syncing temporarily or set `DATABASE_URL=sqlite:///C:/Users/<Username>/AppData/Local/privilegeguard/privilegeguard.db` in `.env` to place the database outside OneDrive's sync root.
- **Current Protection**: Thanks to WAL mode (`-wal` and `-shm` sidecar files) and 30s busy timeouts, the application operates reliably even with active OneDrive synchronization.

---

## 10. Local AI Intelligence & Ollama Integration

PrivilegeGuard AI features a hybrid AI architecture:
- **Primary AI Engine**: Built-in **Deterministic Expert Security Engine** that runs 100% offline with zero dependencies, producing explainable incident summaries, MITRE ATT&CK mappings, and SOC playbooks.
- **Optional Local LLM (Ollama)**: Integrates seamlessly with **Qwen 2.5 (3B)** or **Llama 3** running locally.

### Running with Ollama
1. Install [Ollama](https://ollama.com).
2. Pull and start the recommended model:
   ```powershell
   ollama pull qwen2.5:3b
   ollama run qwen2.5:3b
   ```
3. Set environment variables in `.env` (or use built-in defaults):
   ```ini
   OLLAMA_API_URL=http://localhost:11434/api/generate
   OLLAMA_MODEL=qwen2.5:3b
   OLLAMA_TIMEOUT_SECONDS=120
   ```
4. If Ollama is offline or uninstalled, the application automatically falls back to the deterministic engine without throwing errors or interrupting ingestion.

---

## 11. Safe Database Backup & Restore Procedures

To protect historical audit trails and forensic incident records:

### Safe Online Backup
SQLite database files should **never** be copied using raw file copy while the server is running. Use Python's atomic `sqlite3.backup()` API:
```powershell
python -c "import sqlite3, shutil, datetime; src = sqlite3.connect('privilegeguard.db'); bkp = sqlite3.connect(f'backups/privilegeguard_backup_{datetime.datetime.now().strftime(\"%Y%m%d_%H%M%S\")}.db'); src.backup(bkp); bkp.close(); src.close(); print('[+] Atomic backup completed successfully.')"
```
Backups are stored safely in the `backups/` directory.

### Safe Database Verification
To inspect current database counts without modifying data:
```powershell
python -c "import sqlite3; conn = sqlite3.connect('privilegeguard.db'); cur = conn.cursor(); print(dict(cur.execute('SELECT \'events\', count(*) FROM security_events UNION ALL SELECT \'incidents\', count(*) FROM incidents UNION ALL SELECT \'alerts\', count(*) FROM detection_alerts UNION ALL SELECT \'incident_events\', count(*) FROM incident_events UNION ALL SELECT \'audit_logs\', count(*) FROM audit_logs').fetchall()))"
```

---

## 12. Windows Security Permissions & Audit Policy Setup

### Required Windows Privileges
Reading the Windows `Security` event log is restricted by the Windows Operating System to accounts holding `SeSecurityPrivilege`, members of the `BUILTIN\Administrators` group, or accounts explicitly added to the `Event Log Readers` local security group.

When running in an unelevated console (Standard User Token), Windows returns:
`Access is denied (Windows System Error 5)`
PrivilegeGuard AI accurately detects this condition and reports:
`Status: Access Denied | Error: Administrator privileges or 'Event Log Readers' group membership required to read the Security channel.`

### Running with Elevated Privileges
To enable genuine, live Windows Security event log collection:
1. Open PowerShell or Command Prompt with **Run as Administrator**:
   ```powershell
   Start-Process powershell -Verb runAs
   ```
2. Navigate to the project directory:
   ```powershell
   cd "C:\Users\<Username>\OneDrive\Documents\privilegeguard-ai"
   ```
3. Run the application:
   ```powershell
   python app.py
   ```
   Or run the dedicated standalone background collector:
   ```powershell
   python run_collector.py --channel Security --interval 5.0
   ```

### Enabling Recommended Windows Security Audit Policies
To ensure Windows logs all relevant authentication, privilege elevation, and account modification events, run the following commands in an elevated prompt:
```powershell
# 1. Audit Logon & Logoff (Events 4624, 4625, 4634, 4648)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable

# 2. Audit Privilege Use & Special Logon (Event 4672)
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

# 3. Audit User & Group Account Management (Events 4720, 4722, 4728, 4732, 4738)
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable

# 4. Verify Active Audit Configuration
auditpol /get /category:*
```

---

## 13. Dedicated Background Collector & Demo Modes

### Standalone Background Collector (`run_collector.py`)
Run the collector as an independent, single-owner background process:
```powershell
# Real Windows Security Event Collection (Elevated Console)
python run_collector.py --channel Security --interval 5.0 --batch 100

# Simulated Mode (No elevation required, ideal for offline presentations)
python run_collector.py --simulated --interval 5.0
```

### Isolated Demo Mode (`scripts/run_demo_mode.py`)
For academic presentations and defense vivas without modifying or polluting the live database:
```powershell
python scripts/run_demo_mode.py
```
- Operates on a dedicated, temporary database: `privilegeguard_demo.db` on `http://127.0.0.1:5001`.
- Completely protects the production database `privilegeguard.db`.
- Demonstrates repeated failed logins, account compromise, elevation to `BUILTIN\Administrators`, sensitive resource access, and security log clearing (`Event 1102`).
- To clean up after presentation:
  ```powershell
  Remove-Item privilegeguard_demo.db
  ```

---


---

## 11. Notification & Alert Management System

PrivilegeGuard AI features a production-grade, multi-channel notification architecture designed to keep SOC administrators informed of high-severity security incidents in real time while eliminating alert fatigue through database-backed deduplication.

### Architecture Workflow

```
+-----------------------------------+
|  Windows Security Event Collector |
+-----------------+-----------------+
                  |
                  v
+-----------------+-----------------+
|      CSV / JSON Ingestion         |
+-----------------+-----------------+
                  |
                  v
+-----------------+-----------------+
|   Validation & Normalization      |
+-----------------+-----------------+
                  |
                  v
+-----------------+-----------------+
|      SQLite Database Storage      |
+-----------------+-----------------+
                  |
                  v
+-----------------+-----------------+
|   Rule-Based Detection Engine     |
+-----------------+-----------------+
                  |
                  v
+-----------------+-----------------+
|        Alert Generation           |
+-----------------+-----------------+
                  |
                  v
+-----------------+-----------------+
|       Incident Correlation        |
+-----------------+-----------------+
                  |
                  v
+-----------------+-----------------+
|    Incident Created / Escalated   |
+-----------------+-----------------+
                  |
                  v
+-----------------+-----------------+
|    Notification Dispatcher        |
|  (Database Deduplication Check)   |
+--------+--------------------+-----+
         |                    |
         v                    v
+--------+--------+  +--------+--------+
|  In-App Alert   |  |   Email Worker  |
|  (Dashboard &   |  |  (Async Queue & |
|  Navbar Bell)   |  |   Gmail SMTP)   |
+-----------------+  +-----------------+
```

### Channel Routing & Severity Matrix

By default, the platform routes incidents according to risk severity:

| Severity Level | Risk Score | In-App Dashboard | Gmail SMTP Email | Default Trigger |
| :--- | :--- | :---: | :---: | :--- |
| **CRITICAL** | 80 – 100 | **ENABLED** | **ENABLED** | Immediate email dispatch + unread bell alert |
| **HIGH** | 60 – 79 | **ENABLED** | **ENABLED** | Urgent email dispatch + unread bell alert |
| **MEDIUM** | 30 – 59 | **ENABLED** | Disabled | Dashboard bell dropdown & history log only |
| **LOW** | 0 – 29 | **ENABLED** | Disabled | Dashboard bell dropdown & history log only |

Administrators can customize triggers, disable channels, or change email routing at any time via the **Notification Settings** page (`/settings/notifications`).

---

### Deduplication & Severity Escalation Rules

To prevent flooding administrator inboxes, PrivilegeGuard AI enforces database-backed deduplication rules:

- **Scenario 1 (New Incident Created)**: When a qualifying `HIGH` or `CRITICAL` incident is created, exactly one email and one in-app notification are generated.
- **Scenario 2 (Repeated Polling, No New Events)**: When the Windows Event Log collector polls and encounters no new events, no alerts or notifications are dispatched.
- **Scenario 3 (Additional Evidence, Severity Unchanged)**: When an existing incident correlates new events but its severity classification remains unchanged, duplicate emails are suppressed.
- **Scenario 4 (Severity Escalation)**: When an existing incident escalates from a lower severity to a higher severity (e.g., `HIGH` to `CRITICAL`), a dedicated escalation notification is generated (`[ESCALATION: CRITICAL]`), alerting the administrator immediately.

---

### Non-Blocking Asynchronous Email Worker

Email transmissions are processed by `NotificationWorker`, a thread-safe background queue worker:
- **Zero Blocking**: The Windows Security Event collector, CSV/JSON file upload pipelines, and web UI requests never block waiting for network SMTP handshakes.
- **Fault-Tolerant Persistence**: Outbound notification records are saved in SQLite with `delivery_status="pending"` before transmission.
- **Graceful Error Handling**: If SMTP is temporarily unreachable or credentials are not yet entered, records transition to `delivery_status="failed"` with diagnostic details without interrupting platform monitoring.
- **Retry Mechanism**: Transient failures are automatically retried with exponential backoff up to 3 times.

---

### Gmail SMTP Setup Guide

Outbound email alerts utilize standard Gmail SMTP over SSL (Port 465) or STARTTLS (Port 587).

#### Step-by-Step Gmail App Password Generation:
1. Open your Google Account Security Dashboard at [myaccount.google.com/security](https://myaccount.google.com/security).
2. Ensure **2-Step Verification** is turned **ON**.
3. In the security search bar or under "2-Step Verification", select **App passwords** ([myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)).
4. Name your application: `PrivilegeGuard AI`.
5. Click **Create** and copy the generated 16-character password (e.g. `abcd efgh ijkl mnop`).
6. Paste the password into your `.env` file:
   ```bash
   SMTP_PASSWORD=abcd efgh ijkl mnop
   ```

> **Security Guard**: PrivilegeGuard AI never stores your App Password in the database or exposes credentials in API responses or frontend templates.

---

### Environment Configuration (.env)

Configure your `.env` file in the project root:

```ini
# Core Configuration
SECRET_KEY=privilegeguard-dev-secret-key-2026-safe
DATABASE_URL=sqlite:///privilegeguard.db

# Gmail SMTP Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=465
SMTP_SECURITY=SSL
SMTP_EMAIL=your-sender@gmail.com
SMTP_PASSWORD=your-16-char-app-password
ADMIN_EMAIL=nk8055444@gmail.com

# Notification Channels & Severity Filters
EMAIL_NOTIFICATIONS_ENABLED=true
INAPP_NOTIFICATIONS_ENABLED=true
EMAIL_SEVERITIES=high,critical
INAPP_SEVERITIES=low,medium,high,critical
```

---

### Windows PowerShell Quickstart & Verification Commands

#### 1. Start PrivilegeGuard AI Web Application
```powershell
python app.py
```
Access the SOC dashboard at `http://127.0.0.1:5000`.

#### 2. Send an Immediate SMTP Verification Test Email
From the Web UI:
- Navigate to `http://127.0.0.1:5000/settings/notifications`.
- Click **Send Test Email**.

Or via PowerShell:
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/notifications/test-email" -Method Post -ContentType "application/json" -Body '{"recipient": "nk8055444@gmail.com"}'
```

#### 3. Run the Windows Security Event Collector
```powershell
python run_collector.py --channel Security --interval 5.0 --batch 50
```
*(For demonstration without administrator terminal elevation, add `--simulated`)*:
```powershell
python run_collector.py --simulated --interval 5.0
```

#### 4. Run the Complete Automated Test Suite (49 Tests)
```powershell
pytest -v
```

---
## 14. Test Suite Verification & Windows Verification Report

### Automated Execution via pytest
```
============================= test session starts =============================
platform win32 -- Python 3.14.3, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\Nitin Kumar\OneDrive\Documents\privilegeguard-ai
configfile: pytest.ini
testpaths: tests
plugins: flask-1.3.0
collected 49 items

tests\test_ai_fallback.py ..                                             [  5%]
tests\test_collector.py .......                                          [ 23%]
tests\test_correlation.py .                                              [ 26%]
tests\test_detection.py .......                                          [ 44%]
tests\test_ingestion.py .......                                          [ 63%]
tests\test_persistence_and_metrics.py .                                  [ 65%]
tests\test_reporting.py ..                                               [ 71%]
tests\test_risk_scoring.py ...                                           [ 78%]
tests\test_robustness.py .....                                           [ 92%]
tests\test_routes.py ...                                                 [100%]

============================= 49 passed in 30.67s =============================
```

### Verification Metrics
- **Tests Passed**: 49
- **Tests Failed**: 0
- **Tests Skipped**: 0
- **Tests Not Run**: 0
- **Actual Windows Verification Status**:
  - Live native probe executed against the local Windows 11 host (`LAPTOP-T2G0O0MP`).
  - Standard user token returned `Access is denied (Error 5)` for the `Security` channel, verified accurately and surfaced on the dashboard.
  - Native Windows `Application` channel queried via `wevtapi.dll` ctypes bindings, returning live event records in `<Event xmlns=...>` format.
  - All 12 Windows Security event ID mappings verified against official Microsoft schemas.
  - Checkpoint bookmark persistence and duplicate prevention across restarts verified.
  - Production database `privilegeguard.db` verified completely untouched.

---

## 15. Known Limitations & Roadmap

- **Host-Focused Scope**: PrivilegeGuard AI monitors host identity, authorization, and event log telemetry; it is not designed to replace full network EDR or antivirus solutions.
- **Auditing Dependency**: Windows Event collection relies on Windows Audit Policies being enabled on the monitored host; events that are not audited by the OS cannot be collected.
- **Multi-Node Ingestion**: The current release collects from the local Windows machine; future enterprise iterations could incorporate Windows Event Forwarding (WEF) or WinRM agent collectors across a fleet.


