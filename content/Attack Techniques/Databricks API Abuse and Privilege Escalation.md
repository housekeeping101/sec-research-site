---
title: Databricks API Abuse and Privilege Escalation
date: 2026-03-08
type: ttp
mitre_id: T1087.004, T1528, T1134, T1078.004, T1548, T1552.001, T1537, T1213
mitre_tactic: Discovery, Credential Access, Privilege Escalation, Lateral Movement, Exfiltration
threat_actors: []
tools_used:
  - DBXploit
  - Databricks REST API
  - Python 3
platforms:
  - Databricks
  - Cloud
tags:
  - type/ttp
  - status/active
  - platform/cloud
  - category/credential-access
  - category/privilege-escalation
source:
  url: https://github.com/capitalone/dbxploit
  author: mohamedmrabah, ieribo (CapitalOne)
  date: 2025
---

## Summary

Databricks environments are commonly misconfigured in ways that allow an attacker with any valid Personal Access Token (PAT) to escalate from low-privilege user to workspace or account admin using only native REST APIs. The attack surface includes overly permissive secret scope ACLs, hardcoded credentials in notebooks, extractable context tokens from running notebook environments, and SCIM API endpoints that permit role modification. The DBXploit framework (CapitalOne security research) demonstrates the full attack chain is automatable in minutes using only authenticated API calls that are largely indistinguishable from legitimate Databricks SDK/Terraform activity.

## How It Works

### Step 1 — Obtain a Foothold (T1078.004)
The attacker obtains a valid Databricks PAT by one of several routes:
- Extracting a committed token from a Git repo, `.env` file, or CI/CD secret
- Phishing a developer or data engineer
- Credential reuse from another breach
- SSRF against a Databricks-connected web application
- Finding a token in a notebook output or cluster log

Even a low-privilege user token is sufficient to begin the attack chain.

### Step 2 — Reconnaissance and Identity Fingerprinting (T1087.004, T1213)
Using `whoami.py` and `recon.py`, the attacker:
- Calls `/api/2.0/preview/scim/v2/Me` to map the token to a user identity and privilege level
- Enumerates workspace users, groups, clusters, jobs, and DBFS objects
- Builds a complete target map of the environment

### Step 3 — Secret Scope Enumeration and Credential Harvest (T1552.001, T1528)
`secrets_audit.py` calls the Secrets API to list all scopes and their ACLs:
```
GET /api/2.0/secrets/scopes/list
GET /api/2.0/secrets/acls/list?scope=<scope>
```
Any scope with `READ` permission granted to `all users` (a common misconfiguration) is immediately dumpable. `secrets_dump.py` reads the values and `notebook_scan.py` scans workspace notebooks for hardcoded credentials (API keys, cloud credentials, DB connection strings).

### Step 4 — Token Hijacking and Relay (T1528, T1134)
`token_hijack.py` extracts temporary OAuth tokens from active or recently completed Databricks notebook execution contexts. These context tokens are then replayed by `token_relay.py` to authenticate as the notebook's owner, potentially gaining higher privilege than the original attacker token.

### Step 5 — Job Impersonation (T1134, T1078.004)
`impersonate_job.py` submits Databricks Jobs API run requests specifying a victim user in the `run_as` field:
```
POST /api/2.1/jobs/runs/submit
{ "run_as": { "user_name": "victim@corp.com" }, ... }
```
Audit log events for these job runs are attributed to the victim, not the attacker.

### Step 6 — SCIM-Based Privilege Escalation (T1548, T1098)
If the attacker has (or has pivoted to) an account-admin token, `privilege_escalation.py` calls:
```
PUT /api/2.0/preview/scim/v2/Users/<user-id>
```
to add the `account_admin` role to the attacker's account. This grants full platform control: all workspaces, all secrets, all clusters, all users.

### Step 7 — Data Exfiltration via Webhook (T1537)
`secret_exfiltrate.py` POSTs all harvested secrets to an attacker-controlled external webhook URL over HTTPS. This bypasses any Databricks-internal data lineage or DLP controls and routes data entirely off-platform.

---

## Technical Reference

### Tool Structure (DBXploit)
```
dbxploit/
├── dbxploit.py             # Main interactive CLI menu (14 modules)
├── config.py               # Workspace URL, account ID, PAT token
├── requirements.txt
└── core/
    ├── __init__.py
    ├── access_summary.py   # Summarizes ACL exposure across workspace
    ├── impersonate_job.py  # Submits jobs under another user's identity
    ├── notebook_scan.py    # Scans notebooks for hardcoded credentials
    ├── pivot_chain.py      # Chains techniques for lateral movement
    ├── privilege_escalation.py  # SCIM-based admin promotion
    ├── recon.py            # Enumerate clusters, jobs, DBFS, users
    ├── secret_exfiltrate.py     # Sends secrets to attacker webhook
    ├── secrets_audit.py    # Enumerates secret scopes and ACLs
    ├── secrets_dump.py     # Reads secrets from accessible scopes
    ├── token_hijack.py     # Captures temporary tokens from notebook contexts
    ├── token_relay.py      # Replays captured tokens for lateral movement
    ├── utils.py            # Shared HTTP helpers and API wrappers
    ├── whoami.py           # Fingerprints current token to user identity
    └── workspace_scraper.py    # Bulk enumerates workspace objects
```

### Databricks API Endpoints Abused
```
# Secrets
GET  /api/2.0/secrets/scopes/list
GET  /api/2.0/secrets/list?scope=<scope>
GET  /api/2.0/secrets/acls/list?scope=<scope>
GET  /api/2.0/secrets/get?scope=<scope>&key=<key>

# SCIM (Account-level admin required)
GET  /api/2.0/preview/scim/v2/Users
PUT  /api/2.0/preview/scim/v2/Users/<id>      # Role modification (privesc)
PATCH /api/2.0/preview/scim/v2/Users/<id>

# Jobs & Identity
POST /api/2.1/jobs/runs/submit              # Job submission (impersonation)
GET  /api/2.0/token/list
GET  /api/2.0/preview/scim/v2/Me           # Token identity fingerprinting

# Workspace enumeration
GET  /api/2.0/workspace/list
GET  /api/2.0/clusters/list
GET  /api/2.0/dbfs/list
```

### Configuration File (Attacker-controlled)
```python
# config.py
WORKSPACE_URL = "https://<workspace>.azuredatabricks.net"
ACCOUNT_ID    = "<account-uuid>"
TOKEN         = "<databricks-PAT>"
```

### Module Reference Table

| File | Purpose | Attacker Value |
|------|---------|----------------|
| `secrets_audit.py` | Enumerate all secret scopes and ACL settings | Identifies scope misconfigurations — scopes with READ on `all users` are immediately dumpable |
| `secrets_dump.py` | Read secret values from accessible scopes | Direct credential harvest — service account keys, cloud credentials, DB passwords |
| `notebook_scan.py` | Search workspace notebooks for hardcoded strings | Finds credentials developers left in code — common in data engineering environments |
| `privilege_escalation.py` | Promote user to workspace/account admin via SCIM PUT | Full platform takeover; only requires account-level token |
| `impersonate_job.py` | Submit Databricks jobs under another user's identity | Lateral movement; actions appear attributed to victim user |
| `token_hijack.py` | Extract temporary OAuth tokens from active notebook contexts | Pivot to other users without knowing their credentials |
| `token_relay.py` | Replay harvested tokens against APIs | Extends access; tokens may have higher privileges than original account |
| `secret_exfiltrate.py` | POST secrets to external webhook | Exfiltration that bypasses Databricks audit log enrichment |
| `pivot_chain.py` | Chain techniques in sequence | Automates multi-step escalation without manual intervention |
| `workspace_scraper.py` | Enumerate jobs, clusters, DBFS, notebooks | Full reconnaissance; builds target map for further exploitation |

### Technique-MITRE Mapping

| Tool / Module | MITRE ID | Usage |
|---|---|---|
| `secrets_audit.py` + `secrets_dump.py` | T1552.001, T1528 | Credential harvesting from misconfigured secret scopes |
| `notebook_scan.py` | T1552.001 | Searches notebooks for plaintext secrets |
| `whoami.py` | T1087.004 | Fingerprints token → user identity |
| `recon.py` + `workspace_scraper.py` | T1213, T1087.004 | Full workspace enumeration (clusters, jobs, DBFS, users) |
| `impersonate_job.py` | T1134, T1078.004 | Job submission under victim user identity |
| `token_hijack.py` + `token_relay.py` | T1528, T1134 | Token theft and replay for lateral movement |
| `privilege_escalation.py` | T1548, T1098 | SCIM PUT to promote attacker account to admin |
| `secret_exfiltrate.py` + webhook | T1537 | Route secrets to external attacker-controlled endpoint |
| `pivot_chain.py` | Multiple | Automated chaining of above techniques |

### Setup Commands
```bash
git clone https://github.com/capitalone/dbxploit
cd dbxploit
pip install -r requirements.txt
# Edit config.py with workspace URL, account ID, and PAT
python3 dbxploit.py
# Interactive menu with 14 exploitation modules
```

### Attack Prerequisites

| Requirement | Detail |
|---|---|
| Minimum access | Any valid Databricks PAT (even low-privilege user) |
| For SCIM privesc | Account Admin-level token required |
| For token hijack | Access to a running or recently run notebook context |
| For secret dump | READ ACL on target scope (or `all users` misconfiguration) |
| Network access | HTTPS to `<workspace>.azuredatabricks.net` |

**How minimum access is achievable:**
- Phishing a developer with a Databricks account
- Credential stuffing with leaked credentials
- Extracting a PAT from a committed `.env` file, CI/CD secret, or notebook output
- SSRF against a Databricks-connected application

### Attacker Stealth Notes
- All operations use **native Databricks REST APIs** — no malware, no binaries, no EDR hooks
- API calls are **indistinguishable from legitimate Databricks tooling** (Terraform, SDK, CLI) in isolation
- SCIM modifications may not trigger alerts in environments not monitoring admin role changes
- Webhook exfiltration routes data off-platform; no Databricks Data Lineage detection
- Job impersonation creates audit log entries attributed to the victim user, not the attacker

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Cloud Account Discovery | T1087.004 | Enumerating workspace users, groups, and token identity fingerprinting |
| Steal Application Access Token | T1528 | Extracting Databricks context tokens from notebook environments |
| Access Token Manipulation | T1134 | Job impersonation via `run_as`, token relay for privilege pivot |
| Valid Accounts: Cloud Accounts | T1078.004 | Using stolen or low-privilege PAT as initial foothold |
| Abuse Elevation Control Mechanism | T1548 | SCIM PUT to promote attacker account to account_admin |
| Credentials in Files | T1552.001 | Secrets in Parameter Store paths; hardcoded creds in notebooks |
| Transfer Data to Cloud Account | T1537 | Webhook exfiltration to attacker-controlled external endpoint |
| Data from Information Repositories | T1213 | Workspace enumeration (notebooks, DBFS, job configs) |

---

## Detection Opportunities

### Key Log Sources
- **Databricks Audit Logs** — primary source; delivered to cloud storage or SIEM via log delivery configuration
- **CrowdStrike Falcon** — if endpoint runs the Databricks CLI or SDK
- **Cloud Trail / Azure Monitor** — for underlying cloud resource calls
- **Network logs / Proxy** — for webhook exfiltration detection

### Behavioral Indicators
- Bulk sequential calls to `/api/2.0/secrets/scopes/list` and `/api/2.0/secrets/acls/list` in rapid succession
- `getSecret` calls against multiple scopes from a single principal in a short window
- SCIM `PUT` or `PATCH` to `/Users/<id>` modifying roles — especially adding `account_admin`
- Job submissions specifying a `run_as` user that does not match the authenticating principal
- `/api/2.0/preview/scim/v2/Me` called repeatedly (token fingerprinting/enumeration)
- Outbound HTTPS from Databricks job context to an unknown external domain

### Artifacts Left Behind
- Databricks audit log events: `secrets`, `accounts`, `jobs`, `workspace` service categories
- SCIM modification events with `requestParams.roles` changes
- Job run history with `run_as` mismatch between submitter and executor
- Secret access events (`getSecret`, `listSecrets`) at elevated frequency
- Network egress records to attacker webhook domain

---

## Query Stubs

### CrowdStrike FQL — Databricks CLI / SDK Spawned Processes
```fql
// Processes that may indicate DBXploit usage from an endpoint
event_simpleName=ProcessRollup2
| CommandLine=/python3.*dbxploit/ OR FileName="dbxploit.py"
| table timestamp, ComputerName, UserName, CommandLine, ParentProcessName
```

### CrowdStrike FQL — Outbound HTTPS to Unusual Domains (Webhook Exfil)
```fql
// Network connections from Python processes to non-Databricks domains
event_simpleName=NetworkConnectIP4
| ParentImageFileName=/python3|python/
| RemotePort=443
| NOT RemoteAddressIP4=/10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\./
| NOT DomainName=/.databricks\.com$|.azuredatabricks\.net$|.cloud\.databricks\.com$/
| table timestamp, ComputerName, UserName, DomainName, RemoteAddressIP4
```

### Databricks SQL — Bulk Secret Scope Enumeration
```sql
-- Identify principals rapidly enumerating secret scopes/keys
SELECT
  userIdentity.email         AS principal,
  COUNT(*)                   AS api_calls,
  MIN(timestamp)             AS first_seen,
  MAX(timestamp)             AS last_seen,
  COLLECT_SET(actionName)    AS actions
FROM databricks_audit_logs
WHERE serviceName = 'secrets'
  AND actionName IN ('listScopes', 'listSecrets', 'getAcl', 'getSecret')
  AND timestamp >= NOW() - INTERVAL 1 HOUR
GROUP BY principal
HAVING COUNT(*) > 20
ORDER BY api_calls DESC
```

### Databricks SQL — SCIM Role Modification (Privilege Escalation)
```sql
-- Detect SCIM calls that modify user roles (account_admin promotion)
SELECT
  timestamp,
  userIdentity.email         AS actor,
  requestParams.targetUserName AS target_user,
  requestParams.roles        AS new_roles,
  sourceIPAddress,
  userAgent
FROM databricks_audit_logs
WHERE serviceName = 'accounts'
  AND actionName IN ('updateUser', 'patchUser')
  AND requestParams.roles LIKE '%account_admin%'
ORDER BY timestamp DESC
```

### Databricks SQL — Job Impersonation (run_as Mismatch)
```sql
-- Jobs submitted where the run_as user differs from the submitting principal
SELECT
  timestamp,
  userIdentity.email         AS submitting_principal,
  requestParams.run_as       AS impersonated_user,
  requestParams.job_id,
  sourceIPAddress
FROM databricks_audit_logs
WHERE serviceName = 'jobs'
  AND actionName = 'submitRun'
  AND requestParams.run_as IS NOT NULL
  AND requestParams.run_as != userIdentity.email
ORDER BY timestamp DESC
```

---

## Tools Reference

| Tool | Purpose |
|---|---|
| DBXploit | Modular Databricks exploitation framework (14 modules) |
| Databricks REST API | Native API used for all attack techniques |
| Python 3 | Runtime for DBXploit |

---

## Threat Actor Usage

No specific threat actor attribution at time of writing. The tool was released as a security research proof-of-concept by CapitalOne's security team. However, the techniques it implements are applicable to:

| Threat Profile | Relevance |
|---|---|
| Financial sector attackers | Databricks is widely used in banking/fintech for data pipelines |
| Cloud-native threat actors | Full API-based; no EDR footprint on cloud infrastructure |
| Insider threat / compromised developer | PAT theft from developer workstation is the most realistic initial access |
| Supply chain attackers | Compromised CI/CD token with Databricks access enables the full chain |

---

## References

- [DBXploit GitHub Repository](https://github.com/capitalone/dbxploit)
- [Databricks Secrets API Documentation](https://docs.databricks.com/api/workspace/secrets)
- [Databricks SCIM API Documentation](https://docs.databricks.com/api/account/users)
- [Databricks Audit Log Reference](https://docs.databricks.com/administration-guide/account-settings/audit-logs.html)

## Related Notes

- [[20 - Areas/Threat Hunting/Hunt - Databricks Credential Abuse and Privilege Escalation|Hunt — Databricks Credential Abuse and Privilege Escalation]]
