---
title: Hunt - Databricks Credential Abuse and Privilege Escalation
date: 2026-03-08
type: hunt
status: active
hypothesis: An attacker with a stolen or low-privilege Databricks PAT is enumerating secret scopes, harvesting credentials, and escalating privileges via the SCIM API using only native REST API calls that blend with normal Databricks SDK and Terraform activity.
priority: high
platform: CrowdStrike, Databricks
mitre_id: T1087.004, T1528, T1134, T1078.004, T1548, T1552.001, T1537, T1213
tags:
  - type/hunt
  - status/active
  - platform/cloud
  - category/credential-access
  - category/privilege-escalation
---

## Hypothesis

*"I believe credential abuse and privilege escalation against Databricks is occurring because many organizations leave secret scope ACLs open to `all users`, have PATs committed to Git or CI/CD pipelines, and do not alert on SCIM role modification events — which would manifest as bulk secret enumeration from an unexpected principal followed by SCIM PUT calls adding admin roles."*

**Why this is worth hunting:**
- Databricks secret scopes are a common repository for cloud credentials, API keys, and database passwords — a breach of a single PAT can cascade to full cloud compromise
- SCIM-based privilege escalation requires only a single API call and leaves minimal forensic trace if audit logging is not configured
- All DBXploit attack steps use native authenticated API calls, meaning there is no malware or EDR signal — detection requires behavioral analysis of audit logs
- Job impersonation can shift blame to victim users in audit logs, obscuring the true attacker identity

## Assumptions & Scope

| Item | Detail |
|---|---|
| Environment | Databricks workspaces with audit log delivery enabled (cloud storage or Splunk/SIEM) |
| Timeframe | Initial hunt: 30 days; ongoing detection: rolling 24h |
| Data sources | Databricks audit logs, CrowdStrike Falcon telemetry (endpoint), network proxy/firewall logs |
| Baseline required | Know your normal secret access patterns (CI/CD service principals, Terraform, scheduled jobs) |
| Blind spots | If audit log delivery is not configured, this hunt cannot proceed — verify first |

## Hunt Plan

1. **Verify audit log collection** — Confirm Databricks audit logs are being ingested. Check for `serviceName` fields: `secrets`, `accounts`, `jobs`, `workspace`. If absent, this is itself a finding (T1562 — Impair Defenses).

2. **Identify bulk secret enumeration** — Query for principals that called `listScopes`, `listSecrets`, `getAcl`, or `getSecret` more than 20 times in an hour. Baseline against known CI/CD service principals. Flag any human user accounts appearing in this list.

3. **Hunt for SCIM role modification** — Query for any `updateUser` or `patchUser` calls in the accounts service that include role modifications. Any addition of `account_admin` or `workspace_admin` outside a known provisioning workflow is a high-severity finding.

4. **Detect job impersonation** — Find job run submissions where `run_as` in the request parameters differs from the authenticating user identity. This pattern should be rare or absent in most environments.

5. **Find token fingerprinting behavior** — Look for `listTokens` or repeated calls to `/api/2.0/preview/scim/v2/Me` from the same principal. This is the DBXploit `whoami.py` behavior — it's the attacker profiling the token before proceeding.

6. **Check for webhook exfiltration** — In network/proxy logs, look for outbound HTTPS from Databricks cluster IPs or Python processes to non-Databricks domains. Correlate timing with any secret access events from the same session.

7. **Correlate across stages** — If any single principal appears across steps 2, 3, 4, or 6 within the same session window (e.g., 1-2 hours), treat as confirmed incident.

## Queries

### CrowdStrike FQL — Databricks CLI/Python Process Spawning DBXploit Patterns

> Parameterized: `40 - Resources/Query Library/queries/hunting/cs-hunt-databricks-privesc.md`

```
// Hunt for endpoint execution of DBXploit or similar Databricks exploitation tooling
event_simpleName=ProcessRollup2
| CommandLine=/dbxploit|secrets_dump|secrets_audit|privilege_escalation|token_hijack/
| table timestamp, ComputerName, UserName, CommandLine, ParentProcessName, SHA256HashData
```

### CrowdStrike FQL — Python Outbound HTTPS to Non-Databricks Domains
```
// Webhook exfiltration: Python making HTTPS connections to unknown external hosts
event_simpleName=NetworkConnectIP4
| ImageFileName=/python3?$/
| RemotePort=443
| NOT DomainName=/.databricks\.com$|.azuredatabricks\.net$|.gcp\.databricks\.com$|.cloud\.databricks\.com$/
| NOT RemoteAddressIP4=/(^10\.)|(^172\.(1[6-9]|2[0-9]|3[01])\.)|(^192\.168\.)/
| stats count BY DomainName, RemoteAddressIP4, ComputerName, UserName
| sort -count
```

### Databricks SQL — Step 2: Bulk Secret Enumeration

> Parameterized: `40 - Resources/Query Library/queries/hunting/db-hunt-databricks-privesc.md`

```sql
-- Identify principals rapidly enumerating secret scopes and keys (DBXploit secrets_audit + secrets_dump pattern)
SELECT
  userIdentity.email                    AS principal,
  userIdentity.userAgent                AS user_agent,
  sourceIPAddress,
  COUNT(*)                              AS api_calls,
  COUNT_IF(actionName = 'listScopes')   AS list_scopes,
  COUNT_IF(actionName = 'listSecrets')  AS list_secrets,
  COUNT_IF(actionName = 'getSecret')    AS get_secrets,
  COUNT_IF(actionName = 'getAcl')       AS get_acls,
  MIN(timestamp)                        AS first_seen,
  MAX(timestamp)                        AS last_seen
FROM databricks_audit_logs
WHERE serviceName = 'secrets'
  AND actionName IN ('listScopes', 'listSecrets', 'getSecret', 'getAcl')
  AND date_trunc('hour', timestamp) >= DATE_SUB(NOW(), 30)
GROUP BY principal, user_agent, sourceIPAddress
HAVING COUNT(*) > 20
  -- Exclude known CI/CD service principals:
  AND principal NOT IN ('terraform-svc@corp.com', 'cicd-bot@corp.com')
ORDER BY api_calls DESC
```

### Databricks SQL — Step 3: SCIM Privilege Escalation Detection
```sql
-- Any SCIM call that modifies user roles — especially account_admin promotion
SELECT
  timestamp,
  userIdentity.email                    AS actor,
  requestParams.targetUserName          AS target_user,
  requestParams.roles                   AS roles_assigned,
  sourceIPAddress,
  userAgent,
  response.statusCode                   AS http_status
FROM databricks_audit_logs
WHERE serviceName = 'accounts'
  AND actionName IN ('updateUser', 'patchUser', 'createUser')
  AND (
    requestParams.roles LIKE '%account_admin%'
    OR requestParams.roles LIKE '%admin%'
  )
ORDER BY timestamp DESC
LIMIT 100
```

### Databricks SQL — Step 4: Job Impersonation (run_as Mismatch)
```sql
-- Jobs submitted where run_as != submitting principal (DBXploit impersonate_job.py)
SELECT
  timestamp,
  userIdentity.email                    AS submitting_principal,
  requestParams.run_as                  AS impersonated_user,
  requestParams.job_id                  AS job_id,
  requestParams.run_name                AS run_name,
  sourceIPAddress,
  userAgent
FROM databricks_audit_logs
WHERE serviceName = 'jobs'
  AND actionName IN ('submitRun', 'runNow')
  AND requestParams.run_as IS NOT NULL
  AND requestParams.run_as != userIdentity.email
ORDER BY timestamp DESC
```

### Databricks SQL — Step 5: Token Fingerprinting Behavior
```sql
-- Repeated token identity lookups — attacker profiling tokens (DBXploit whoami.py)
SELECT
  userIdentity.email                    AS principal,
  sourceIPAddress,
  COUNT(*)                              AS whoami_calls,
  MIN(timestamp)                        AS first_call,
  MAX(timestamp)                        AS last_call
FROM databricks_audit_logs
WHERE serviceName IN ('token', 'accounts')
  AND actionName IN ('listTokens', 'getUser', 'listUsers')
  AND date_trunc('hour', timestamp) >= DATE_SUB(NOW(), 4)
GROUP BY principal, sourceIPAddress
HAVING COUNT(*) > 5
ORDER BY whoami_calls DESC
```

### Databricks SQL — Step 7: Cross-Stage Correlation (Full Attack Chain)
```sql
-- Identify principals appearing across multiple attack stages within a 2-hour window
WITH secret_enum AS (
  SELECT userIdentity.email AS principal, MIN(timestamp) AS stage_time, 'secret_enum' AS stage
  FROM databricks_audit_logs
  WHERE serviceName = 'secrets' AND actionName IN ('listScopes', 'getSecret')
  GROUP BY principal HAVING COUNT(*) > 10
),
scim_privesc AS (
  SELECT userIdentity.email AS principal, MIN(timestamp) AS stage_time, 'scim_privesc' AS stage
  FROM databricks_audit_logs
  WHERE serviceName = 'accounts' AND actionName IN ('updateUser', 'patchUser')
  GROUP BY principal
),
job_impersonate AS (
  SELECT userIdentity.email AS principal, MIN(timestamp) AS stage_time, 'job_impersonate' AS stage
  FROM databricks_audit_logs
  WHERE serviceName = 'jobs' AND actionName = 'submitRun' AND requestParams.run_as != userIdentity.email
  GROUP BY principal
)
SELECT principal, COLLECT_LIST(stage) AS attack_stages, COUNT(DISTINCT stage) AS stage_count
FROM (
  SELECT * FROM secret_enum
  UNION ALL SELECT * FROM scim_privesc
  UNION ALL SELECT * FROM job_impersonate
)
GROUP BY principal
HAVING stage_count >= 2
ORDER BY stage_count DESC
```

## Findings

### Hits

*Populate during hunt execution.*

| Date | Principal | Source IP | Stages Observed | Severity |
|---|---|---|---|---|
| — | — | — | — | — |

### False Positives / Tuning Notes

| Source | Expected Behavior | Exclusion |
|---|---|---|
| Terraform service principal | `listScopes` on deploy cycles; `getSecret` for variable injection | Exclude `terraform-svc@corp.com` by principal |
| CI/CD bot (GitHub Actions, Jenkins) | Bulk secret reads on pipeline runs | Exclude known service account emails |
| Databricks SDK development/testing | Developers iterating against dev workspace | Scope hunt to production workspace IDs |
| Databricks Terraform provider | May call SCIM APIs for user provisioning during workspace setup | Validate against known provisioning windows |
| Job scheduler service accounts | May submit jobs with `run_as` for service impersonation patterns | Document expected `run_as` patterns and exclude |

## Outcome

- [ ] No evidence found — environment appears clean for this technique
- [ ] Suspicious activity found — escalate for IR investigation
- [ ] Detection rule created — promoted to production alerting

## Related Notes

- [[30 - Knowledge/Cybersecurity/Attack Techniques/Databricks API Abuse and Privilege Escalation|TTP Note — Databricks API Abuse and Privilege Escalation]]
- [[30 - Knowledge/Cybersecurity/Malware & TTPs/DBXploit Databricks Exploitation - Research Extraction|Research Extraction — DBXploit Databricks Exploitation]]
- [[20 - Areas/Detection Engineering/Detections|Detection Engineering]]
