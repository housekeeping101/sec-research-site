---
title: Hunt - AWS Secrets Manager Credential Harvesting
date: 2026-03-13
type: hunt
status: active
hypothesis: A threat actor with escalated IAM privileges is enumerating and bulk-retrieving secrets from Secrets Manager and/or SSM Parameter Store — which would manifest as ListSecrets or DescribeParameters calls from identities with no prior history in these services, followed by high-volume GetSecretValue or GetParametersByPath calls if data event logging is enabled.
priority: high
platform: [CrowdStrike, Databricks]
mitre_id: T1552.001, T1555, T1083
tags:
  - type/hunt
  - status/active
  - platform/aws
  - category/credential-access
  - category/secrets
---

## Hypothesis

> I believe a threat actor with escalated IAM permissions is harvesting credentials stored in Secrets Manager and SSM Parameter Store — because these services are the primary credential repositories in AWS environments and the actual retrieval calls (GetSecretValue, GetParameter) are CloudTrail data events not logged by default, creating a detection blind spot — which would manifest as enumeration calls from unexpected identities (ListSecrets, DescribeSecret, DescribeParameters) and, where data events are enabled, bulk GetSecretValue or GetParametersByPath calls in a short window.

**Why this is worth hunting:**
- `GetSecretValue` and `GetParameter` are data events — **not logged in CloudTrail by default** in most environments
- Even without data event logging, enumeration calls (`ListSecrets`, `DescribeParameters`) are management events and ARE logged — these signal intent
- Secrets Manager often contains DB credentials, API keys, and cross-account tokens — high lateral movement value
- Bulk secret dumps happen fast (seconds to minutes) — a narrow detection window
- IAM privesc followed by secrets enumeration is a well-established attack chain

---

## Assumptions & Scope
- Environment: AWS CloudTrail (management events), CloudTrail data events for Secrets Manager and SSM if enabled
- Timeframe: Rolling 30 days
- Data sources:
  - CloudTrail management events — `ListSecrets`, `DescribeSecret`, `DescribeParameters` (always available)
  - CloudTrail data events — `GetSecretValue`, `GetParameter`, `GetParametersByPath` (only if explicitly enabled)
  - GuardDuty — anomaly-based findings for unusual secret access
  - AWS Config — identify which accounts/environments lack data event logging (detection gap mapping)

---

## Hunt Plan

1. **Hunt for Secrets Manager enumeration from new/unexpected identities**
   `ListSecrets` and bulk `DescribeSecret` calls from identities with no historical Secrets Manager activity. Flag especially when preceded by IAM escalation events in the same session.

2. **Hunt for bulk GetSecretValue (if data events enabled)**
   Identify identities accessing more than a threshold number of distinct secrets in a single hour. Normal application access is typically to 1-3 specific secrets.

3. **Hunt for Parameter Store full-path dump**
   `GetParametersByPath` with `--path /` and `--recursive` is not a normal application pattern — it dumps all parameters. Flag any occurrence.

4. **Hunt for IAM escalation → secrets access correlation**
   Join IAM modification events with secrets enumeration events within a 60-minute window from the same identity. This cross-stage correlation is a high-fidelity signal.

5. **Identify accounts missing data event logging (coverage gap)**
   Query CloudTrail configuration — if `GetSecretValue` and `GetParameter` data events are not enabled, document the blind spot and recommend remediation.

---

## Queries

### CrowdStrike FQL

> Parameterized: `40 - Resources/Query Library/queries/hunting/cs-hunt-secrets-harvesting.md`

```fql
// Secrets Manager enumeration — ListSecrets from unexpected identity
event_simpleName=CloudTrailEvent
| EventName=ListSecrets
| table _time, UserIdentityArn, SourceIPAddress, AWSRegion

// Bulk DescribeSecret — enumeration pattern (>10 calls)
event_simpleName=CloudTrailEvent
| EventName=DescribeSecret
| stats count(_time) as call_count by UserIdentityArn
| where call_count > 10
| sort -call_count

// GetSecretValue bulk access (data events must be enabled)
event_simpleName=CloudTrailEvent
| EventName=GetSecretValue
| stats count(_time) as access_count by UserIdentityArn
| where access_count > 5
| sort -access_count

// Parameter Store full dump
event_simpleName=CloudTrailEvent
| EventName=GetParametersByPath
| table _time, UserIdentityArn, RequestParameters, SourceIPAddress
```

### Databricks SQL

> Parameterized: `40 - Resources/Query Library/queries/hunting/db-hunt-secrets-harvesting.md`

```sql
-- Secrets enumeration events — all types, last 30 days
SELECT
  event_time,
  user_identity_arn,
  event_name,
  source_ip_address,
  aws_region
FROM cloudtrail_events
WHERE event_name IN (
  'ListSecrets',
  'DescribeSecret',
  'GetSecretValue',
  'ListSecretVersionIds',
  'DescribeParameters',
  'GetParameter',
  'GetParameters',
  'GetParametersByPath'
)
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
ORDER BY event_time DESC;

-- Identities with first-ever Secrets Manager access (new baseline)
SELECT
  user_identity_arn,
  MIN(event_time) AS first_secrets_access,
  COUNT(*) AS total_calls
FROM cloudtrail_events
WHERE event_name IN ('ListSecrets', 'DescribeSecret', 'GetSecretValue')
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
GROUP BY 1
ORDER BY first_secrets_access DESC;

-- Bulk GetSecretValue per identity per hour (data events required)
SELECT
  DATE_TRUNC('hour', event_time) AS hour,
  user_identity_arn,
  COUNT(*) AS secret_access_count
FROM cloudtrail_events
WHERE event_name = 'GetSecretValue'
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
GROUP BY 1, 2
HAVING secret_access_count > 5
ORDER BY secret_access_count DESC;

-- IAM escalation → secrets access within 60 minutes (kill chain correlation)
WITH iam_events AS (
  SELECT user_identity_arn, event_time AS iam_time
  FROM cloudtrail_events
  WHERE event_name IN (
    'AttachUserPolicy','AttachRolePolicy','CreateAccessKey',
    'PutUserPolicy','CreatePolicy','SetDefaultPolicyVersion'
  )
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
),
secrets_events AS (
  SELECT user_identity_arn, event_time AS secret_time
  FROM cloudtrail_events
  WHERE event_name IN ('ListSecrets','GetSecretValue','GetParametersByPath')
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
)
SELECT
  i.user_identity_arn,
  i.iam_time AS iam_escalation_time,
  s.secret_time AS secrets_access_time,
  DATEDIFF('minute', i.iam_time, s.secret_time) AS minutes_between
FROM iam_events i
JOIN secrets_events s ON i.user_identity_arn = s.user_identity_arn
WHERE s.secret_time > i.iam_time
  AND DATEDIFF('minute', i.iam_time, s.secret_time) <= 60
ORDER BY minutes_between;

-- Parameter Store full dump pattern
SELECT
  event_time,
  user_identity_arn,
  event_name,
  request_parameters,
  source_ip_address
FROM cloudtrail_events
WHERE event_name = 'GetParametersByPath'
  AND (
    request_parameters LIKE '%"path":"/",%'
    OR request_parameters LIKE '%recursive%'
  )
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
ORDER BY event_time DESC;
```

---

## Findings

### Hits
-

### False Positives / Tuning Notes
- CI/CD pipelines legitimately access specific secrets at deploy time — baseline by role ARN and secret name; flag access to secrets outside expected list
- AWS Lambda functions commonly call `GetSecretValue` at cold start — establish per-function baselines
- `ListSecrets` is called by some monitoring tools — document and exclude known monitoring role ARNs
- `DescribeParameters` is called by AWS SSM inventory — distinguish from bulk enumeration by call volume

---

## Outcome
- [ ] No evidence found — hypothesis closed
- [ ] Suspicious activity found — escalated to investigation
- [ ] Detection rule created → [[link to rule]]

## Related Notes
- [[AWS Secrets Manager and Parameter Store Attacks]] — TTP note with full technique breakdown
- [[AWS Secrets Manager and Parameter Store Attacks]] — full TTP note with technical reference and attack chains
- [[Hunt - AWS IAM Privilege Escalation]] — IAM privesc enabling secrets access
- [[Hunt - EC2 IMDS Credential Theft]] — IMDS credential theft enabling secrets access
- [[40 - Resources/Query Library/Hunt Queries]]
- [[20 - Areas/Detection Engineering/Detections]]
