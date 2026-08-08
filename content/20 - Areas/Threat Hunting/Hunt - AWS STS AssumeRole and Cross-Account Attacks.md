---
title: Hunt - AWS STS AssumeRole and Cross-Account Attacks
date: 2026-03-13
type: hunt
status: active
hypothesis: A threat actor is abusing AWS STS to maintain persistent access via role chain juggling, pivot across accounts via misconfigured trust policies or the default OrganizationAccountAccessRole, or survive incident response via GetFederationToken — which would manifest as repeated AssumeRole calls from the same identity, cross-account role assumptions from unexpected source accounts, OrganizationAccountAccessRole assumptions from non-automation principals, or GetFederationToken calls with high-privilege policy ARNs.
priority: high
platform: [CrowdStrike, Databricks]
mitre_id: T1078.004, T1548, T1550.001, T1134
tags:
  - type/hunt
  - status/active
  - platform/aws
  - category/lateral-movement
  - category/privilege-escalation
  - category/persistence
  - category/sts
---

## Hypothesis

> I believe a threat actor is exploiting AWS STS role assumption to maintain persistent access or pivot across AWS accounts — because role chaining refreshes credential expiration without creating new IAM resources, the default `OrganizationAccountAccessRole` provides a path from any management account compromise to all member accounts, and `GetFederationToken` creates credentials that survive access key deletion — which would manifest as high-frequency repeated AssumeRole calls, assumptions of the `OrganizationAccountAccessRole` outside known automation windows, cross-account assumptions from external or unexpected source accounts, or `GetFederationToken` calls with `AdministratorAccess` policy attached.

**Why this is worth hunting:**
- Role chain juggling creates **no IAM modification events** — no new users, no new keys, no policy changes
- `OrganizationAccountAccessRole` is present by default in every member account — exploiting it requires zero setup
- `GetFederationToken` tokens **survive access key deletion** — a critical gap in IR playbooks that don't explicitly invalidate sessions
- Cross-account AssumeRole from external accounts is a legitimate feature used by vendors and partners — blends into normal traffic
- `AssumeRole` from a wildcard trust policy (`Principal: *`) can come from **any AWS account globally**

---

## Assumptions & Scope
- Environment: AWS CloudTrail (management events), AWS Config (IAM trust policy audit)
- Timeframe: Rolling 30 days
- Data sources:
  - CloudTrail — `AssumeRole`, `GetFederationToken`, `GetCallerIdentity` (all management events, always logged)
  - AWS Config — trust policy configuration history
  - GuardDuty — anomaly-based credential usage findings

---

## Hunt Plan

1. **Hunt for role chain juggling — repeated AssumeRole of same role**
   Flag identities assuming the same role more than 3 times in 24 hours — this is the signature of continuous credential refresh.

2. **Hunt for OrganizationAccountAccessRole assumptions**
   Any assumption of this role outside known automation roles is high-priority. In most environments, only specific deployment pipelines should assume this role.

3. **Hunt for cross-account AssumeRole from unexpected source accounts**
   `AssumeRole` where the source account ID doesn't match any account in the organization — or where the source account is external and unexpected.

4. **Hunt for GetFederationToken with high-privilege policies**
   `GetFederationToken` combined with `AdministratorAccess` or `PowerUserAccess` policy ARNs is unusual and warrants investigation.

5. **Hunt for GetCallerIdentity as first event from new credentials**
   `GetCallerIdentity` is the standard credential validation call. A session's first event being `GetCallerIdentity` from a previously unseen source IP is a signal of new/stolen credential usage.

6. **Audit trust policies for wildcard principals**
   Query IAM or AWS Config for roles with `"Principal": {"AWS": "*"}` — these are universally exploitable from any AWS account.

---

## Queries

### CrowdStrike FQL

> Parameterized: `40 - Resources/Query Library/queries/hunting/cs-hunt-sts-assume-role.md`

```fql
// All AssumeRole events
event_simpleName=CloudTrailEvent
| EventName=AssumeRole
| table _time, UserIdentityArn, RequestParameters, SourceIPAddress, AWSRegion

// Role chain juggling — same role assumed repeatedly
event_simpleName=CloudTrailEvent
| EventName=AssumeRole
| stats count(_time) as assume_count by UserIdentityArn, RequestParameters.roleArn
| where assume_count > 3
| sort -assume_count

// OrganizationAccountAccessRole assumption
event_simpleName=CloudTrailEvent
| EventName=AssumeRole
| RequestParameters.roleArn=*OrganizationAccountAccessRole*
| table _time, UserIdentityArn, RequestParameters, SourceIPAddress

// GetFederationToken with high-privilege policy
event_simpleName=CloudTrailEvent
| EventName=GetFederationToken
| RequestParameters.policyArns=*AdministratorAccess*
| table _time, UserIdentityArn, RequestParameters, SourceIPAddress

// GetCallerIdentity — credential validation (first action of stolen cred)
event_simpleName=CloudTrailEvent
| EventName=GetCallerIdentity
| table _time, UserIdentityArn, SourceIPAddress, UserAgent
```

### Databricks SQL

> Parameterized: `40 - Resources/Query Library/queries/hunting/db-hunt-sts-assume-role.md`

```sql
-- All STS events — broad visibility
SELECT
  event_time,
  user_identity_arn,
  event_name,
  request_parameters,
  source_ip_address,
  aws_region
FROM cloudtrail_events
WHERE event_name IN (
  'AssumeRole',
  'AssumeRoleWithWebIdentity',
  'AssumeRoleWithSAML',
  'GetFederationToken',
  'GetCallerIdentity',
  'GetSessionToken'
)
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
ORDER BY event_time DESC;

-- Role chain juggling — repeated AssumeRole of same role
SELECT
  user_identity_arn,
  JSON_EXTRACT_SCALAR(request_parameters, '$.roleArn') AS assumed_role,
  COUNT(*) AS assume_count,
  MIN(event_time) AS first_seen,
  MAX(event_time) AS last_seen
FROM cloudtrail_events
WHERE event_name = 'AssumeRole'
  AND event_time >= CURRENT_DATE - INTERVAL 24 HOURS
GROUP BY 1, 2
HAVING assume_count > 3
ORDER BY assume_count DESC;

-- OrganizationAccountAccessRole assumptions
SELECT
  event_time,
  user_identity_arn,
  JSON_EXTRACT_SCALAR(request_parameters, '$.roleArn') AS assumed_role,
  source_ip_address,
  JSON_EXTRACT_SCALAR(user_identity, '$.accountId') AS source_account
FROM cloudtrail_events
WHERE event_name = 'AssumeRole'
  AND request_parameters LIKE '%OrganizationAccountAccessRole%'
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
ORDER BY event_time DESC;

-- GetFederationToken with high-privilege policy (persistence before key deletion)
SELECT
  event_time,
  user_identity_arn,
  request_parameters,
  source_ip_address
FROM cloudtrail_events
WHERE event_name = 'GetFederationToken'
  AND (
    request_parameters LIKE '%AdministratorAccess%'
    OR request_parameters LIKE '%PowerUser%'
    OR request_parameters LIKE '%FullAccess%'
  )
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
ORDER BY event_time DESC;

-- Cross-account AssumeRole — source account not in org (potential external attacker)
SELECT
  event_time,
  user_identity_arn,
  JSON_EXTRACT_SCALAR(request_parameters, '$.roleArn') AS assumed_role,
  JSON_EXTRACT_SCALAR(user_identity, '$.accountId') AS source_account,
  source_ip_address
FROM cloudtrail_events
WHERE event_name = 'AssumeRole'
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
  -- Tune: replace with your known account IDs
  AND JSON_EXTRACT_SCALAR(user_identity, '$.accountId') NOT IN (
    '111111111111', '222222222222'  -- known org account IDs
  )
ORDER BY event_time DESC;

-- GetCallerIdentity as first-ever event from credential (new/stolen cred signal)
SELECT
  event_time,
  user_identity_arn,
  source_ip_address,
  user_agent
FROM cloudtrail_events
WHERE event_name = 'GetCallerIdentity'
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
  AND user_identity_arn NOT IN (
    -- exclude known monitoring/automation that regularly calls this
    SELECT DISTINCT user_identity_arn
    FROM cloudtrail_events
    WHERE event_name = 'GetCallerIdentity'
      AND event_time < CURRENT_DATE - INTERVAL 30 DAYS
  )
ORDER BY event_time DESC;
```

---

## Findings

### Hits
-

### False Positives / Tuning Notes
- Legitimate vendor cross-account access — document expected external account IDs and exclude them
- CI/CD pipelines use `AssumeRole` frequently — baseline by pipeline role ARN; chain juggling is unusual even for CI/CD
- `OrganizationAccountAccessRole` may be assumed by legitimate DevOps automation — document known role ARNs that should use this
- `GetCallerIdentity` is called by legitimate SDK integrations for health checks — establish baseline of expected callers
- Some monitoring tools (Datadog, Lacework, etc.) call `AssumeRole` into member accounts — document these cross-account roles

---

## Outcome
- [ ] No evidence found — hypothesis closed
- [ ] Suspicious activity found — escalated to investigation
- [ ] Detection rule created → [[link to rule]]

## Related Notes
- [[AWS STS AssumeRole and Cross-Account Attacks]] — TTP note with full technique breakdown
- [[AWS STS AssumeRole and Cross-Account Attacks]] — full TTP note with technical reference and all attack chains
- [[Hunt - AWS IAM Privilege Escalation]] — IAM privesc enabling role assumption
- [[Hunt - AWS SSM Lateral Movement]] — post-AssumeRole execution via SSM
- [[40 - Resources/Query Library/Hunt Queries]]
- [[20 - Areas/Detection Engineering/Detections]]
