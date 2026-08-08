---
title: Hunt - AWS SSM Lateral Movement
date: 2026-03-13
type: hunt
status: active
hypothesis: A threat actor with escalated IAM permissions is using AWS SSM to execute commands on EC2 instances or open interactive shell sessions — bypassing traditional network controls — which would manifest as SendCommand or StartSession events from unexpected identities, bulk instance targeting, or SSM usage from identities/IPs with no prior SSM history.
priority: high
platform: [CrowdStrike, Databricks]
mitre_id: T1651, T1021, T1059.009
tags:
  - type/hunt
  - status/active
  - platform/aws
  - category/lateral-movement
  - category/execution
  - category/ssm
---

## Hypothesis

> I believe a threat actor with valid AWS IAM credentials is using SSM Run Command or Session Manager to execute commands on EC2 instances without opening network ports or SSH — because SSM requires only IAM permissions, command content is hidden from CloudTrail, and most environments lack host-based detection for SSM-spawned processes — which would manifest as SendCommand or StartSession from unexpected IAM identities, SSM commands issued to multiple instances in a short window, or Session Manager sessions from source IPs inconsistent with normal operator geography.

**Why this is worth hunting:**
- `SendCommand` command content is **explicitly redacted** in CloudTrail — `HIDDEN_DUE_TO_SECURITY_REASONS`
- `StartSession` provides a full interactive shell with no network exposure requirement
- SSM bypasses security group rules, NACLs, and bastion host controls entirely
- No key pair or SSH is required — IAM credentials are the only prerequisite
- Port forwarding via SSM can expose internal databases/services without security group modifications
- Session content logging (to S3/CloudWatch) is optional and often not configured

---

## Assumptions & Scope
- Environment: AWS CloudTrail (management events), CrowdStrike Falcon (endpoint telemetry on EC2)
- Timeframe: Rolling 30 days
- Data sources:
  - CloudTrail — `SendCommand`, `StartSession`, `DescribeInstanceInformation` (management events, always logged)
  - CrowdStrike Falcon — process execution on EC2 instances (amazon-ssm-agent child processes)
  - CloudWatch / S3 — Session Manager session logs (if configured)

---

## Hunt Plan

1. **Hunt for SSM recon — DescribeInstanceInformation from unexpected identities**
   This is the enumeration step — an attacker maps which instances are SSM-managed before executing commands. Flag from identities with no SSM history.

2. **Hunt for SendCommand outside known automation identities**
   `SendCommand` from any IAM identity that isn't a known deployment pipeline, patch management role, or operations role is suspicious.

3. **Hunt for SSM lateral movement sweep — multiple instances targeted**
   Attackers often target many instances rapidly. Flag `SendCommand` reaching more than 3 distinct instances from the same identity in a short window.

4. **Hunt for Session Manager from unexpected source IPs**
   `StartSession` from a source IP outside known VPN ranges, corporate egress IPs, or AWS IP space warrants investigation.

5. **Hunt for alternative SSM documents (denylist bypass)**
   `SendCommand` using `AWS-RunDocument`, `AWS-RunRemoteScript`, or `AWS-ApplyAnsiblePlaybooks` may indicate bypass of a `AWS-RunShellScript` restriction.

6. **Hunt for absence of session logging on targeted instances**
   Identify `StartSession` events to instances where `ssm:SessionManagerRunShell` document logging to S3/CloudWatch is not configured — visibility gap.

---

## Queries

### CrowdStrike FQL

> Parameterized: `40 - Resources/Query Library/queries/hunting/cs-hunt-ssm-lateral-movement.md`

```fql
// SSM recon — DescribeInstanceInformation
event_simpleName=CloudTrailEvent
| EventName=DescribeInstanceInformation
| table _time, UserIdentityArn, SourceIPAddress, AWSRegion

// SendCommand from unexpected identity
event_simpleName=CloudTrailEvent
| EventName=SendCommand
| table _time, UserIdentityArn, RequestParameters, SourceIPAddress

// Session Manager shell opened
event_simpleName=CloudTrailEvent
| EventName=StartSession
| table _time, UserIdentityArn, RequestParameters, SourceIPAddress

// Lateral sweep — SendCommand to many instances
event_simpleName=CloudTrailEvent
| EventName=SendCommand
| stats dc(RequestParameters.instanceIds) as instances_targeted by UserIdentityArn
| where instances_targeted > 3
| sort -instances_targeted

// Alternative SSM document usage (potential denylist bypass)
event_simpleName=CloudTrailEvent
| EventName=SendCommand
| RequestParameters.documentName IN (
    "AWS-RunDocument",
    "AWS-RunRemoteScript",
    "AWS-ApplyAnsiblePlaybooks",
    "AWS-RunAnsiblePlaybook"
  )
| table _time, UserIdentityArn, RequestParameters, SourceIPAddress
```

### Databricks SQL

> Parameterized: `40 - Resources/Query Library/queries/hunting/db-hunt-ssm-lateral-movement.md`

```sql
-- All SSM execution and recon events
SELECT
  event_time,
  user_identity_arn,
  event_name,
  request_parameters,
  source_ip_address,
  aws_region
FROM cloudtrail_events
WHERE event_name IN (
  'DescribeInstanceInformation',
  'SendCommand',
  'StartSession',
  'TerminateSession',
  'ListCommandInvocations'
)
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
ORDER BY event_time DESC;

-- SSM lateral sweep — multiple instances targeted by same identity
SELECT
  DATE_TRUNC('hour', event_time) AS hour,
  user_identity_arn,
  COUNT(*) AS command_count
FROM cloudtrail_events
WHERE event_name = 'SendCommand'
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
GROUP BY 1, 2
HAVING command_count > 3
ORDER BY command_count DESC;

-- Alternative SSM document usage (denylist bypass)
SELECT
  event_time,
  user_identity_arn,
  JSON_EXTRACT_SCALAR(request_parameters, '$.documentName') AS document_used,
  source_ip_address
FROM cloudtrail_events
WHERE event_name = 'SendCommand'
  AND JSON_EXTRACT_SCALAR(request_parameters, '$.documentName') NOT IN (
    'AWS-RunShellScript',
    'AWS-RunPowerShellScript'
  )
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
ORDER BY event_time DESC;

-- StartSession from unexpected source IPs (tune with known VPN/corporate ranges)
SELECT
  event_time,
  user_identity_arn,
  JSON_EXTRACT_SCALAR(request_parameters, '$.target') AS target_instance,
  source_ip_address
FROM cloudtrail_events
WHERE event_name = 'StartSession'
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
  -- Exclude known operator IP ranges:
  -- AND source_ip_address NOT LIKE '10.%'
ORDER BY event_time DESC;

-- IAM credential theft → SSM execution correlation (within 2 hours)
WITH credential_theft AS (
  SELECT user_identity_arn, event_time AS theft_time
  FROM cloudtrail_events
  WHERE event_name IN (
    'GetSecretValue', 'GetParameter', 'CreateAccessKey', 'AssumeRole'
  )
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
),
ssm_exec AS (
  SELECT user_identity_arn, event_time AS exec_time
  FROM cloudtrail_events
  WHERE event_name IN ('SendCommand', 'StartSession')
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
)
SELECT
  c.user_identity_arn,
  c.theft_time,
  s.exec_time,
  DATEDIFF('minute', c.theft_time, s.exec_time) AS minutes_between
FROM credential_theft c
JOIN ssm_exec s ON c.user_identity_arn = s.user_identity_arn
WHERE s.exec_time > c.theft_time
  AND DATEDIFF('minute', c.theft_time, s.exec_time) <= 120
ORDER BY minutes_between;
```

---

## Findings

### Hits
-

### False Positives / Tuning Notes
- Patch management (AWS Systems Manager Patch Manager) uses `SendCommand` with `AWS-RunPatchBaseline` — baseline by document name and schedule
- AWS Config automation uses `SendCommand` — document known automation role ARNs
- DevOps teams using `StartSession` for legitimate troubleshooting — baseline by team IP ranges
- `DescribeInstanceInformation` is called by monitoring tools (Datadog, New Relic, etc.) — establish known monitoring role baselines

---

## Outcome
- [ ] No evidence found — hypothesis closed
- [ ] Suspicious activity found — escalated to investigation
- [ ] Detection rule created → [[link to rule]]

## Related Notes
- [[AWS SSM Lateral Movement and Command Execution]] — TTP note with full technique breakdown
- [[AWS SSM Lateral Movement and Command Execution]] — full TTP note with technical reference and SSM document bypass table
- [[Hunt - AWS IAM Privilege Escalation]] — IAM privesc enabling SSM access
- [[Hunt - AWS STS AssumeRole and Cross-Account Attacks]] — cross-account SSM execution
- [[40 - Resources/Query Library/Hunt Queries]]
- [[20 - Areas/Detection Engineering/Detections]]
