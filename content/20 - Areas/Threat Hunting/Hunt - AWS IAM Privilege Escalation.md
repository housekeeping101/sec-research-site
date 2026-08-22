---
title: Hunt - AWS IAM Privilege Escalation
date: 2026-03-08
type: hunt
status: active
hypothesis: A threat actor with initial AWS access is abusing IAM permissions to escalate privileges to administrator, which would manifest as unexpected IAM policy modifications, PassRole events to unusual services, or access key creation targeting other users.
priority: high
platform: [CrowdStrike, Databricks]
mitre_id: T1078.004, T1548, T1098, T1136.003
tags:
  - type/hunt
  - status/active
  - platform/aws
  - category/privilege-escalation
  - category/iam
---

## Hypothesis

> I believe a threat actor with low-privilege AWS access is abusing misconfigured IAM permissions to escalate to administrator because PassRole misconfigurations and overly broad IAM permissions are extremely common in AWS environments, which would manifest as unexpected IAM modification events, Lambda/ECS/Glue resource creation by unusual identities, or access key creation targeting accounts other than the caller's own.

**Why this is worth hunting:**
- IAM misconfiguration is endemic — most AWS environments have unintentional privesc paths discoverable by PMapper
- Escalation events often look like legitimate admin activity and don't trigger default GuardDuty alerts
- The blast radius of a successful escalation is total account compromise
- CloudTrail captures every IAM API call — high-fidelity data source with low noise if scoped correctly

---

## Assumptions & Scope
- Environment: AWS CloudTrail logs ingested into Databricks / CrowdStrike
- Timeframe: Rolling 30 days
- Data sources available:
  - CloudTrail — all management events (IAM, STS, Lambda, EC2, ECS, Glue)
  - AWS Config — resource configuration history
  - GuardDuty findings (supplemental)

---

## Hunt Plan

1. **Baseline IAM modification activity**
   Identify which identities normally perform IAM write operations in the environment. Any identity outside this baseline performing IAM modifications is a high-priority lead.

2. **Hunt for direct escalation actions**
   Query for the specific API calls that directly grant elevated permissions: `AttachUserPolicy`, `AttachRolePolicy`, `PutUserPolicy`, `CreatePolicyVersion`, `SetDefaultPolicyVersion`, `DeleteRolePermissionsBoundary`, `UpdateAssumeRolePolicy`.

3. **Hunt for PassRole to services**
   `iam:PassRole` combined with service creation events (Lambda, ECS, Glue, CloudFormation, EC2) from the same identity within a short window is the most common escalation pattern.

4. **Hunt for access key creation targeting other users**
   `CreateAccessKey` where the target username differs from the caller is a direct identity takeover signal.

5. **Hunt for permission boundary removal**
   `DeleteRolePermissionsBoundary` and `DeleteUserPermissionsBoundary` are rare operations — any occurrence warrants review.

6. **Correlate with prior access patterns**
   For any hits, check if the identity performed any unusual enumeration beforehand (`iam:ListPolicies`, `iam:SimulatePrincipalPolicy`, `iam:GetPolicy`) — this suggests deliberate reconnaissance.

---

## Queries

### CrowdStrike FQL

> Parameterized: `40 - Resources/Query Library/queries/hunting/cs-hunt-iam-privesc.md`

```fql
// Direct IAM escalation actions
event_simpleName=CloudTrailEvent
| EventName IN (
    "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy",
    "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy",
    "CreatePolicyVersion", "SetDefaultPolicyVersion",
    "DeleteRolePermissionsBoundary", "DeleteUserPermissionsBoundary",
    "UpdateAssumeRolePolicy", "AddUserToGroup"
  )
| table _time, UserIdentityArn, EventName, RequestParameters, SourceIPAddress

// PassRole events — identify service escalation setup
event_simpleName=CloudTrailEvent
| EventName="PassRole"
| table _time, UserIdentityArn, RequestParameters, SourceIPAddress

// CreateAccessKey against a different user (identity takeover)
event_simpleName=CloudTrailEvent
| EventName="CreateAccessKey"
| eval target_user=RequestParameters.userName
| eval caller=UserIdentityArn
| NOT caller=*target_user*
| table _time, caller, target_user, SourceIPAddress

// IAM enumeration recon before escalation
event_simpleName=CloudTrailEvent
| EventName IN ("ListPolicies", "SimulatePrincipalPolicy", "GetPolicy", "ListAttachedUserPolicies")
| table _time, UserIdentityArn, EventName, SourceIPAddress
| sort _time asc

// GUI-Vil-style stealth takeover: CreateLoginProfile on a PRE-EXISTING user (not one created moments earlier)
event_simpleName=CloudTrailEvent
| EventName="CreateLoginProfile"
| join field=UserIdentityArn
    [ search event_simpleName=CloudTrailEvent EventName="CreateUser"
      | rename UserName as NewUserName ]
| NOT RequestParameters.userName=NewUserName
| table _time, UserIdentityArn, RequestParameters.userName, SourceIPAddress

// Known real-world attacker user agent (GUI-Vil)
event_simpleName=CloudTrailEvent
| UserAgent="*S3 Browser*"
| table _time, UserIdentityArn, EventName, UserAgent, SourceIPAddress

// New IAM usernames matching known attacker naming conventions
event_simpleName=CloudTrailEvent
| EventName="CreateUser"
| RequestParameters.userName IN ("backup", "sec_audit", "administrateurs") OR RequestParameters.userName="aws_dev*" OR RequestParameters.userName="aws-cli*"
| table _time, UserIdentityArn, RequestParameters.userName, SourceIPAddress
```

### Databricks SQL

> Parameterized: `40 - Resources/Query Library/queries/hunting/db-hunt-iam-privesc.md`

```sql
-- All direct IAM escalation actions (30 days)
SELECT
  event_time,
  user_identity_arn,
  event_name,
  request_parameters,
  source_ip_address,
  aws_region
FROM cloudtrail_events
WHERE event_name IN (
  'AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy',
  'PutUserPolicy', 'PutRolePolicy', 'PutGroupPolicy',
  'CreatePolicyVersion', 'SetDefaultPolicyVersion',
  'DeleteRolePermissionsBoundary', 'DeleteUserPermissionsBoundary',
  'UpdateAssumeRolePolicy', 'AddUserToGroup'
)
AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
ORDER BY event_time DESC;

-- PassRole followed by service creation (same identity, same hour)
WITH passrole AS (
  SELECT event_time, user_identity_arn, request_parameters
  FROM cloudtrail_events
  WHERE event_name = 'PassRole'
),
service_create AS (
  SELECT event_time, user_identity_arn, event_name
  FROM cloudtrail_events
  WHERE event_name IN (
    'CreateFunction20150331', 'UpdateFunctionCode20150331v2',
    'RunInstances', 'RunTask', 'CreateStack',
    'CreateJob', 'CreatePipeline'
  )
)
SELECT
  p.user_identity_arn,
  p.event_time AS passrole_time,
  s.event_name AS service_action,
  s.event_time AS service_time
FROM passrole p
JOIN service_create s
  ON p.user_identity_arn = s.user_identity_arn
  AND s.event_time BETWEEN p.event_time AND p.event_time + INTERVAL 1 HOUR
ORDER BY passrole_time DESC;

-- CreateAccessKey targeting a different user
SELECT
  event_time,
  user_identity_arn AS caller,
  JSON_EXTRACT_SCALAR(request_parameters, '$.userName') AS target_user,
  source_ip_address
FROM cloudtrail_events
WHERE event_name = 'CreateAccessKey'
  AND JSON_EXTRACT_SCALAR(request_parameters, '$.userName') IS NOT NULL
  AND NOT user_identity_arn LIKE CONCAT('%', JSON_EXTRACT_SCALAR(request_parameters, '$.userName'), '%')
ORDER BY event_time DESC;

-- Real-world IOC-based detections (GUI-Vil / DataDog case studies)

-- Known attacker user agent (GUI-Vil's S3 Browser)
SELECT event_time, user_identity_arn, event_name, user_agent, source_ip_address
FROM cloudtrail_events
WHERE user_agent LIKE '%S3 Browser%'
ORDER BY event_time DESC;

-- New IAM usernames matching known attacker naming conventions
SELECT event_time, user_identity_arn, JSON_EXTRACT_SCALAR(request_parameters, '$.userName') AS new_user, source_ip_address
FROM cloudtrail_events
WHERE event_name = 'CreateUser'
  AND (
    JSON_EXTRACT_SCALAR(request_parameters, '$.userName') IN ('backup', 'sec_audit', 'administrateurs')
    OR JSON_EXTRACT_SCALAR(request_parameters, '$.userName') LIKE 'aws_dev%'
    OR JSON_EXTRACT_SCALAR(request_parameters, '$.userName') LIKE 'aws-cli%'
  )
ORDER BY event_time DESC;

-- ECS Fargate mining-scale abuse: cluster/task-def spikes in regions with no prior history
SELECT aws_region, event_name, COUNT(*) AS event_count, MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
FROM cloudtrail_events
WHERE event_name IN ('CreateCluster', 'RegisterTaskDefinition', 'CreateService')
GROUP BY aws_region, event_name
ORDER BY event_count DESC;
```

---

## Findings

### Hits
-

### False Positives / Tuning Notes
- Terraform, CDK, and CloudFormation service roles legitimately perform IAM modifications — establish a baseline of expected automation principals and exclude them
- IT/cloud admin teams performing legitimate IAM work will appear — cross-reference with change requests
- `CreatePolicyVersion` during deployments is common — filter by known CI/CD role ARNs
- `PassRole` by CodePipeline or CodeBuild service roles is expected — document and exclude known automation
- The `aws-cli*` / `aws_dev*` username pattern query can false-positive on legitimate developer-provisioned service accounts — tune the prefix list to your org's actual naming conventions before relying on it as a standalone alert
- `S3 Browser` user agent is a strong signal in most enterprise environments (rarely used legitimately) but confirm it isn't part of an approved internal S3 management workflow before treating every hit as malicious
- ECS cluster/task-definition spikes are expected during legitimate autoscaling events or new service rollouts — cross-reference region against your account's approved region list first; GUI-Vil/DataDog-style abuse specifically shows up in regions with **no prior account history**

---

## Real-World Grounding
This hunt's IOC-based queries above are derived directly from documented intrusions, not hypothetical patterns — see [[GUI-Vil (p0-LUCR-1) AWS Cryptomining Campaigns - Research Extraction]] for the full case studies (Permiso/p0 Labs, DataDog Security Labs) and [[GUI-Vil (p0-LUCR-1)]] for the actor profile behind the S3 Browser / stealth-CreateLoginProfile pattern.

---

## Outcome
- [ ] No evidence found — hypothesis closed
- [ ] Suspicious activity found — escalated to investigation
- [ ] Detection rule created → [[link to rule]]

## Related Notes
- [[AWS IAM Privilege Escalation]] — full TTP note with permission tables, tool reference, and escalation paths
- [[Hunt - EC2 IMDS Credential Theft]] — related hunt; IMDS theft feeds IAM abuse
- [[GUI-Vil (p0-LUCR-1) AWS Cryptomining Campaigns - Research Extraction]] — real-world case studies underpinning the IOC-based queries above
- [[GUI-Vil (p0-LUCR-1)]] — threat actor profile
- [[40 - Resources/Query Library/Hunt Queries]]
- [[20 - Areas/Detection Engineering/Detections]]
