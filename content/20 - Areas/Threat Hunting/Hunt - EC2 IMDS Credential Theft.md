---
title: Hunt - EC2 IMDS Credential Theft
date: 2026-03-08
type: hunt
status: active
hypothesis: A threat actor is exploiting an SSRF vulnerability in a web application running on EC2 to access the Instance Metadata Service and steal temporary IAM role credentials, which would manifest as instance credentials used from an external IP or an unusual source, followed by IAM enumeration activity.
priority: high
platform: [CrowdStrike, Databricks]
mitre_id: T1552.005, T1078.004
tags:
  - type/hunt
  - status/active
  - platform/aws
  - category/credential-access
  - category/ssrf
  - category/imds
---

## Hypothesis

> I believe a threat actor is exploiting an SSRF vulnerability in an EC2-hosted web application to access the IMDS endpoint and steal temporary IAM role credentials because SSRF vulnerabilities are common in web applications and IMDSv1 requires no authentication, which would manifest as instance profile credentials being used from an IP address outside the known range of that EC2 instance, or a spike in `GetCallerIdentity` calls from unusual sources.

**Why this is worth hunting:**
- IMDSv1 remains enabled on many instances — one SSRF vulnerability is all it takes
- The Capital One breach demonstrated the real-world impact at scale
- Instance credential use from external IPs is a high-fidelity signal with low legitimate false positive rate
- GuardDuty's `InstanceCredentialExfiltration` finding only fires for use outside AWS — internal pivots are blind spots

---

## Assumptions & Scope
- Environment: AWS CloudTrail, VPC Flow Logs, GuardDuty findings
- Timeframe: Rolling 30 days
- Data sources available:
  - CloudTrail — API calls with identity context
  - VPC Flow Logs — traffic to 169.254.169.254 (if collected)
  - GuardDuty — `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` findings
  - EC2 inventory — known instance IPs for correlation

---

## Hunt Plan

1. **Hunt for instance credentials used from unexpected IPs**
   Instance profile credentials are identifiable by ARN format `arn:aws:sts::<account>:assumed-role/<role>/i-<instance-id>`. Any API call using these credentials from an IP that isn't the EC2 instance's known IP is a strong signal.

2. **Hunt for GetCallerIdentity spikes**
   Attackers consistently call `GetCallerIdentity` immediately after obtaining credentials to confirm they work. A burst of these calls from new or unusual identities is a reliable indicator.

3. **Hunt for IMDSv1 usage (no token header)**
   If IMDSv2 is enforced, requests without a token header are blocked and logged. Hunt for instances still running IMDSv1 as exposure identification.

4. **Hunt for IAM enumeration following instance credential use**
   After stealing credentials, attackers enumerate permissions. Look for `ListPolicies`, `GetPolicy`, `SimulatePrincipalPolicy` events from instance role ARNs at unusual times.

5. **Correlate with GuardDuty findings**
   `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` is a direct match — investigate any open findings.

6. **Review VPC Flow Logs for IMDS traffic**
   Traffic to `169.254.169.254` (IMDS) from unexpected processes or at unusual times in flow logs may indicate SSRF probing or exploitation.

---

## Queries

### CrowdStrike FQL

> Parameterized: `40 - Resources/Query Library/queries/hunting/cs-hunt-imds-credential-theft.md`

```fql
// Instance credentials used from non-instance IP
event_simpleName=CloudTrailEvent
| UserIdentityType=AssumedRole
| UserIdentityArn=*:assumed-role/*/i-*
| table _time, UserIdentityArn, EventName, SourceIPAddress, AWSRegion
| sort _time desc

// GetCallerIdentity calls — attacker recon after credential theft
event_simpleName=CloudTrailEvent
| EventName=GetCallerIdentity
| UserIdentityType=AssumedRole
| table _time, UserIdentityArn, SourceIPAddress, AWSRegion
| sort _time desc

// IAM enumeration by instance role
event_simpleName=CloudTrailEvent
| EventName IN ("ListPolicies", "GetPolicy", "SimulatePrincipalPolicy", "ListAttachedRolePolicies")
| UserIdentityArn=*:assumed-role/*/i-*
| table _time, UserIdentityArn, EventName, SourceIPAddress
```

### Databricks SQL

> Parameterized: `40 - Resources/Query Library/queries/hunting/db-hunt-imds-credential-theft.md`

```sql
-- Instance credentials used from IP outside known EC2 inventory
SELECT
  ct.event_time,
  ct.user_identity_arn,
  ct.event_name,
  ct.source_ip_address,
  ct.aws_region
FROM cloudtrail_events ct
WHERE
  ct.user_identity_type = 'AssumedRole'
  AND ct.user_identity_arn REGEXP '.*:assumed-role/.*/i-[0-9a-f]+'
  AND ct.source_ip_address NOT IN (
    SELECT private_ip FROM ec2_inventory
    UNION
    SELECT public_ip FROM ec2_inventory
  )
  AND ct.event_time >= CURRENT_DATE - INTERVAL 30 DAYS
ORDER BY ct.event_time DESC;

-- GetCallerIdentity burst — attacker confirming stolen creds
SELECT
  DATE_TRUNC('hour', event_time) AS hour,
  user_identity_arn,
  source_ip_address,
  COUNT(*) AS call_count
FROM cloudtrail_events
WHERE
  event_name = 'GetCallerIdentity'
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
GROUP BY 1, 2, 3
HAVING call_count > 3
ORDER BY call_count DESC;

-- IAM enumeration from instance role ARNs
SELECT
  event_time,
  user_identity_arn,
  event_name,
  source_ip_address
FROM cloudtrail_events
WHERE
  event_name IN ('ListPolicies', 'GetPolicy', 'SimulatePrincipalPolicy', 'ListAttachedRolePolicies')
  AND user_identity_arn REGEXP '.*:assumed-role/.*/i-[0-9a-f]+'
ORDER BY event_time DESC;
```

---

## Findings

### Hits
-

### False Positives / Tuning Notes
- Legitimate applications on EC2 may call AWS APIs from the instance IP — these will appear with instance role ARNs from the correct IP and should be baselined and excluded
- NAT Gateway / proxy setups may cause legitimate instance traffic to appear from the NAT IP — document these and add to known IP list
- `GetCallerIdentity` is sometimes called by SDKs during initialization — establish a baseline frequency per role and alert on deviation rather than absolute count
- Spot instance replacement can cause a new instance ID with the same role — verify against EC2 instance launch events

---

## Outcome
- [ ] No evidence found — hypothesis closed
- [ ] Suspicious activity found — escalated to investigation
- [ ] Detection rule created → [[link to rule]]

## Related Notes
- [[EC2 Instance Metadata Service Abuse]] — TTP note with full technique breakdown
- [[EC2 Instance Metadata Service Abuse]] — full TTP note with technical reference, endpoint table, and attack chains
- [[Hunt - AWS IAM Privilege Escalation]] — what attackers do with stolen IMDS credentials
- [[40 - Resources/Query Library/Hunt Queries]]
- [[20 - Areas/Detection Engineering/Detections]]
