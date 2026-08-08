---
title: Hunt - AWS S3 Misconfiguration and Exfiltration
date: 2026-03-08
type: hunt
status: active
hypothesis: A threat actor is exploiting S3 misconfiguration or over-permissive IAM access to enumerate, bulk-download, or silently exfiltrate data via bucket replication — which would manifest as anomalous GetObject volume, unexpected replication configuration changes, or bucket policy modifications granting access to unknown accounts.
priority: high
platform: [CrowdStrike, Databricks]
mitre_id: T1530, T1537, T1190, T1083
tags:
  - type/hunt
  - status/active
  - platform/aws
  - category/exfiltration
  - category/s3
  - category/misconfiguration
---

## Hypothesis

> I believe a threat actor is exploiting misconfigured or over-permissive S3 buckets to enumerate and exfiltrate data — either unauthenticated via public access, or post-compromise via bucket replication — because S3 misconfigurations are extremely common and CloudTrail data exfiltration signals (bulk GetObject, PutBucketReplication) are often not baselined or alerted on, which would manifest as high-volume object access from a single identity, unexpected replication configuration changes, or bucket policy modifications referencing unknown AWS account IDs.

**Why this is worth hunting:**
- S3 exfiltration via replication is stealthy — data leaves the account silently without triggering GuardDuty's default exfil finding
- Bulk `GetObject` is not alerted by default in most SIEM configurations despite being a clear staging signal
- `PutBucketReplication` is rare in most environments — any occurrence is worth investigating
- Domain takeover via deleted buckets is a persistent risk that survives infrastructure teardowns
- Unauthenticated bucket access may not generate CloudTrail events at all — S3 server access logs are the only coverage

---

## Assumptions & Scope
- Environment: AWS CloudTrail (management events + S3 data events if enabled), S3 Server Access Logs, GuardDuty
- Timeframe: Rolling 30 days
- Data sources available:
  - CloudTrail management events — bucket config changes (replication, versioning, ACL, policy)
  - CloudTrail data events (S3) — object-level GetObject/PutObject (requires explicit enablement per bucket)
  - S3 Server Access Logs — unauthenticated access (not in CloudTrail)
  - GuardDuty — anomaly-based S3 findings
  - AWS Config — historical bucket configuration state

---

## Hunt Plan

1. **Hunt for bucket replication configuration changes**
   `PutBucketReplication` is rare and high-value. Any occurrence from a non-automation identity is a priority lead. Correlate with `PutBucketVersioning` on the same bucket within the same window.

2. **Hunt for S3 Batch Operations job creation**
   `JobCreated` events outside known scheduled jobs indicate bulk object processing — potentially exfiltrating existing objects to an attacker-controlled bucket.

3. **Hunt for bulk GetObject from a single identity**
   Baseline normal object access per identity per hour. Flag identities exceeding that threshold significantly, especially across multiple buckets.

4. **Hunt for bucket policy and ACL modifications**
   `PutBucketPolicy` or `PutBucketAcl` events referencing unknown AWS account IDs or wildcard principals in the policy document.

5. **Hunt for unauthenticated access in S3 Server Access Logs**
   CloudTrail does not log unauthenticated S3 access. S3 Server Access Logs capture this. Look for `GetObject` requests with no authentication header across sensitive buckets.

6. **Identify exposed buckets via AWS Config**
   Query Config for buckets where `BlockPublicAcls`, `BlockPublicPolicy`, `IgnorePublicAcls`, or `RestrictPublicBuckets` are set to `false`.

---

## Queries

### CrowdStrike FQL

> Parameterized: `40 - Resources/Query Library/queries/hunting/cs-hunt-s3-exfiltration.md`

```fql
// PutBucketReplication — silent exfil setup
event_simpleName=CloudTrailEvent
| EventName=PutBucketReplication
| table _time, UserIdentityArn, RequestParameters, SourceIPAddress, AWSRegion

// PutBucketVersioning on established buckets — replication prerequisite
event_simpleName=CloudTrailEvent
| EventName=PutBucketVersioning
| table _time, UserIdentityArn, RequestParameters, SourceIPAddress

// S3 Batch Operations job created — bulk exfil of existing objects
event_simpleName=CloudTrailEvent
| EventName=JobCreated
| EventSource=s3.amazonaws.com
| table _time, UserIdentityArn, RequestParameters, SourceIPAddress

// Bulk GetObject — data staging
event_simpleName=CloudTrailEvent
| EventName=GetObject
| stats count(_time) as request_count by UserIdentityArn, S3BucketName
| where request_count > 100
| sort -request_count

// Bucket policy modification referencing external account
event_simpleName=CloudTrailEvent
| EventName IN ("PutBucketPolicy", "PutBucketAcl")
| table _time, UserIdentityArn, RequestParameters, SourceIPAddress
```

### Databricks SQL

> Parameterized: `40 - Resources/Query Library/queries/hunting/db-hunt-s3-exfiltration.md`

```sql
-- Replication exfil chain: PutBucketReplication + versioning + batch ops
SELECT
  event_time,
  user_identity_arn,
  event_name,
  request_parameters,
  source_ip_address,
  aws_region
FROM cloudtrail_events
WHERE event_name IN (
  'PutBucketReplication',
  'PutBucketVersioning',
  'JobCreated',
  'DeleteBucketReplication'
)
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
ORDER BY event_time DESC;

-- Bulk GetObject per identity per hour (data staging)
SELECT
  DATE_TRUNC('hour', event_time) AS hour,
  user_identity_arn,
  JSON_EXTRACT_SCALAR(request_parameters, '$.bucketName') AS bucket,
  COUNT(*) AS request_count
FROM cloudtrail_events
WHERE event_name = 'GetObject'
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
GROUP BY 1, 2, 3
HAVING request_count > 100
ORDER BY request_count DESC;

-- Bucket policy/ACL changes with cross-account or wildcard principals
SELECT
  event_time,
  user_identity_arn,
  event_name,
  request_parameters,
  source_ip_address
FROM cloudtrail_events
WHERE event_name IN ('PutBucketPolicy', 'PutBucketAcl')
  AND (
    request_parameters LIKE '%"AWS":"*"%'
    OR request_parameters LIKE '%arn:aws:iam::%'
  )
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
ORDER BY event_time DESC;

-- Identify buckets with public access blocks disabled (Config)
SELECT
  resource_id AS bucket_name,
  configuration,
  configuration_item_capture_time
FROM aws_config_history
WHERE resource_type = 'AWS::S3::Bucket'
  AND (
    JSON_EXTRACT_SCALAR(configuration, '$.PublicAccessBlockConfiguration.BlockPublicAcls') = 'false'
    OR JSON_EXTRACT_SCALAR(configuration, '$.PublicAccessBlockConfiguration.RestrictPublicBuckets') = 'false'
  )
ORDER BY configuration_item_capture_time DESC;
```

---

## Findings

### Hits
-

### False Positives / Tuning Notes
- DR/backup automation legitimately uses `PutBucketReplication` — document known replication roles and exclude them
- CI/CD pipelines perform bulk `GetObject` (artifact downloads) — baseline by role and bucket; exclude known pipeline ARNs
- `PutBucketVersioning` is sometimes enabled as part of legitimate infrastructure-as-code deployments — cross-reference with Terraform/CDK change records
- S3 Batch Operations are used for lifecycle management and migrations — verify `JobCreated` events against known scheduled jobs
- Public buckets hosting static websites or open datasets are intentional — maintain an inventory of approved public buckets to exclude from alerts

---

## Outcome
- [ ] No evidence found — hypothesis closed
- [ ] Suspicious activity found — escalated to investigation
- [ ] Detection rule created → [[link to rule]]

## Related Notes
- [[AWS S3 Misconfiguration and Bucket Attacks]] — TTP note with full technique breakdown
- [[AWS S3 Misconfiguration and Bucket Attacks]] — full TTP note with technical reference, tools, and attack chains
- [[Hunt - AWS IAM Privilege Escalation]] — IAM privesc enabling authenticated S3 attacks
- [[Hunt - EC2 IMDS Credential Theft]] — IMDS credential theft enabling S3 access
- [[40 - Resources/Query Library/Hunt Queries]]
- [[20 - Areas/Detection Engineering/Detections]]
