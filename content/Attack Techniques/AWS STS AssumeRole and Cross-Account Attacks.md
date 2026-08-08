---
title: AWS STS AssumeRole and Cross-Account Attacks
date: 2026-03-13
type: ttp
mitre_id: T1078.004, T1548, T1550.001, T1134
mitre_tactic: Defense Evasion, Privilege Escalation, Persistence, Lateral Movement
threat_actors: []
tools_used: [aws-cli, Pacu, AWSRoleJuggler]
platforms: [AWS]
tags:
  - type/ttp
  - status/active
  - platform/aws
  - category/lateral-movement
  - category/privilege-escalation
  - category/persistence
  - category/sts
source:
  url: https://hackingthe.cloud/aws/post_exploitation/role-chain-juggling/
  author: hackingthe.cloud
  date: 2024
---

## Summary
AWS STS (Security Token Service) is the backbone of AWS identity — it issues temporary credentials for role assumptions, federation, and cross-account access. Attackers exploit STS in three critical ways: **role chain juggling** to maintain indefinite access without creating new credentials; **cross-account pivoting** via misconfigured trust policies or the default `OrganizationAccountAccessRole`; and **credential persistence** via `GetFederationToken` to survive access key deletion during incident response. These techniques use legitimate AWS functionality and are extremely difficult to distinguish from normal IAM operations without strong baseline behavior.

## How It Works

### Path 1: Role Chain Juggling (Indefinite Persistence)
AWS refreshes the credential expiration timestamp each time a role is assumed through a chain. An attacker continuously re-assumes roles to maintain access indefinitely without any IAM modification.

```
Initial AssumeRole → Credential (expires in 1 hr)
    ↓ (before expiry)
AssumeRole using current credential → New credential (expires in 1 hr)
    ↓ (repeat forever)
```
No new IAM users, no new access keys, no IAM modification events.

### Path 2: Wildcard Trust Policy Exploitation
A trust policy with `"Principal": {"AWS": "*"}` allows any AWS principal globally to assume the role — not limited to the same account or organization.

```
Attacker (any AWS account) → sts:AssumeRole → victim-role (wildcarded trust)
    ↓
Permissions of victim-role granted to attacker session
```

### Path 3: AWS Organizations Default Role Abuse
Every account created via AWS Organizations gets `OrganizationAccountAccessRole` with `AdministratorAccess`, trusting the management account. Compromise the management account = admin on all member accounts.

```
Management account compromise
    ↓
AssumeRole → OrganizationAccountAccessRole in each member account
    ↓
AdministratorAccess across entire organization
```

### Path 4: GetFederationToken Persistence (Survive IR)
Create a federation token before defenders rotate the compromised keys. Token persists up to 36 hours even after original key deletion.

```
Compromise detected → IR begins
    ↓ (attacker acts first)
GetFederationToken → ASIA... credential valid for 36 hours
    ↓
IR team deletes AKIA... keys
    ↓
Attacker continues with ASIA... federation token
```

---

## Technical Reference

### STS Credential Types

| Type | Prefix | Issued By | Max Duration |
|---|---|---|---|
| Long-term IAM user keys | `AKIA` | IAM | Indefinite |
| Assumed role credentials | `ASIA` | STS AssumeRole | 1 hour (default) to 12 hours |
| Federation token | `ASIA` | STS GetFederationToken | 15 min to 36 hours |
| SAML/WebIdentity | `ASIA` | STS AssumeRoleWithSAML/WebIdentity | Varies |

### Technique 1: Role Chain Juggling Commands

```bash
# Assume a role
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/target-role \
  --role-session-name persistence-session

# Export credentials from response
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# Use those credentials to assume another role (or the same role again)
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/target-role \
  --role-session-name renewed-session

# Automated tool for continuous role chain juggling
./aws_role_juggler.py -r arn:aws:iam::ACCT:role/role-a arn:aws:iam::ACCT:role/role-b
# Source: https://github.com/hotnops/AWSRoleJuggler/
```

**Why it works:** AWS refreshes the expiration timestamp each time a role is assumed through a chain. There is no limit on the number of chaining hops.

**CloudTrail events:** `AssumeRole` — repeated calls from the same principal, cycling between roles

### Technique 2: Wildcard Trust Policy Exploitation

Misconfigured trust policy:
```json
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": "*"},
        "Action": "sts:AssumeRole"
    }]
}
```

**Subtle variant — logic inversion via ArnNotEquals + Allow:**
```json
{
    "Effect": "Allow",
    "Principal": {"AWS": "*"},
    "Action": "sts:AssumeRole",
    "Condition": {
        "ArnNotEquals": {
            "aws:PrincipalArn": "arn:aws:iam::123456789012:role/intent-allow-role"
        }
    }
}
```
This inverts the intended logic: `ArnNotEquals` with `Allow` means *everyone except the intended role* can assume it.

**Exploitation:**
```bash
# From any AWS account — no credentials in victim account needed
aws sts assume-role \
  --role-arn arn:aws:iam::VICTIM_ACCOUNT:role/misconfigured-role \
  --role-session-name attacker-session
```

**Discovery:** Role ARNs can be brute-forced or derived from unique IDs. Public S3 bucket policies, error messages, and CloudTrail log references often expose role ARNs.

### Technique 3: AWS Organizations Default Role Abuse

```bash
# From compromised management account — assume admin on any member account
aws sts assume-role \
  --role-arn arn:aws:iam::MEMBER_ACCOUNT_ID:role/OrganizationAccountAccessRole \
  --role-session-name org-pivot

# Pacu automation — brute force OrganizationAccountAccessRole across all accounts
run organizations__assume_role
```

**Blast radius:** Management account compromise = admin on every member account created through the organization.

**Additional organization pivot paths:**
- **Trusted Access** — services activated organization-wide give management account indirect control
- **Delegated Administration** — compromised delegated admin gets read-only org APIs + SCP manipulation (post-2022)
- **IAM Identity Center** — create users and permission sets to provision admin access to target member accounts

### Technique 4: GetFederationToken (Survive Key Deletion)

```bash
# Create a federation token before keys are rotated/deleted
aws sts get-federation-token \
  --name attacker-session \
  --policy-arns arn=arn:aws:iam::aws:policy/AdministratorAccess \
  --duration-seconds 129600    # 36 hours maximum

# Response: temporary ASIA... credentials that survive original key deletion
```

**Limitations of federation tokens directly in CLI:**
- Cannot call IAM operations
- Cannot call STS operations (except `GetCallerIdentity`)

**Workaround:** Convert to a console session URL — full IAM access available via browser, higher detection risk.

### CloudTrail Events

| API Call | Event Name | Notes |
|---|---|---|
| `sts:AssumeRole` | `AssumeRole` | Source account, role ARN, session name all logged |
| `sts:AssumeRoleWithWebIdentity` | `AssumeRoleWithWebIdentity` | External IdP token in request |
| `sts:AssumeRoleWithSAML` | `AssumeRoleWithSAML` | SAML assertion details |
| `sts:GetFederationToken` | `GetFederationToken` | Username and policy ARNs logged |
| `sts:GetCallerIdentity` | `GetCallerIdentity` | Often used for credential validation |
| `sts:GetSessionToken` | `GetSessionToken` | MFA-based temp cred issuance |

**Key detection signal:** `AssumeRole` events where `sourceIPAddress` or `userAgent` are unexpected, or where the `roleSessionName` is generic/random rather than following naming conventions.

### Identity Validation (Attacker Reconnaissance)

```bash
# Validate stolen credentials and identify principal (logged in CloudTrail)
aws sts get-caller-identity

# Stealth alternative — enumerate services via error messages (not logged)
aws sqs list-queues    # Returns identity info in error if no SQS access
```

### Attack Chains

#### Chain 1: Single Account → Cross-Account Pivot via OrganizationAccountAccessRole
```
Compromise IAM principal in any account
    ↓
aws organizations list-accounts  (enumerate member accounts)
    ↓
aws sts assume-role → OrganizationAccountAccessRole in each member account
    ↓
AdministratorAccess across entire organization
```

#### Chain 2: Credential Compromise → GetFederationToken → Survive Incident Response
```
IAM user credentials compromised
    ↓
aws sts get-federation-token --duration-seconds 129600
    ↓
Store ASIA credentials out-of-band
    ↓
IR team deletes/rotates access keys
    ↓
Attacker continues using federation token for up to 36 hours
```

#### Chain 3: Role Chain Juggling → Indefinite Persistence
```
Assume initial role (1-hour credentials)
    ↓
Before expiration: use role to assume another trusting role
    ↓
Credentials refreshed; repeat indefinitely
    ↓
No new access keys created; no IAM modification events
```

### Key Indicators
- `AssumeRole` calls from unexpected source IPs or user-agents
- `roleSessionName` not matching expected naming convention (e.g., random strings)
- `AssumeRole` calls from a role ARN to the same role ARN (self-chaining)
- Repeated `AssumeRole` calls in short succession (role juggling pattern)
- `GetFederationToken` with `AdministratorAccess` policy ARN
- `OrganizationAccountAccessRole` assumption from unexpected principals
- `GetCallerIdentity` as first action from newly observed identity

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Valid Accounts: Cloud Accounts | T1078.004 | Using assumed role credentials as valid cloud identity |
| Abuse Elevation Control Mechanism | T1548 | Abusing trust relationships to elevate privileges |
| Use Alternate Authentication Material | T1550.001 | Using STS temporary credentials instead of long-term keys |
| Access Token Manipulation | T1134 | Role chaining and GetFederationToken to create alternate tokens |

---

## Detection Opportunities

### Behavioral Indicators
- `AssumeRole` calls where the session name is generic, random, or doesn't match naming conventions
- **Same role assumed by the same principal repeatedly in a short window** — role chain juggling
- `AssumeRole` from an unexpected source account (cross-account attack from external account)
- `OrganizationAccountAccessRole` assumption from any principal other than known automation
- `GetFederationToken` with `AdministratorAccess` policy ARN
- `GetCallerIdentity` as the first API call from a newly observed identity — credential validation

### Trust Policy Audit Indicators
- IAM roles with `"Principal": {"AWS": "*"}` in trust policy
- Conditions using `ArnNotEquals` with `Effect: Allow` (logic inversion)
- Roles trusted by external account IDs not in the organization

---

## Query Stubs

### CrowdStrike FQL
```fql
// AssumeRole from unexpected source — cross-account
event_simpleName=CloudTrailEvent
| EventName=AssumeRole
| table _time, UserIdentityArn, RequestParameters, SourceIPAddress, AWSRegion

// Role chain juggling — same role assumed repeatedly
event_simpleName=CloudTrailEvent
| EventName=AssumeRole
| stats count(_time) as assume_count by UserIdentityArn, RequestParameters.roleArn
| where assume_count > 5
| sort -assume_count

// GetFederationToken — persistence before key deletion
event_simpleName=CloudTrailEvent
| EventName=GetFederationToken
| table _time, UserIdentityArn, RequestParameters, SourceIPAddress

// OrganizationAccountAccessRole assumptions
event_simpleName=CloudTrailEvent
| EventName=AssumeRole
| RequestParameters.roleArn=*OrganizationAccountAccessRole*
| table _time, UserIdentityArn, RequestParameters, SourceIPAddress
```

### Databricks SQL
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
  'GetCallerIdentity'
)
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
ORDER BY event_time DESC;

-- Role chain juggling — repeated AssumeRole of same role by same identity
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
  source_ip_address
FROM cloudtrail_events
WHERE event_name = 'AssumeRole'
  AND request_parameters LIKE '%OrganizationAccountAccessRole%'
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
ORDER BY event_time DESC;

-- GetFederationToken with high-privilege policy
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
  )
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
ORDER BY event_time DESC;

-- Cross-account AssumeRole — source account ≠ target account
SELECT
  event_time,
  user_identity_arn,
  JSON_EXTRACT_SCALAR(request_parameters, '$.roleArn') AS assumed_role,
  source_ip_address,
  JSON_EXTRACT_SCALAR(user_identity, '$.accountId') AS source_account
FROM cloudtrail_events
WHERE event_name = 'AssumeRole'
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
  AND JSON_EXTRACT_SCALAR(request_parameters, '$.roleArn') NOT LIKE
      CONCAT('%', JSON_EXTRACT_SCALAR(user_identity, '$.accountId'), '%')
ORDER BY event_time DESC;
```

---

## Tools Reference

| Tool | Purpose |
|---|---|
| AWS CLI | Manual STS operations and role assumption |
| Pacu `organizations__assume_role` | Automated OrganizationAccountAccessRole pivot across all accounts |
| AWSRoleJuggler | Automated continuous role chain juggling |

---

## References
- [hackingthe.cloud: Role Chain Juggling](https://hackingthe.cloud/aws/post_exploitation/role-chain-juggling/)
- [hackingthe.cloud: Misconfigured IAM Role Trust Policy — Wildcard Principal](https://hackingthe.cloud/aws/exploitation/Misconfigured_Resource-Based_Policies/misconfigured_iam_role_trust_policy_wildcard_principal/)
- [hackingthe.cloud: AWS Organizations Defaults](https://hackingthe.cloud/aws/general-knowledge/aws_organizations_defaults/)
- [hackingthe.cloud: Survive Key Deletion with GetFederationToken](https://hackingthe.cloud/aws/post_exploitation/survive_access_key_deletion_with_sts_getfederationtoken/)
- [AWSRoleJuggler Tool](https://github.com/hotnops/AWSRoleJuggler/)

## Related Notes
- [[Hunt - AWS STS AssumeRole and Cross-Account Attacks]] — active hunt hypothesis
- [[AWS IAM Privilege Escalation]] — initial access enabling role assumption
- [[AWS SSM Lateral Movement and Command Execution]] — post-AssumeRole execution
- [[30 - Knowledge/Cybersecurity/Research Index]]
