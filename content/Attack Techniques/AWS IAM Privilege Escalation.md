---
title: AWS IAM Privilege Escalation
date: 2026-03-08
type: ttp
mitre_id: T1078.004, T1548, T1098, T1136.003
mitre_tactic: Privilege Escalation, Persistence, Defense Evasion
threat_actors: []
tools_used: [Pacu, PMapper, iam-vulnerable, AWS CLI]
platforms: [AWS]
tags:
  - type/ttp
  - status/active
  - platform/aws
  - category/privilege-escalation
  - category/iam
source:
  url: https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
  author: Spencer Gietzen (Rhino Security Labs) via hackingthe.cloud
  date: 2023
---

## Summary
AWS IAM privilege escalation abuses overly permissive IAM policies to elevate access from a low-privilege identity to administrator. Any permission that allows modifying IAM policies, assuming privileged roles, or passing roles to AWS services that execute code represents a potential escalation path. 30+ distinct paths have been documented; PMapper can identify all viable paths automatically for a given AWS account.

## How It Works

### Step 1 — Enumerate Current Permissions
Attacker starts with any AWS identity (user, role, instance profile) and enumerates what it can do.
```bash
aws iam get-user
aws iam list-attached-user-policies --user-name <user>
aws iam list-user-policies --user-name <user>
aws sts get-caller-identity
```

### Step 2 — Identify Escalation Path
One or more of three escalation categories is present:

**A — Direct policy manipulation**
Permissions like `iam:AttachUserPolicy`, `iam:PutUserPolicy`, `iam:CreatePolicyVersion` allow directly granting admin access to the current identity.

**B — Identity takeover**
Permissions like `iam:CreateAccessKey`, `iam:UpdateLoginProfile`, `iam:UpdateAssumeRolePolicy` allow taking over a higher-privileged identity.

**C — PassRole + service execution (most common)**
`iam:PassRole` combined with a service permission (e.g., `lambda:CreateFunction`, `ec2:RunInstances`, `ecs:RunTask`) allows passing a privileged role to a service that runs code — the code then retrieves the privileged credentials from within the execution environment.

### Step 3 — Execute Escalation
Example — Lambda PassRole escalation:
```bash
# Create function with privileged role
aws lambda create-function \
  --function-name privesc \
  --runtime python3.9 \
  --role arn:aws:iam::<account>:role/<privileged-role> \
  --handler index.handler \
  --zip-file fileb://function.zip

# Invoke to retrieve role credentials
aws lambda invoke --function-name privesc out.json
```

Example — direct policy attach:
```bash
aws iam attach-user-policy \
  --user-name <your-user> \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### Step 4 — Validate Escalated Access
```bash
aws sts get-caller-identity
aws iam list-policies --scope Local   # Confirm admin access
```

---

## Technical Reference

### Permission Categories & Abuse Methods

#### 1. Direct Policy Manipulation
Permissions that let an attacker modify their own or others' permissions directly.

| Permission | Abuse Method |
|---|---|
| `iam:AttachUserPolicy` | Attach `AdministratorAccess` to your own user |
| `iam:AttachRolePolicy` | Attach admin policy to a role you control |
| `iam:AttachGroupPolicy` | Attach admin policy to a group you're in |
| `iam:PutUserPolicy` | Create inline admin policy on your user |
| `iam:PutRolePolicy` | Create inline admin policy on a role you control |
| `iam:CreatePolicyVersion` | Create a new version of an existing policy with `*:*` |
| `iam:SetDefaultPolicyVersion` | Roll back a policy to a previous permissive version |
| `iam:DeleteUserPolicy` | Remove a restrictive inline policy from yourself |

#### 2. Identity Takeover
Permissions that allow taking control of a higher-privileged identity.

| Permission | Abuse Method |
|---|---|
| `iam:CreateAccessKey` | Create access keys for a more privileged user |
| `iam:CreateLoginProfile` | Set a console password on an account with no password |
| `iam:UpdateLoginProfile` | Change the console password of a privileged user |
| `iam:AddUserToGroup` | Add yourself to a group with admin permissions |
| `iam:UpdateAssumeRolePolicy` | Modify a role's trust policy to allow your identity to assume it |

#### 3. Permissions Boundary Removal
Permissions boundaries cap what a role/user can do even if policies allow more. Removing them is silent escalation.

| Permission | Abuse Method |
|---|---|
| `iam:DeleteRolePermissionsBoundary` | Remove boundary from a role, enabling full policy permissions |
| `iam:DeleteUserPermissionsBoundary` | Remove boundary from a user |

#### 4. PassRole + Service Escalation (Most Common)
`iam:PassRole` combined with a service permission is the most prevalent escalation path. The attacker passes a privileged role to a service that executes code, then retrieves credentials from that execution context.

**Required combination:** `iam:PassRole` + one of the following:

| Service Permission | Attack Method |
|---|---|
| `ec2:RunInstances` | Launch EC2 instance with privileged role; retrieve creds via user data or IMDS |
| `lambda:CreateFunction` + `lambda:InvokeFunction` | Create Lambda with privileged role; invoke to exfiltrate creds |
| `lambda:UpdateFunctionCode` | Modify existing Lambda code to exfiltrate its role credentials |
| `lambda:UpdateFunctionConfiguration` | Add malicious Lambda layer to existing function |
| `ecs:RunTask` | Run Fargate task with command override to exfiltrate creds |
| `cloudformation:CreateStack` | Deploy stack with privileged role; include resource that exfils creds |
| `glue:CreateJob` + `glue:StartJobRun` | Create Glue job with privileged role, exfil from job execution |
| `glue:UpdateDevEndpoint` | Update SSH public key on Glue dev endpoint; SSH in and steal creds |
| `datapipeline:CreatePipeline` + `datapipeline:PutPipelineDefinition` | Create pipeline with elevated role |
| `autoscaling:CreateLaunchConfiguration` | Create launch config with privileged role attached to new instances |

#### 5. CodeStar / Misc
| Permission | Abuse Method |
|---|---|
| `codestar:CreateProject` | Grants enumeration permissions and organizational access |
| `codestar:AssociateTeamMember` | Elevate access within CodeStar project scope |

### Credential Exfiltration Methods (Post-Escalation)
Once a privileged role is assumed or a service executes with elevated permissions, creds are extracted via:
- **EC2 user data scripts** — executed at instance launch, can POST creds to attacker URL
- **IMDS endpoint** — `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` from within the instance
- **Lambda environment** — `os.environ['AWS_ACCESS_KEY_ID']` etc. from within function
- **CloudWatch Logs** — print creds to stdout, retrieve from logs

### Tool Commands

**PMapper key commands:**
```bash
# Graph the account
pmapper graph create

# Find all privesc paths from a specific principal
pmapper analysis --suggest

# Query specific path
pmapper query "who can escalate privileges"
```

**Pacu IAM modules:**
```bash
run iam__privesc_scan          # Scan for all privesc paths
run iam__enum_permissions      # Enumerate current permissions
run iam__backdoor_users_keys   # Create backdoor access keys
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Valid Accounts: Cloud Accounts | T1078.004 | Using existing IAM identity as foothold |
| Abuse Elevation Control Mechanism | T1548 | Exploiting IAM policy misconfigurations to elevate privileges |
| Account Manipulation | T1098 | Modifying IAM policies, group memberships, or role trust relationships |
| Create Account: Cloud Account | T1136.003 | Creating backdoor IAM users or access keys |

---

## Detection Opportunities

### Key Log Sources
- **CloudTrail** — all IAM API calls are logged; this is the primary detection source
- **AWS Config** — tracks configuration changes to IAM policies, roles, and users
- **GuardDuty** — has some IAM anomaly detections built in
- **IAM Access Analyzer** — identifies overly permissive policies proactively

### Behavioral Indicators
- IAM policy attachment events for the same identity that recently assumed a new role
- `iam:CreatePolicyVersion` followed immediately by `iam:SetDefaultPolicyVersion`
- `iam:PassRole` to a service that is not normally used by that identity
- Lambda/ECS/Glue resources created or updated by an identity with no prior history of doing so
- `iam:CreateAccessKey` called against a user other than the caller's own identity
- `iam:UpdateLoginProfile` or `iam:CreateLoginProfile` on a high-privilege account
- `iam:DeleteRolePermissionsBoundary` or `iam:DeleteUserPermissionsBoundary` — rare and suspicious
- New role trust policy modification (`iam:UpdateAssumeRolePolicy`) not matching a change request

### Artifacts Left Behind
- New policy versions attached to existing managed policies
- New inline policies on users, roles, or groups
- New Lambda functions, Glue jobs, or ECS tasks created during off-hours
- CloudTrail event: `CreatePolicyVersion` with `isDefaultVersion: true`
- CloudTrail event: `AttachUserPolicy` with `AdministratorAccess` ARN

---

## Query Stubs

### CrowdStrike FQL
```fql
// IAM policy attachment to self or other user
event_simpleName=CloudTrailEvent
| EventName IN ("AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy", "PutUserPolicy", "PutRolePolicy")
| table _time, UserName, EventName, RequestParameters

// PassRole to service — high value escalation signal
event_simpleName=CloudTrailEvent
| EventName="PassRole"
| table _time, UserName, RequestParameters, SourceIPAddress

// CreateAccessKey called against a different user
event_simpleName=CloudTrailEvent
| EventName="CreateAccessKey"
| eval self_action=if(RequestParameters.userName==UserName, "self", "other")
| self_action=other
| table _time, UserName, RequestParameters.userName, SourceIPAddress
```

### Databricks SQL
```sql
-- IAM escalation actions in CloudTrail
SELECT
  event_time,
  user_identity_arn,
  event_name,
  request_parameters,
  source_ip_address
FROM cloudtrail_events
WHERE event_name IN (
  'AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy',
  'PutUserPolicy', 'PutRolePolicy', 'PutGroupPolicy',
  'CreatePolicyVersion', 'SetDefaultPolicyVersion',
  'DeleteRolePermissionsBoundary', 'DeleteUserPermissionsBoundary',
  'UpdateAssumeRolePolicy', 'CreateAccessKey', 'UpdateLoginProfile'
)
ORDER BY event_time DESC;

-- PassRole events — pivot point for service escalation
SELECT
  event_time,
  user_identity_arn,
  request_parameters,
  source_ip_address
FROM cloudtrail_events
WHERE event_name = 'PassRole'
ORDER BY event_time DESC;
```

---

## Tools Reference

| Tool | Purpose |
|---|---|
| **Pacu** | AWS exploitation framework; has IAM privesc modules |
| **PMapper** | Graphs IAM relationships and identifies all escalation paths automatically |
| **iam-vulnerable** | BishopFox lab environment for practicing IAM privesc (by Seth Art) |
| **AWS CLI** | Manual enumeration and exploitation |

---

## Threat Actor Usage
PassRole escalation and direct policy manipulation are used across financially motivated actors, nation-state APTs, and red teams targeting AWS environments. Any post-compromise cloud pivot will attempt IAM escalation as a first step.

| Actor Type | Common Method |
|---|---|
| Financially motivated | CreateAccessKey on privileged users, PassRole to Lambda |
| Nation-state | Persistence via backdoor roles, UpdateAssumeRolePolicy |
| Insider threat | AttachUserPolicy, AddUserToGroup |

---

## References
- [hackingthe.cloud — IAM Privilege Escalation](https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/)
- [Rhino Security Labs — AWS IAM Privilege Escalation Methods and Mitigation](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [BishopFox — iam-vulnerable](https://github.com/BishopFox/iam-vulnerable)
- [PMapper](https://github.com/nccgroup/PMapper)

## Related Notes
- [[Hunt - AWS IAM Privilege Escalation]] — active hunt hypothesis with queries
- [[EC2 Instance Metadata Service Abuse]] — credential theft technique feeding into IAM abuse
- [[30 - Knowledge/Cybersecurity/Research Index]]
