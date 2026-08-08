---
title: Security Research Notes
---

# Research Index

A living index of all research notes in the vault. Updated each time a new note is created through the [[40 - Resources/Research & Hunt Workflow|Research & Hunt Workflow]].

---

## Attack Techniques

| Note | MITRE | Platform | Date |
|---|---|---|---|
| [[30 - Knowledge/Cybersecurity/Attack Techniques/Abusing Slack for Offensive Operations\|Abusing Slack for Offensive Operations]] | T1539, T1555, T1213.003, T1083 | Windows, macOS | 2026-03-07 |
| [[30 - Knowledge/Cybersecurity/Attack Techniques/AWS IAM Privilege Escalation\|AWS IAM Privilege Escalation]] | T1078.004, T1548, T1098, T1136.003 | AWS | 2026-03-08 |
| [[30 - Knowledge/Cybersecurity/Attack Techniques/EC2 Instance Metadata Service Abuse\|EC2 Instance Metadata Service Abuse (IMDS)]] | T1552.005, T1078.004 | AWS | 2026-03-08 |
| [[30 - Knowledge/Cybersecurity/Attack Techniques/AWS S3 Misconfiguration and Bucket Attacks\|AWS S3 Misconfiguration and Bucket Attacks]] | T1530, T1537, T1190, T1083 | AWS | 2026-03-08 |
| [[30 - Knowledge/Cybersecurity/Attack Techniques/Databricks API Abuse and Privilege Escalation\|Databricks API Abuse and Privilege Escalation]] | T1087.004, T1528, T1134, T1078.004, T1548, T1552.001, T1537 | Databricks, Cloud | 2026-03-08 |
| [[30 - Knowledge/Cybersecurity/Attack Techniques/AWS Secrets Manager and Parameter Store Attacks\|AWS Secrets Manager and Parameter Store Attacks]] | T1552.001, T1555, T1083 | AWS | 2026-03-13 |
| [[30 - Knowledge/Cybersecurity/Attack Techniques/AWS SSM Lateral Movement and Command Execution\|AWS SSM Lateral Movement and Command Execution]] | T1651, T1021, T1059.009 | AWS | 2026-03-13 |
| [[30 - Knowledge/Cybersecurity/Attack Techniques/AWS STS AssumeRole and Cross-Account Attacks\|AWS STS AssumeRole and Cross-Account Attacks]] | T1078.004, T1548, T1550.001, T1134 | AWS | 2026-03-13 |
| [[30 - Knowledge/Cybersecurity/Attack Techniques/macOS Info Stealer - Data Targeted\|macOS Info Stealer - Data Targeted]] | T1539, T1555.003, T1115, T1552.004 | macOS | 2026-03-07 |
| [[30 - Knowledge/Cybersecurity/Attack Techniques/macOS Gaslight Backdoor\|macOS Gaslight Backdoor]] | T1123, T1115, T1056.004, T1571, T1008, T1543.001, T1140, T1027, T1020, T1059.004 | macOS | 2026-07-10 |
| [[30 - Knowledge/Cybersecurity/Attack Techniques/macOS TCC Manipulation via AppleScript\|macOS TCC Manipulation via AppleScript]] | T1566.001, T1059.002, T1564.004, T1027, T1547, T1217, T1071.001, T1547.015 | macOS | 2026-07-25 |
| [[30 - Knowledge/Cybersecurity/Attack Techniques/ClickFix\|ClickFix]] | — | Windows, Linux | — |
| [[30 - Knowledge/Cybersecurity/Attack Techniques/ClickFix macOS via Script Editor\|ClickFix macOS via Script Editor]] | T1204.001, T1059.004, T1140, T1105, T1218.005 | macOS | 2026-04-10 |
| [[30 - Knowledge/Cybersecurity/Attack Techniques/Linux Rootkit\|Linux Rootkit]] | — | Linux | — |
| [[30 - Knowledge/Cybersecurity/Attack Techniques/crypto theft\|Crypto Theft]] | — | — | — |
| [[30 - Knowledge/Cybersecurity/Attack Techniques/Malware Traffic Analysis\|Malware Traffic Analysis]] | — | — | — |
| [[30 - Knowledge/Cybersecurity/Attack Techniques/Oauth 2.0 and OpenID Connect\|OAuth 2.0 and OpenID Connect]] | — | Web | — |
| [[30 - Knowledge/Cybersecurity/Attack Techniques/AWS Pentesting\|AWS Pentesting]] | — | Cloud | — |
| [[30 - Knowledge/Cybersecurity/Attack Techniques/SQL injection\|SQL Injection]] | — | Web | — |

---

## Malware & TTPs (Research Extractions)

| Note | MITRE | Platform | Date |
|---|---|---|---|
| [[30 - Knowledge/Cybersecurity/Malware & TTPs/ClickFix macOS Script Editor and Atomic Stealer - Research Extraction\|ClickFix macOS Script Editor and Atomic Stealer]] | T1204.001, T1059.004, T1140, T1105, T1218.005 | macOS | 2026-04-10 |
| [[30 - Knowledge/Cybersecurity/Malware & TTPs/macOS Gaslight Backdoor - Research Extraction\|macOS Gaslight Backdoor]] | T1123, T1115, T1056.004, T1571, T1008, T1543.001, T1140, T1027, T1020, T1059.004 | macOS | 2026-07-10 |
| [[30 - Knowledge/Cybersecurity/Malware & TTPs/macOS TCC Manipulation - Research Extraction\|macOS TCC Manipulation]] | T1566.001, T1059.002, T1564.004, T1027, T1547, T1217, T1071.001, T1547.015 | macOS | 2026-07-25 |

---

## Hunt Hypotheses

| Note | Status | MITRE | Platform | Date |
|---|---|---|---|---|
| [[20 - Areas/Threat Hunting/Hunt - Slack Cookie Theft and Session Hijacking\|Hunt - Slack Cookie Theft and Session Hijacking]] | Active | T1539, T1555 | Windows, macOS | 2026-03-08 |
| [[20 - Areas/Threat Hunting/Hunt - AWS IAM Privilege Escalation\|Hunt - AWS IAM Privilege Escalation]] | Active | T1078.004, T1548, T1098 | AWS | 2026-03-08 |
| [[20 - Areas/Threat Hunting/Hunt - EC2 IMDS Credential Theft\|Hunt - EC2 IMDS Credential Theft]] | Active | T1552.005, T1078.004 | AWS | 2026-03-08 |
| [[20 - Areas/Threat Hunting/Hunt - AWS S3 Misconfiguration and Exfiltration\|Hunt - AWS S3 Misconfiguration and Exfiltration]] | Active | T1530, T1537, T1190 | AWS | 2026-03-08 |
| [[20 - Areas/Threat Hunting/Hunt - Databricks Credential Abuse and Privilege Escalation\|Hunt - Databricks Credential Abuse and Privilege Escalation]] | Active | T1087.004, T1528, T1548, T1537 | Databricks, Cloud | 2026-03-08 |
| [[20 - Areas/Threat Hunting/Hunt - AWS Secrets Manager Credential Harvesting\|Hunt - AWS Secrets Manager Credential Harvesting]] | Active | T1552.001, T1555, T1083 | AWS | 2026-03-13 |
| [[20 - Areas/Threat Hunting/Hunt - AWS SSM Lateral Movement\|Hunt - AWS SSM Lateral Movement]] | Active | T1651, T1021, T1059.009 | AWS | 2026-03-13 |
| [[20 - Areas/Threat Hunting/Hunt - AWS STS AssumeRole and Cross-Account Attacks\|Hunt - AWS STS AssumeRole and Cross-Account Attacks]] | Active | T1078.004, T1548, T1550.001 | AWS | 2026-03-13 |
| [[20 - Areas/Threat Hunting/Sentinelone Mac OS Hunting\|SentinelOne macOS Hunting]] | — | — | macOS | — |
| [[20 - Areas/Threat Hunting/Threat Hunting macOS\|Threat Hunting macOS]] | — | — | macOS | — |
| [[20 - Areas/Threat Hunting/Hunt - ClickFix macOS Script Editor and Atomic Stealer\|Hunt - ClickFix macOS Script Editor and Atomic Stealer]] | Active | T1204.001, T1059.004, T1140, T1105, T1218.005 | macOS | 2026-04-10 |
| [[20 - Areas/Threat Hunting/Hunt - macOS Gaslight Backdoor\|Hunt - macOS Gaslight Backdoor]] | Active | T1123, T1115, T1056.004, T1571, T1543.001, T1020 | macOS | 2026-07-10 |
| [[20 - Areas/Threat Hunting/Hunt - macOS TCC Manipulation\|Hunt - macOS TCC Manipulation]] | Active | T1566.001, T1059.002, T1547, T1217, T1071.001, T1547.015 | macOS | 2026-07-25 |

---

## Threat Actors & APTs

| Note | Origin | Motivation | Date |
|---|---|---|---|
| [[30 - Knowledge/Cybersecurity/Threat Actors & APTs/Scattered Spider\|Scattered Spider]] | — | Financial | — |
| [[30 - Knowledge/Cybersecurity/Threat Actors & APTs/CHAMELGANG & FRIENDS\|ChamelGang & Friends]] | — | Espionage | — |
| [[30 - Knowledge/Cybersecurity/Threat Actors & APTs/Bling Libra's Tactical Evolution- The Threat Actor Group Behind ShinyHunters Ransomware\|Bling Libra / ShinyHunters]] | — | Financial | — |

---

## Tools & Platforms

| Note | Category |
|---|---|
| [[30 - Knowledge/Cybersecurity/Tools & Platforms/CrowdStrike\|CrowdStrike]] | EDR |
| [[30 - Knowledge/Cybersecurity/Tools & Platforms/Cobalt Strike\|Cobalt Strike]] | C2 |
| [[30 - Knowledge/Cybersecurity/Tools & Platforms/Ngrok\|Ngrok]] | Tunneling |
| [[30 - Knowledge/Cybersecurity/Tools & Platforms/Impacket\|Impacket]] | Lateral Movement |
| [[30 - Knowledge/Cybersecurity/Tools & Platforms/RMM Tools\|RMM Tools]] | Remote Access |
| [[30 - Knowledge/Cybersecurity/Tools & Platforms/Cloudflare Dev tunnel\|Cloudflare Dev Tunnel]] | Tunneling |

---

## DFIR & Forensics

| Note | Platform | Date |
|---|---|---|
| [[30 - Knowledge/Cybersecurity/DFIR & Forensics/Forensics/Mac Forensics\|Mac Forensics]] | macOS | — |
| [[30 - Knowledge/Cybersecurity/DFIR & Forensics/Forensics/Mac Traige\|Mac Triage]] | macOS | — |
| [[30 - Knowledge/Cybersecurity/DFIR & Forensics/Forensics/Windows Forensics\|Windows Forensics]] | Windows | — |
| [[30 - Knowledge/Cybersecurity/DFIR & Forensics/Forensics/Forensics\|Forensics General]] | Cross-platform | — |
| [[30 - Knowledge/Cybersecurity/DFIR & Forensics/Forensics/Apple Silicon Recovery Mode\|Apple Silicon Recovery Mode]] | macOS | 2026-04-18 |

---

## Detection Engineering

| Note | Type |
|---|---|
| [[40 - Resources/Query Library/Hunt Queries\|Hunt Queries]] | Query library |

---

## Research Note Clusters
Notes created together as part of a single research session are grouped here for easy navigation.

### Slack Session Hijacking (2026-03-07/08)
> Source: SpecterOps — Abusing Slack for Offensive Operations
- [[30 - Knowledge/Cybersecurity/Attack Techniques/Abusing Slack for Offensive Operations|1. TTP Note]] — MITRE mapping, detection opportunities, full technical reference (file paths, tools, API endpoints, extraction commands), query stubs
- [[20 - Areas/Threat Hunting/Hunt - Slack Cookie Theft and Session Hijacking|2. Hunt Hypothesis]] — actionable hunt with CrowdStrike FQL and Databricks queries

### AWS IAM Privilege Escalation (2026-03-08)
> Source: hackingthe.cloud — IAM Privilege Escalation (Spencer Gietzen / Rhino Security Labs)
- [[30 - Knowledge/Cybersecurity/Attack Techniques/AWS IAM Privilege Escalation|1. TTP Note]] — MITRE mapping, step-by-step escalation, 30+ permission paths, Pacu/PMapper commands, CloudTrail detection queries
- [[20 - Areas/Threat Hunting/Hunt - AWS IAM Privilege Escalation|2. Hunt Hypothesis]] — CrowdStrike FQL and Databricks SQL hunting IAM modification events and PassRole patterns

### AWS S3 Misconfiguration Attack Chains (2026-03-08)
> Source: Intigriti — Hacking Misconfigured AWS S3 Buckets; hackingthe.cloud — S3 Bucket Replication Exfiltration
- [[30 - Knowledge/Cybersecurity/Attack Techniques/AWS S3 Misconfiguration and Bucket Attacks|1. TTP Note]] — MITRE mapping, step-by-step attack paths, misconfiguration types table, all CLI commands, 4 attack chains, CloudTrail and GuardDuty detection
- [[20 - Areas/Threat Hunting/Hunt - AWS S3 Misconfiguration and Exfiltration|2. Hunt Hypothesis]] — hunting replication config changes, bulk GetObject, policy modifications with unknown account IDs

### EC2 IMDS Credential Theft via SSRF (2026-03-08)
> Source: hackingthe.cloud — EC2 Metadata SSRF
- [[30 - Knowledge/Cybersecurity/Attack Techniques/EC2 Instance Metadata Service Abuse|1. TTP Note]] — MITRE mapping, full attack flow, all IMDS endpoints, IMDSv1 vs v2, Capital One breach, CloudTrail and VPC Flow Log detection
- [[20 - Areas/Threat Hunting/Hunt - EC2 IMDS Credential Theft|2. Hunt Hypothesis]] — hunting instance credentials used from unexpected IPs and GetCallerIdentity spikes

### Databricks API Abuse and Privilege Escalation (2026-03-08)
> Source: CapitalOne Security Research — DBXploit (github.com/capitalone/dbxploit)
- [[30 - Knowledge/Cybersecurity/Attack Techniques/Databricks API Abuse and Privilege Escalation|1. TTP Note]] — MITRE mapping (T1528, T1548, T1134, T1537), step-by-step technique breakdown, full module reference, API endpoints, CrowdStrike FQL and Databricks SQL detection queries
- [[20 - Areas/Threat Hunting/Hunt - Databricks Credential Abuse and Privilege Escalation|2. Hunt Hypothesis]] — 7-step hunt plan targeting bulk secret enumeration, SCIM role modification, job impersonation, token fingerprinting, and cross-stage correlation

### AWS Secrets Manager, SSM Lateral Movement & STS Cross-Account (2026-03-13)
> Source: hackingthe.cloud — Role Chain Juggling, Run Shell Commands on EC2, Intercept SSM Communications, Misconfigured Trust Policies, AWS Organizations Defaults, Survive Key Deletion with GetFederationToken
- [[30 - Knowledge/Cybersecurity/Attack Techniques/AWS Secrets Manager and Parameter Store Attacks|1. TTP Note]] — MITRE mapping, IAM permissions tables, all enumeration commands, CloudTrail data event gap, attack chains, kill chain correlation query
- [[20 - Areas/Threat Hunting/Hunt - AWS Secrets Manager Credential Harvesting|1b. Hunt Hypothesis]] — hunting enumeration from new identities, bulk secret access, IAM→secrets correlation
- [[30 - Knowledge/Cybersecurity/Attack Techniques/AWS SSM Lateral Movement and Command Execution|2. TTP Note]] — MITRE mapping (T1651), all 5 methods, alternative SSM document denylist bypass, CloudTrail command content redaction gap, 6 attack chains
- [[20 - Areas/Threat Hunting/Hunt - AWS SSM Lateral Movement|2b. Hunt Hypothesis]] — hunting SendCommand from unexpected identities, lateral sweep patterns, alternative document usage
- [[30 - Knowledge/Cybersecurity/Attack Techniques/AWS STS AssumeRole and Cross-Account Attacks|3. TTP Note]] — MITRE mapping (T1078.004, T1548, T1550.001, T1134), all 4 attack paths, wildcard trust policy examples, cross-account detection queries
- [[20 - Areas/Threat Hunting/Hunt - AWS STS AssumeRole and Cross-Account Attacks|3b. Hunt Hypothesis]] — hunting role chain juggling, OrganizationAccountAccessRole assumptions, GetFederationToken with admin policy, cross-account pivoting

### ClickFix macOS via Script Editor (2026-04-10)
> Source: Jamf Threat Labs — Thijs Xhaflaire, ClickFix macOS: Script Editor & Atomic Stealer
- [[30 - Knowledge/Cybersecurity/Malware & TTPs/ClickFix macOS Script Editor and Atomic Stealer - Research Extraction|1. Research Extraction]] — full IOCs, obfuscation techniques, macOS 15.4 bypass context, xattr/Gatekeeper evasion
- [[30 - Knowledge/Cybersecurity/Attack Techniques/ClickFix macOS via Script Editor|2. TTP Note]] — step-by-step attack chain, detection opportunities, CrowdStrike FQL and Databricks query stubs
- [[20 - Areas/Threat Hunting/Hunt - ClickFix macOS Script Editor and Atomic Stealer|3. Hunt Hypothesis]] — 7-step hunt plan targeting Script Editor child processes, in-memory decode chains, xattr on /tmp, IOC domains

### macOS Infostealer Data Targeting (2026-03-07)
> Source: Phil Stokes, SentinelOne — Session Cookies, Keychains, SSH Keys & More
- [[30 - Knowledge/Cybersecurity/Attack Techniques/macOS Info Stealer - Data Targeted|1. TTP Note]] — 7 data categories, malware examples, file paths, detection queries

### macOS Gaslight Backdoor (2026-07-10)
> Source: SentinelOne SentinelLABS — Phil Stokes, macOS.Gaslight: Rust Backdoor Turns Prompt Injection on the Analyst, Not the Sandbox
- [[30 - Knowledge/Cybersecurity/Malware & TTPs/macOS Gaslight Backdoor - Research Extraction|1. Research Extraction]] — full IOCs, embedded prompt-injection blob details, C2/persistence/anti-analysis breakdown, DPRK-aligned attribution (BONZAI/AIRPIPE)
- [[30 - Knowledge/Cybersecurity/Attack Techniques/macOS Gaslight Backdoor|2. TTP Note]] — step-by-step attack chain, MITRE mapping, CrowdStrike FQL and Databricks query stubs
- [[20 - Areas/Threat Hunting/Hunt - macOS Gaslight Backdoor|3. Hunt Hypothesis]] — 7-step hunt plan targeting Apple-namespace LaunchAgent masquerading, keychain access, Telegram C2 traffic, standalone CPython fetches, known hashes

### macOS TCC Manipulation via AppleScript (2026-07-25)
> Source: @oj-sec — TChCh-Changes: A Look at macOS TCC Manipulation in the Wild
- [[30 - Knowledge/Cybersecurity/Malware & TTPs/macOS TCC Manipulation - Research Extraction|1. Research Extraction]] — full IOCs, patch status by macOS version, C2 infrastructure, Sapphire Sleet/BlueNoroff/UNC1069 overlap attribution; enriched with macOS 26.4 Terminal paste-block context and confirmed `xprotectd` unified-log telemetry findings
- [[30 - Knowledge/Cybersecurity/Attack Techniques/macOS TCC Manipulation via AppleScript|2. TTP Note]] — step-by-step attack chain, MITRE mapping, CrowdStrike FQL and Databricks query stubs
- [[20 - Areas/Threat Hunting/Hunt - macOS TCC Manipulation|3. Hunt Hypothesis]] — 8-step hunt plan targeting tccd termination, Script Editor compile/sign chains, unattributed TCC.db writes, known C2 domains, and (Step 8) live-response `xprotectd` paste-log correlation
- [[30 - Knowledge/Cybersecurity/Attack Techniques/ClickFix macOS via Script Editor|4. Related enrichment]] — cross-cluster addition documenting why ClickFix pivoted to Script Editor: macOS 26.4/Sequoia 15.4's Terminal paste-block (`ES_EVENT_TYPE_RESERVED_0/1`, `es_event_paste_t`, per Koh M. Nakagawa/OBTS v8 and Patrick Wardle/Objective-See), its 30-day/dev-tools exemption, and confirmed `xprotectd` os_log telemetry (Safe Browsing URL lookup pass, plaintext `"Source process is not a browser"` decision branch)

---

*This index is maintained automatically via the `/hunt-research` workflow. Add new entries manually or run `/hunt-research` to auto-populate.*
