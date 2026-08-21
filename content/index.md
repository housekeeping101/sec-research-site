---
title: Security Research Notes
---

# Research Index

A living index of all research notes in the vault. Updated each time a new note is created through the [[40 - Resources/Research & Hunt Workflow|Research & Hunt Workflow]].

---

## Attack Techniques

| Note | MITRE | Platform | Date |
|---|---|---|---|
| [[Attack Techniques/Abusing Slack for Offensive Operations\|Abusing Slack for Offensive Operations]] | T1539, T1555, T1213.003, T1083 | Windows, macOS | 2026-03-07 |
| [[Attack Techniques/AWS IAM Privilege Escalation\|AWS IAM Privilege Escalation]] | T1078.004, T1548, T1098, T1136.003 | AWS | 2026-03-08 |
| [[Attack Techniques/EC2 Instance Metadata Service Abuse\|EC2 Instance Metadata Service Abuse (IMDS)]] | T1552.005, T1078.004 | AWS | 2026-03-08 |
| [[Attack Techniques/AWS S3 Misconfiguration and Bucket Attacks\|AWS S3 Misconfiguration and Bucket Attacks]] | T1530, T1537, T1190, T1083 | AWS | 2026-03-08 |
| [[Attack Techniques/Databricks API Abuse and Privilege Escalation\|Databricks API Abuse and Privilege Escalation]] | T1087.004, T1528, T1134, T1078.004, T1548, T1552.001, T1537 | Databricks, Cloud | 2026-03-08 |
| [[Attack Techniques/AWS Secrets Manager and Parameter Store Attacks\|AWS Secrets Manager and Parameter Store Attacks]] | T1552.001, T1555, T1083 | AWS | 2026-03-13 |
| [[Attack Techniques/AWS SSM Lateral Movement and Command Execution\|AWS SSM Lateral Movement and Command Execution]] | T1651, T1021, T1059.009 | AWS | 2026-03-13 |
| [[Attack Techniques/AWS STS AssumeRole and Cross-Account Attacks\|AWS STS AssumeRole and Cross-Account Attacks]] | T1078.004, T1548, T1550.001, T1134 | AWS | 2026-03-13 |
| [[Attack Techniques/macOS Info Stealer - Data Targeted\|macOS Info Stealer - Data Targeted]] | T1539, T1555.003, T1115, T1552.004 | macOS | 2026-03-07 |
| [[Attack Techniques/macOS Gaslight Backdoor\|macOS Gaslight Backdoor]] | T1123, T1115, T1056.004, T1571, T1008, T1543.001, T1140, T1027, T1020, T1059.004 | macOS | 2026-07-10 |
| [[Attack Techniques/macOS TCC Manipulation via AppleScript\|macOS TCC Manipulation via AppleScript]] | T1566.001, T1059.002, T1564.004, T1027, T1547, T1217, T1071.001, T1547.015 | macOS | 2026-07-25 |
| [[Attack Techniques/Overlord RAT via Fake Zoom Installer\|Overlord RAT via Fake Zoom Installer]] | T1204.002, T1027, T1140, T1036.005, T1547.014, T1059.004, T1082, T1071.001, T1056.001, T1113, T1123, T1005, T1041 | macOS, Windows | 2026-08-13 |
| [[Attack Techniques/TryCloudflare Tunnel Abuse for RAT Delivery\|TryCloudflare Tunnel Abuse for RAT Delivery]] | T1566.001, T1204.002, T1027.012, T1036, T1218, T1059.003, T1059.006, T1055, T1620, T1547.001, T1572, T1071.001, T1041 | Windows | 2026-08-21 |
| [[Attack Techniques/Cloudflare Workers Dead-Drop Resolver C2\|Cloudflare Workers Dead-Drop Resolver C2]] | T1566.002, T1021.002, T1037.001, T1574.002, T1140, T1132, T1071.001, T1008, T1550.001, T1649 | Windows, Cloud | 2026-08-21 |
| [[Attack Techniques/ClickFix\|ClickFix]] | — | Windows, Linux | — |
| [[Attack Techniques/ClickFix macOS via Script Editor\|ClickFix macOS via Script Editor]] | T1204.001, T1059.004, T1140, T1105, T1218.005 | macOS | 2026-04-10 |
| [[Attack Techniques/Linux Rootkit\|Linux Rootkit]] | — | Linux | — |
| [[Attack Techniques/crypto theft\|Crypto Theft]] | — | — | — |
| [[Attack Techniques/Malware Traffic Analysis\|Malware Traffic Analysis]] | — | — | — |
| [[Attack Techniques/Oauth 2.0 and OpenID Connect\|OAuth 2.0 and OpenID Connect]] | — | Web | — |
| [[Attack Techniques/AWS Pentesting\|AWS Pentesting]] | — | Cloud | — |
| [[Attack Techniques/SQL injection\|SQL Injection]] | — | Web | — |

---

## Malware & TTPs (Research Extractions)

| Note | MITRE | Platform | Date |
|---|---|---|---|
| [[Malware & TTPs/ClickFix macOS Script Editor and Atomic Stealer - Research Extraction\|ClickFix macOS Script Editor and Atomic Stealer]] | T1204.001, T1059.004, T1140, T1105, T1218.005 | macOS | 2026-04-10 |
| [[Malware & TTPs/macOS Gaslight Backdoor - Research Extraction\|macOS Gaslight Backdoor]] | T1123, T1115, T1056.004, T1571, T1008, T1543.001, T1140, T1027, T1020, T1059.004 | macOS | 2026-07-10 |
| [[Malware & TTPs/macOS TCC Manipulation - Research Extraction\|macOS TCC Manipulation]] | T1566.001, T1059.002, T1564.004, T1027, T1547, T1217, T1071.001, T1547.015 | macOS | 2026-07-25 |
| [[Malware & TTPs/Overlord RAT via Fake Zoom Installer - Research Extraction\|Overlord RAT via Fake Zoom Installer]] | T1204.002, T1027, T1140, T1036.005, T1547.014, T1059.004, T1082, T1071.001, T1056.001, T1113, T1123, T1005, T1041 | macOS, Windows | 2026-08-13 |
| [[Malware & TTPs/TryCloudflare Tunnel Abuse for RAT Delivery - Research Extraction\|TryCloudflare Tunnel Abuse for RAT Delivery]] | T1566.001, T1204.002, T1027.012, T1036, T1218, T1059.003, T1059.006, T1055, T1620, T1547.001, T1572, T1071.001, T1041 | Windows | 2026-08-21 |
| [[Malware & TTPs/Cloudflare Workers Dead-Drop Resolver C2 - Research Extraction\|Cloudflare Workers Dead-Drop Resolver C2]] | T1566.002, T1021.002, T1037.001, T1574.002, T1140, T1132, T1071.001, T1008, T1550.001, T1649 | Windows, Cloud | 2026-08-21 |

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
| [[20 - Areas/Threat Hunting/Hunt - ClickFix macOS Script Editor and Atomic Stealer\|Hunt - ClickFix macOS Script Editor and Atomic Stealer]] | Active | T1204.001, T1059.004, T1140, T1105, T1218.005 | macOS | 2026-04-10 |
| [[20 - Areas/Threat Hunting/Hunt - macOS Gaslight Backdoor\|Hunt - macOS Gaslight Backdoor]] | Active | T1123, T1115, T1056.004, T1571, T1543.001, T1020 | macOS | 2026-07-10 |
| [[20 - Areas/Threat Hunting/Hunt - macOS TCC Manipulation\|Hunt - macOS TCC Manipulation]] | Active | T1566.001, T1059.002, T1547, T1217, T1071.001, T1547.015 | macOS | 2026-07-25 |
| [[20 - Areas/Threat Hunting/Hunt - Overlord RAT via Fake Zoom Installer\|Hunt - Overlord RAT via Fake Zoom Installer]] | Active | T1204.002, T1027, T1036.005, T1547.014, T1071.001, T1056.001, T1041 | macOS, Windows | 2026-08-13 |
| [[20 - Areas/Threat Hunting/Hunt - TryCloudflare Tunnel Abuse for RAT Delivery\|Hunt - TryCloudflare Tunnel Abuse for RAT Delivery]] | Active | T1566.001, T1204.002, T1055, T1620, T1547.001, T1572, T1071.001 | Windows | 2026-08-21 |
| [[20 - Areas/Threat Hunting/Hunt - Cloudflare Workers Dead-Drop Resolver C2\|Hunt - Cloudflare Workers Dead-Drop Resolver C2]] | Active | T1566.002, T1021.002, T1574.002, T1071.001, T1550.001, T1649 | Windows, Cloud | 2026-08-21 |

---

## Threat Actors & APTs

| Note | Origin | Motivation | Date |
|---|---|---|---|
| [[Threat Actors & APTs/Scattered Spider\|Scattered Spider]] | — | Financial | — |
| [[Threat Actors & APTs/CHAMELGANG & FRIENDS\|ChamelGang & Friends]] | — | Espionage | — |
| [[Threat Actors & APTs/Bling Libra's Tactical Evolution- The Threat Actor Group Behind ShinyHunters Ransomware\|Bling Libra / ShinyHunters]] | — | Financial | — |

---

## Tools & Platforms

| Note | Category |
|---|---|
| [[Tools & Platforms/CrowdStrike\|CrowdStrike]] | EDR |
| [[Tools & Platforms/Cobalt Strike\|Cobalt Strike]] | C2 |
| [[Tools & Platforms/Ngrok\|Ngrok]] | Tunneling |
| [[Tools & Platforms/Impacket\|Impacket]] | Lateral Movement |
| [[Tools & Platforms/RMM Tools\|RMM Tools]] | Remote Access |
| [[Tools & Platforms/Cloudflare Dev tunnel\|Cloudflare Dev Tunnel]] | Tunneling |

---

## DFIR & Forensics

| Note | Platform | Date |
|---|---|---|
| [[DFIR & Forensics/Forensics/Mac Forensics\|Mac Forensics]] | macOS | — |
| [[DFIR & Forensics/Forensics/Mac Traige\|Mac Triage]] | macOS | — |
| [[DFIR & Forensics/Forensics/Windows Forensics\|Windows Forensics]] | Windows | — |
| [[DFIR & Forensics/Forensics/Forensics\|Forensics General]] | Cross-platform | — |
| [[DFIR & Forensics/Forensics/Apple Silicon Recovery Mode\|Apple Silicon Recovery Mode]] | macOS | 2026-04-18 |

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
- [[Attack Techniques/Abusing Slack for Offensive Operations|1. TTP Note]] — MITRE mapping, detection opportunities, full technical reference (file paths, tools, API endpoints, extraction commands), query stubs
- [[20 - Areas/Threat Hunting/Hunt - Slack Cookie Theft and Session Hijacking|2. Hunt Hypothesis]] — actionable hunt with CrowdStrike FQL and Databricks queries

### AWS IAM Privilege Escalation (2026-03-08)
> Source: hackingthe.cloud — IAM Privilege Escalation (Spencer Gietzen / Rhino Security Labs)
- [[Attack Techniques/AWS IAM Privilege Escalation|1. TTP Note]] — MITRE mapping, step-by-step escalation, 30+ permission paths, Pacu/PMapper commands, CloudTrail detection queries
- [[20 - Areas/Threat Hunting/Hunt - AWS IAM Privilege Escalation|2. Hunt Hypothesis]] — CrowdStrike FQL and Databricks SQL hunting IAM modification events and PassRole patterns

### AWS S3 Misconfiguration Attack Chains (2026-03-08)
> Source: Intigriti — Hacking Misconfigured AWS S3 Buckets; hackingthe.cloud — S3 Bucket Replication Exfiltration
- [[Attack Techniques/AWS S3 Misconfiguration and Bucket Attacks|1. TTP Note]] — MITRE mapping, step-by-step attack paths, misconfiguration types table, all CLI commands, 4 attack chains, CloudTrail and GuardDuty detection
- [[20 - Areas/Threat Hunting/Hunt - AWS S3 Misconfiguration and Exfiltration|2. Hunt Hypothesis]] — hunting replication config changes, bulk GetObject, policy modifications with unknown account IDs

### EC2 IMDS Credential Theft via SSRF (2026-03-08)
> Source: hackingthe.cloud — EC2 Metadata SSRF
- [[Attack Techniques/EC2 Instance Metadata Service Abuse|1. TTP Note]] — MITRE mapping, full attack flow, all IMDS endpoints, IMDSv1 vs v2, Capital One breach, CloudTrail and VPC Flow Log detection
- [[20 - Areas/Threat Hunting/Hunt - EC2 IMDS Credential Theft|2. Hunt Hypothesis]] — hunting instance credentials used from unexpected IPs and GetCallerIdentity spikes

### Databricks API Abuse and Privilege Escalation (2026-03-08)
> Source: CapitalOne Security Research — DBXploit (github.com/capitalone/dbxploit)
- [[Attack Techniques/Databricks API Abuse and Privilege Escalation|1. TTP Note]] — MITRE mapping (T1528, T1548, T1134, T1537), step-by-step technique breakdown, full module reference, API endpoints, CrowdStrike FQL and Databricks SQL detection queries
- [[20 - Areas/Threat Hunting/Hunt - Databricks Credential Abuse and Privilege Escalation|2. Hunt Hypothesis]] — 7-step hunt plan targeting bulk secret enumeration, SCIM role modification, job impersonation, token fingerprinting, and cross-stage correlation

### AWS Secrets Manager, SSM Lateral Movement & STS Cross-Account (2026-03-13)
> Source: hackingthe.cloud — Role Chain Juggling, Run Shell Commands on EC2, Intercept SSM Communications, Misconfigured Trust Policies, AWS Organizations Defaults, Survive Key Deletion with GetFederationToken
- [[Attack Techniques/AWS Secrets Manager and Parameter Store Attacks|1. TTP Note]] — MITRE mapping, IAM permissions tables, all enumeration commands, CloudTrail data event gap, attack chains, kill chain correlation query
- [[20 - Areas/Threat Hunting/Hunt - AWS Secrets Manager Credential Harvesting|1b. Hunt Hypothesis]] — hunting enumeration from new identities, bulk secret access, IAM→secrets correlation
- [[Attack Techniques/AWS SSM Lateral Movement and Command Execution|2. TTP Note]] — MITRE mapping (T1651), all 5 methods, alternative SSM document denylist bypass, CloudTrail command content redaction gap, 6 attack chains
- [[20 - Areas/Threat Hunting/Hunt - AWS SSM Lateral Movement|2b. Hunt Hypothesis]] — hunting SendCommand from unexpected identities, lateral sweep patterns, alternative document usage
- [[Attack Techniques/AWS STS AssumeRole and Cross-Account Attacks|3. TTP Note]] — MITRE mapping (T1078.004, T1548, T1550.001, T1134), all 4 attack paths, wildcard trust policy examples, cross-account detection queries
- [[20 - Areas/Threat Hunting/Hunt - AWS STS AssumeRole and Cross-Account Attacks|3b. Hunt Hypothesis]] — hunting role chain juggling, OrganizationAccountAccessRole assumptions, GetFederationToken with admin policy, cross-account pivoting

### ClickFix macOS via Script Editor (2026-04-10)
> Source: Jamf Threat Labs — Thijs Xhaflaire, ClickFix macOS: Script Editor & Atomic Stealer
- [[Malware & TTPs/ClickFix macOS Script Editor and Atomic Stealer - Research Extraction|1. Research Extraction]] — full IOCs, obfuscation techniques, macOS 15.4 bypass context, xattr/Gatekeeper evasion
- [[Attack Techniques/ClickFix macOS via Script Editor|2. TTP Note]] — step-by-step attack chain, detection opportunities, CrowdStrike FQL and Databricks query stubs
- [[20 - Areas/Threat Hunting/Hunt - ClickFix macOS Script Editor and Atomic Stealer|3. Hunt Hypothesis]] — 7-step hunt plan targeting Script Editor child processes, in-memory decode chains, xattr on /tmp, IOC domains

### macOS Infostealer Data Targeting (2026-03-07)
> Source: Phil Stokes, SentinelOne — Session Cookies, Keychains, SSH Keys & More
- [[Attack Techniques/macOS Info Stealer - Data Targeted|1. TTP Note]] — 7 data categories, malware examples, file paths, detection queries

### macOS Gaslight Backdoor (2026-07-10)
> Source: SentinelOne SentinelLABS — Phil Stokes, macOS.Gaslight: Rust Backdoor Turns Prompt Injection on the Analyst, Not the Sandbox
- [[Malware & TTPs/macOS Gaslight Backdoor - Research Extraction|1. Research Extraction]] — full IOCs, embedded prompt-injection blob details, C2/persistence/anti-analysis breakdown, DPRK-aligned attribution (BONZAI/AIRPIPE)
- [[Attack Techniques/macOS Gaslight Backdoor|2. TTP Note]] — step-by-step attack chain, MITRE mapping, CrowdStrike FQL and Databricks query stubs
- [[20 - Areas/Threat Hunting/Hunt - macOS Gaslight Backdoor|3. Hunt Hypothesis]] — 7-step hunt plan targeting Apple-namespace LaunchAgent masquerading, keychain access, Telegram C2 traffic, standalone CPython fetches, known hashes

### macOS TCC Manipulation via AppleScript (2026-07-25)
> Source: @oj-sec — TChCh-Changes: A Look at macOS TCC Manipulation in the Wild
- [[Malware & TTPs/macOS TCC Manipulation - Research Extraction|1. Research Extraction]] — full IOCs, patch status by macOS version, C2 infrastructure, Sapphire Sleet/BlueNoroff/UNC1069 overlap attribution; enriched with macOS 26.4 Terminal paste-block context and confirmed `xprotectd` unified-log telemetry findings
- [[Attack Techniques/macOS TCC Manipulation via AppleScript|2. TTP Note]] — step-by-step attack chain, MITRE mapping, CrowdStrike FQL and Databricks query stubs
- [[20 - Areas/Threat Hunting/Hunt - macOS TCC Manipulation|3. Hunt Hypothesis]] — 8-step hunt plan targeting tccd termination, Script Editor compile/sign chains, unattributed TCC.db writes, known C2 domains, and (Step 8) live-response `xprotectd` paste-log correlation
- [[Attack Techniques/ClickFix macOS via Script Editor|4. Related enrichment]] — cross-cluster addition documenting why ClickFix pivoted to Script Editor: macOS 26.4/Sequoia 15.4's Terminal paste-block (`ES_EVENT_TYPE_RESERVED_0/1`, `es_event_paste_t`, per Koh M. Nakagawa/OBTS v8 and Patrick Wardle/Objective-See), its 30-day/dev-tools exemption, and confirmed `xprotectd` os_log telemetry (Safe Browsing URL lookup pass, plaintext `"Source process is not a browser"` decision branch)

### Overlord RAT via Fake Zoom Installer (2026-08-13)
> Source: Jamf Threat Labs — Ferdous Saljooki, Fake Zoom Installer Delivers Overlord RAT for macOS
- [[Malware & TTPs/Overlord RAT via Fake Zoom Installer - Research Extraction|1. Research Extraction]] — full IOCs, .NET 10 cross-platform downloader mechanics, garble-obfuscated Go agent capabilities, FlexibleFerret LaunchAgent-label overlap
- [[Attack Techniques/Overlord RAT via Fake Zoom Installer|2. TTP Note]] — step-by-step 8-stage attack chain, MITRE mapping, CrowdStrike FQL and Databricks SQL query stubs
- [[20 - Areas/Threat Hunting/Hunt - Overlord RAT via Fake Zoom Installer|3. Hunt Hypothesis]] — 8-step hunt plan targeting com.zoom LaunchAgent masquerading, embedded PE-in-Mach-O artifacts, C2 domain/port traffic, and Windows parity checks

### Cloudflare Infrastructure Abuse (2026-08-21)
> Sources: Securonix — Tim Peck, Analyzing SERPENTINE#CLOUD; CyCraft — Infrastructure-Less Adversary: C2 Laundering via Dead-Drop Resolvers (JSAC 2026); SOCPrime/ESET — Gamaredon in 2025
> Two related but distinct techniques abusing different Cloudflare products, researched together from a single captured lead:
- [[Malware & TTPs/TryCloudflare Tunnel Abuse for RAT Delivery - Research Extraction|1a. Research Extraction — TryCloudflare Tunnel Abuse]] — SERPENTINE#CLOUD campaign, full 5-stage attack chain (LNK→WSF→BAT→Python→Donut), Early Bird APC injection, IOCs
- [[Attack Techniques/TryCloudflare Tunnel Abuse for RAT Delivery|1b. TTP Note]] — step-by-step attack chain, MITRE mapping, CrowdStrike FQL and Databricks SQL query stubs
- [[20 - Areas/Threat Hunting/Hunt - TryCloudflare Tunnel Abuse for RAT Delivery|1c. Hunt Hypothesis]] — 7-step hunt plan targeting WebDAV/robocopy tunnel traffic, WSH execution, Early Bird APC signatures
- [[Malware & TTPs/Cloudflare Workers Dead-Drop Resolver C2 - Research Extraction|2a. Research Extraction — Cloudflare Workers Dead-Drop Resolver C2]] — Taiwan-targeting APT campaign (CyCraft/JSAC 2026), GRAPHBROTLI/GRAPHRELOOK/RCREMARK malware, AD CS ESC1/3/8/11 abuse, ephemeral GPO tampering; Gamaredon convergent-adoption context
- [[Attack Techniques/Cloudflare Workers Dead-Drop Resolver C2|2b. TTP Note]] — step-by-step attack chain, MITRE mapping, CrowdStrike FQL and Databricks SQL query stubs
- [[20 - Areas/Threat Hunting/Hunt - Cloudflare Workers Dead-Drop Resolver C2|2c. Hunt Hypothesis]] — 7-step hunt plan targeting Graph API OAuth abuse, Workers subdomain traffic, DLL side-loading, ADCS NTLM relay, GPO script tampering

---

*This index is maintained automatically via the `/hunt-research` workflow. Add new entries manually or run `/hunt-research` to auto-populate.*
