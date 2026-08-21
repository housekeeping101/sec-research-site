---
title: Cloudflare Workers Dead-Drop Resolver C2
date: 2026-08-21
type: ttp
mitre_id: T1566.002, T1021.002, T1037.001, T1574.002, T1140, T1132, T1071.001, T1008, T1550.001, T1649
mitre_tactic: Initial Access, Lateral Movement, Persistence, Defense Evasion, Command and Control, Credential Access
threat_actors: [Unnamed Chinese state-sponsored APT (Taiwan-targeting, JSAC 2026 / CyCraft); Gamaredon (Russia-aligned, convergent technique adopter per ESET/SOCPrime)]
tools_used: [Cloudflare Workers, Microsoft Graph API, Outlook API, Google Sheets, SoftEther VPN, GRAPHBROTLI, GRAPHRELOOK, RCREMARK]
platforms: [Windows, Cloud/SaaS]
tags:
  - type/ttp
  - status/active
  - platform/windows
  - platform/cloud
  - category/c2
  - category/defense-evasion
  - category/apt
source:
  url: https://www.cycraft.com/en/post/ddr-apt-en-20260331
  author: CyCraft Technology
  date: 2026-03-31
---

## Summary
Dead-drop resolvers (DDRs) let malware discover its live C2 server address at runtime by reading a publicly-accessible page or API response hosted on a trusted third-party service, instead of hardcoding a C2 domain into the sample. This technique — documented in depth in a Chinese state-sponsored campaign against Taiwan (CyCraft, JSAC 2026) and independently converged upon by Gamaredon (ESET, 2026) — uses Cloudflare Workers, Microsoft Graph API, Outlook, and Google Sheets as DDR hosts, laundering C2 resolution through infrastructure defenders already trust and rarely block wholesale.

## How It Works

### Step 1 — Initial Compromise & Lateral Movement (T1566.002, T1021.002)
- Phishing campaign compromises an internal endpoint
- Actor moves laterally via SMB/Windows Admin Shares using harvested high-privilege credentials

### Step 2 — Stealthy Execution via Ephemeral GPO Tampering (T1037.001)
- Rather than deploying a persistent malicious logon script, the actor temporarily modifies a legitimate Group Policy logon script (`gpupdate.bat`) or a legitimate-looking file (`log.js`, Node.js variant) to trigger payload execution
- Restores the original file content immediately after execution, minimizing the window in which file-integrity monitoring would catch the tampering — this is as much an anti-forensic technique as an execution technique

### Step 3 — Privilege Escalation via AD CS Abuse (T1649)
- Exploits Active Directory Certificate Services misconfigurations to escalate from a low-privilege foothold to Domain Admin:
  - **ESC1** — certificate templates with overly permissive Enroll rights granted to "Domain/Authenticated Users"
  - **ESC3** — abuse of Enrollment Agent templates
  - **ESC8** — NTLM relay attacks against ADCS Web Enrollment
  - **ESC11** — NTLM relay attacks against RPC Certificate Enrollment
- These are configuration weaknesses common in real-world AD deployments, not novel exploits requiring 0-days

### Step 4 — Persistence via SoftEther VPN
- Deploys SoftEther VPN post-escalation for stable, low-friction remote access into the target network, independent of the initial phishing foothold

### Step 5 — Dead-Drop Resolver C2 (T1071.001, T1132, T1140, T1550.001, T1008)
Three parallel, redundant DDR channels are used to resolve live C2 addresses at runtime:

**Cloud services (GRAPHBROTLI, Go-based):**
- Authenticates to Microsoft Graph API via OAuth2 **Client Credentials Grant** using embedded `client_id`/`client_secret` — no user interaction required (T1550.001)
- Retrieves the organization's user list, then reads operator commands hidden in a specific user's `streetAddress` attribute (trigger word `"start"`)
- Commands are compressed with Brotli and encoded with Base91 (T1132 Data Encoding) before being embedded in the attribute field

**Outlook API (GRAPHRELOOK):**
- Receives operator commands via messages sent to/from an attacker-controlled Outlook account
- Delivered onto the host via DLL side-loading — `U-Messenger.exe` loads a malicious `version.dll` (T1574.002)
- Executes shellcode decrypted from `config.dat`

**Cloudflare Workers (RCREMARK):**
- Traditional RC4-encrypted, Base64-obfuscated backdoor, but its C2 backend is fronted by a `*.workers.dev` Cloudflare Workers subdomain
- Commands are extracted from HTML comments on the fronted page using the regex `<!--remark:\s*([A-Za-z0-9+/=]+)\s*-->` — hidden inside what looks like ordinary webpage markup (T1140 Deobfuscate/Decode Files or Information)

- A fourth, lower-tier channel — compromised legacy websites (suspected via a GoWeb2 framework SQL injection vulnerability) — provides additional fallback DDR hosting (T1008 Fallback Channels)

### Step 6 — Command Execution & Data Operations
- RCREMARK exposes a full remote-shell command set: `run`, `rate` (heartbeat tuning), `drives`, `ls`, `mkdir`/`rmdir`, `rm`, `cp`, `cat`, `put`

## Detection Opportunities

### Key Log Sources
- **Cloud identity/SaaS logs (Entra ID / M365 audit logs):** OAuth2 app registrations using Client Credentials Grant with unusual Graph API scopes (User.Read.All and similar bulk-enumeration permissions); Graph API calls reading/writing user attribute fields like `streetAddress` outside normal HR/IT workflows
- **Network/DNS:** Outbound HTTPS to `*.workers.dev` subdomains from endpoint processes with no legitimate developer/business justification
- **Endpoint file-integrity monitoring:** Modify-then-restore events on `gpupdate.bat` or other GPO logon scripts within a short time window
- **Endpoint telemetry (EDR):** `U-Messenger.exe` loading an unexpected/unsigned `version.dll`; NTLM authentication attempts against ADCS Web Enrollment (`certsrv`) or RPC endpoints from non-standard sources

### Behavioral Indicators
- A service principal or application authenticating to Microsoft Graph with Client Credentials Grant, then enumerating the full org user list — unusual for most legitimate app integrations, which scope to specific users/groups
- Outlook mailbox receiving/sending messages with no human-readable content, at regular heartbeat-like intervals, to/from an external or newly-created account
- A GPO logon script's file hash or last-modified timestamp changing and then reverting within a single monitoring window
- NTLM relay traffic targeting ADCS endpoints from a host that has no legitimate reason to enroll certificates

### Artifacts Left Behind
- Modified-then-restored `gpupdate.bat` (may only be visible via file-integrity monitoring with sufficiently granular polling, or via Windows Event Log 4663/4656 object-access auditing on the file)
- `version.dll` side-loaded alongside `U-Messenger.exe`
- `config.dat` encrypted configuration/shellcode blob
- C2 domains and MD5 hashes documented in [[Malware & TTPs/Cloudflare Workers Dead-Drop Resolver C2 - Research Extraction]]

## Query Stubs

### CrowdStrike FQL

```
// U-Messenger.exe loading an unexpected version.dll (DLL side-loading)
#repo=base_sensor #event_simpleName=ImageHash
| ImageFileName=/U-Messenger\.exe/i
| ModuleFileName=/version\.dll$/i
| select(Timestamp, ComputerName, UserName, ImageFileName, ModuleFileName, SHA256HashData)
| sort(-Timestamp)
```

```
// Outbound connections to Cloudflare Workers subdomains
#repo=base_sensor #event_simpleName=/(DnsRequest|NetworkConnectIP4)/
| DomainName=/\.workers\.dev$/i
| select(Timestamp, ComputerName, UserName, ImageFileName, DomainName)
| sort(-Timestamp)
```

```
// NTLM relay attempts against ADCS Web Enrollment endpoints
#repo=base_sensor #event_simpleName=/(NetworkConnectIP4|AuthActivityAuditLog)/
| TargetPort=(80, 443)
| RequestUri=/certsrv/i
| select(Timestamp, ComputerName, UserName, RemoteAddressIP4, RequestUri)
| sort(-Timestamp)
```

```
// Hash match on known GRAPHBROTLI/GRAPHRELOOK/RCREMARK artifacts (MD5 — lower confidence)
#repo=base_sensor #event_simpleName=/(ProcessRollup2|NewExecutableWritten)/
| MD5HashData=(6affcbf6607ee163a49bb750ae1397c1, b29ff0af33b38ec98e62a5c24d1dd06d, 45c4c4d4224c413408450e965c618742, 529abd9cf61fbab99f440e4134f27fd8)
| select(Timestamp, ComputerName, UserName, TargetFileName, CommandLine)
```

### Databricks SQL

```sql
-- U-Messenger.exe loading an unexpected version.dll
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  image_file_name,
  module_file_name,
  sha256_hash
FROM crowdstrike.module_events
WHERE image_file_name RLIKE '.*U-Messenger\\.exe'
  AND module_file_name RLIKE '.*version\\.dll$'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- Outbound connections to Cloudflare Workers subdomains
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  image_file_name,
  domain_name
FROM crowdstrike.dns_events
WHERE domain_name RLIKE '.*\\.workers\\.dev$'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- OAuth2 Client Credentials Grant apps enumerating the full user directory (M365/Entra audit log)
SELECT
  timestamp,
  application_id,
  application_display_name,
  operation,
  result_status
FROM m365.audit_events
WHERE operation IN ('Add service principal.', 'Consent to application.')
   OR (operation = 'List users.' AND grant_type = 'client_credentials')
ORDER BY timestamp DESC
LIMIT 500;
-- TODO: tune exclusions — known approved automation/service accounts with legitimate bulk user-read scopes
```

```sql
-- Hash match on known GRAPHBROTLI/GRAPHRELOOK/RCREMARK artifacts (MD5)
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  target_file_name,
  md5_hash
FROM crowdstrike.file_events
WHERE md5_hash IN (
  '6affcbf6607ee163a49bb750ae1397c1',
  'b29ff0af33b38ec98e62a5c24d1dd06d',
  '45c4c4d4224c413408450e965c618742',
  '529abd9cf61fbab99f440e4134f27fd8'
)
ORDER BY timestamp DESC;
```

## Threat Actor Usage

| Actor | Notes |
|---|---|
| Unnamed Chinese state-sponsored APT (Taiwan-targeting) | Documented by CyCraft at JSAC 2026; active since 2024 against Taiwan government and manufacturing sectors. Not attributed to Gamaredon or any other named cluster — this is the primary source for the full DDR/AD CS/GRAPHBROTLI-GRAPHRELOOK-RCREMARK tradecraft documented in this note. |
| Gamaredon (Russia-aligned) | Per ESET (June 2026, via SOCPrime), independently adopted the same Cloudflare Workers/Tunnels + dead-drop-resolver technique class (Telegram/Telegraph/Teletype DDRs) within its 2025–2026 "Gamma" tooling refresh, targeting Ukraine. Unrelated campaign — evidence of convergent tradecraft adoption, not shared infrastructure or coordination with the Taiwan-targeting actor. |

## References
- [Infrastructure-Less Adversary: C2 Laundering via Dead-Drop Resolvers and the Microsoft Graph API — CyCraft (JSAC 2026, 2026-03-31)](https://www.cycraft.com/en/post/ddr-apt-en-20260331)
- [Infrastructure-less Adversary: C2 Laundering via Dead-Drop Resolvers — JSAC 2026 conference paper (Wei-Chieh Chao, Shih-Min Chan)](https://jsac.jpcert.or.jp/archive/2026/pdf/JSAC2026_1_8_wei-chieh_chao_shih-min_chan_en.pdf)
- [Gamaredon in 2025: Uses Tunnels, Workers, Dead Drops, and New Alliances — SOCPrime, summarizing ESET Research (2026-06-30)](https://socprime.com/active-threats/gamaredon-in-2025-tunnels-workers-dead-drops-and-new-alliances/)

## Related Notes
- [[Malware & TTPs/Cloudflare Workers Dead-Drop Resolver C2 - Research Extraction]]
- [[20 - Areas/Threat Hunting/Hunt - Cloudflare Workers Dead-Drop Resolver C2]]
- [[Attack Techniques/TryCloudflare Tunnel Abuse for RAT Delivery]] — related Cloudflare-infrastructure-abuse technique using Tunnels instead of Workers for delivery
