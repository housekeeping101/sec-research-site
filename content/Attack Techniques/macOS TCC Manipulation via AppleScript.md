---
title: macOS TCC Manipulation via AppleScript
date: 2026-07-25
type: ttp
mitre_id: T1566.001, T1059.002, T1564.004, T1027, T1547, T1217, T1071.001, T1547.015
mitre_tactic: Initial Access, Execution, Defense Evasion, Privilege Escalation, Discovery, Command and Control, Persistence
threat_actors: [Sapphire Sleet (overlap, unconfirmed), BlueNoroff, UNC1069]
tools_used: [osacompile, codesign, sqlite, curl, Script Editor]
platforms: [macOS]
tags:
  - type/ttp
  - status/active
  - platform/macos
  - category/privilege-escalation
  - category/defense-evasion
source:
  url: https://oj-sec.com/blog/20260721/
  author: "@oj-sec"
  date: 2026-07-21
---

## Summary
Attackers deliver AppleScript-based malware (via spearphished `.scpt` files opened in Script Editor) that runs a multi-stage payload chain to directly manipulate the macOS TCC (Transparency, Control and Consent) database. By writing permission rows into `TCC.db` and force-restarting `tccd`, the attacker grants a follow-on process elevated access (Full Disk Access, Automation, etc.) without triggering the normal user consent dialog, enabling privilege inheritance for later-stage tooling. The technique is patched on current macOS releases but remains viable wherever an attacker already holds Full Disk Access.

## How It Works

### Step 1 — Delivery (T1566.001)
- Victim receives a malicious `.scpt` file via spearphishing, often with a custom lure document and a fake "Compatibility Wizard" pretext with a styled progress bar tailored to the target organization
- File is opened and run natively in Script Editor — no code signing or Gatekeeper warning blocks unsigned `.scpt` execution in this context

### Step 2 — First-Stage Execution & Fingerprinting (T1059.002, T1027)
- First-stage AppleScript hides its logic among 1000+ padding/blank lines
- Runs `uname -m` and `sw_vers -productVersion` to select the correct downstream payload/exploit path for the target's architecture and OS version
- Downloads next-stage payload via `curl -sLk`

### Step 3 — Payload Compilation & Signing (T1027, T1564.004)
- Compiles a run-only AppleScript app bundle: `osacompile -s -x -l AppleScript -o ptApp`
- Ad hoc signs the bundle: `codesign --force --deep --sign`
- Sets `LSUIElement=true` so the resulting app has no Dock icon

### Step 4 — TCC Manipulation (T1547, T1217)
- Terminates the user's `tccd` process to force a re-read of the permissions database:
  ```
  ps -xo pid,user,comm | grep tccd | awk -v u=$(whoami) '$2==u {print $1}' | xargs kill -9
  ```
- Uses `sqlite` to directly write permission rows into `TCC.db` (system: `/Library/Application Support/com.apple.TCC/TCC.db`; user: `~/Library/Application Support/com.apple.TCC/TCC.db`), synthetically granting access without a consent prompt
- Where Finder AppleEvents authorization can still be abused (pre-patch), leverages Finder to perform privileged filesystem operations on the attacker's behalf

### Step 5 — Discovery (T1217)
- Enumerates `/Users`, `/Applications`, `~/Downloads`, `~/Documents`, `~/Desktop`
- Collects process listings and hardware identifiers (device serial) for C2 telemetry

### Step 6 — Persistence (T1547.015)
- Drops a LaunchAgent under `~/Library/LaunchAgents/` for the backdoor

### Step 7 — Command & Control (T1071.001)
- Beacons over HTTP(S) using WordPress-path-masquerading C2 endpoints (`/wp-includes/...`, `/wp-content/plugins/...`)
- Telemetry submission and command polling via `/.php?req=contact&dv=[device_serial]` and `/.php?req=tell&dv=[device_serial]`
- Config persisted at `~/Library/Application Support/Applets/.svc.conf`; temporary `.scpt` files deleted post-execution to reduce forensic footprint

## Detection Opportunities

### Key Log Sources
- Endpoint Security Framework (ESF) `tcc_modify` events, cross-referenced against actual on-disk `TCC.db` contents
- Process execution telemetry for `osacompile`, `codesign`, and `sqlite` invoked as children of Script Editor
- Command-line logging capturing `kill -9` targeting `tccd`
- Network/DNS logs for the known C2 domains and WordPress-masquerading URI paths
- LaunchAgent file-write events under `~/Library/LaunchAgents/`

### Behavioral Indicators
- User-initiated termination of `tccd` (rare outside of macOS internals/updates)
- `TCC.db` permission rows that exist on disk but have no corresponding EDR/ESF grant event — indicates synthetic insertion
- Script Editor spawning `curl`, `osacompile`, or `codesign` as child processes
- Newly-installed app bundle with `LSUIElement=true` and an ad hoc signature, with no Dock presence
- HTTP requests to `*.php?req=contact` / `*.php?req=tell` with a `dv=` device-serial parameter

### Artifacts Left Behind
- `ptApp.app` bundle (or similarly named run-only compiled AppleScript bundle)
- `~/Library/Application Support/Applets/.svc.conf`
- `~/Library/LaunchAgents/` entries tied to the backdoor
- TCC directory rename artifacts with random suffixes
- Ad hoc code signatures on newly created app bundles

## Query Stubs

### CrowdStrike FQL

```
// tccd process termination via kill -9 (rare in normal operation)
#repo=base_sensor #event_simpleName=/ProcessRollup2/
| CommandLine=/tccd/i
| CommandLine=/kill\s+-9/i
| select(Timestamp, ComputerName, UserName, CommandLine, ParentBaseFileName)
| sort(-Timestamp)
```

```
// Script Editor spawning osacompile/codesign/curl children
#repo=base_sensor #event_simpleName=/ProcessRollup2/
| ParentBaseFileName=/Script Editor/i
| FileName=/(osacompile|codesign|curl)/i
| select(Timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName)
| sort(-Timestamp)
```

```
// TCC.db write access outside of tccd/system processes
#repo=base_sensor #event_simpleName=/(FileWriteInfo|FileOpenInfo)/
| TargetFileName=/com\.apple\.TCC\/TCC\.db$/
| !ImageFileName=/(tccd|syspolicyd)/i
| select(Timestamp, ComputerName, UserName, ImageFileName, TargetFileName)
| sort(-Timestamp)
```

```
// Outbound requests to known TChCh-Changes C2 paths
#repo=base_sensor #event_simpleName=/(DnsRequest|NetworkConnectIP4|HttpRequestHeader)/
| (DomainName=/(cigalsn\.com|ecoferros\.com)/ OR RequestURI=/\.php\?req=(contact|tell)/)
| select(Timestamp, ComputerName, UserName, ImageFileName, DomainName, RequestURI)
| sort(-Timestamp)
```

### Databricks SQL

```sql
-- tccd killed via command line (rare)
SELECT
  timestamp, device_id, computer_name, user_name, command_line, parent_base_file_name
FROM crowdstrike.process_events
WHERE command_line RLIKE '(?i).*tccd.*'
  AND command_line RLIKE '(?i).*kill\\s+-9.*'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- Script Editor spawning compilation/signing/download tooling
SELECT
  timestamp, device_id, computer_name, user_name, file_name, command_line, parent_base_file_name
FROM crowdstrike.process_events
WHERE parent_base_file_name RLIKE '(?i).*Script Editor.*'
  AND file_name RLIKE '(?i).*(osacompile|codesign|curl).*'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- Non-system process writing to TCC.db
SELECT
  timestamp, device_id, computer_name, user_name, image_file_name, target_file_name
FROM crowdstrike.file_events
WHERE target_file_name RLIKE '.*com\\.apple\\.TCC/TCC\\.db$'
  AND image_file_name NOT RLIKE '(?i).*(tccd|syspolicyd).*'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- Outbound traffic to known TChCh-Changes C2 infrastructure
SELECT
  timestamp, device_id, computer_name, user_name, image_file_name, domain_name, request_uri
FROM crowdstrike.network_events
WHERE domain_name RLIKE '.*(cigalsn\\.com|ecoferros\\.com).*'
   OR request_uri RLIKE '.*\\.php\\?req=(contact|tell).*'
ORDER BY timestamp DESC
LIMIT 500;
```

## Threat Actor Usage

| Actor | Notes |
|---|---|
| TChCh-Changes cluster (unnamed, independent) | Primary observed activity; cryptocurrency-sector targeting via AppleScript spearphishing and direct TCC.db manipulation |
| Sapphire Sleet (overlap, unconfirmed) | North Korean state actor; shares delivery method, TCC manipulation implementation, and sector targeting — formal attribution deferred by source |
| BlueNoroff / UNC1069 | Related DPRK-aligned clusters cited in prior reporting (Kaspersky Oct 2025, Mandiant Feb 2026) with tactical overlap |

## References
- [TChCh-Changes: A Look at macOS TCC Manipulation in the Wild (@oj-sec, 2026-07-21)](https://oj-sec.com/blog/20260721/)

## Related Notes
- [[30 - Knowledge/Cybersecurity/Malware & TTPs/macOS TCC Manipulation - Research Extraction]]
- [[20 - Areas/Threat Hunting/Hunt - macOS TCC Manipulation]]
- [[30 - Knowledge/Cybersecurity/Attack Techniques/macOS Info Stealer - Data Targeted]] — related macOS credential/data targeting context
