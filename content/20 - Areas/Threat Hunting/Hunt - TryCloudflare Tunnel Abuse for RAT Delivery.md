---
title: Hunt - TryCloudflare Tunnel Abuse for RAT Delivery
date: 2026-08-21
type: hunt
status: active
hypothesis: Threat actors are abusing the free TryCloudflare tunnel service (trycloudflare.com) as a disposable delivery layer for a multi-stage RAT infection chain, which would manifest as robocopy/WebDAV connections to trycloudflare.com subdomains, cscript.exe executing .wsf files from %TEMP%, python.exe running from non-standard paths, and suspended processes (notepad.exe) initiating outbound connections consistent with Early Bird APC injection.
priority: high
platform: CrowdStrike, Databricks
mitre_id: T1566.001, T1204.002, T1027.012, T1036, T1218, T1059.003, T1059.006, T1055, T1620, T1547.001, T1572, T1071.001, T1041
tags:
  - type/hunt
  - status/active
  - platform/windows
  - platform/crowdstrike
  - platform/databricks
  - category/rat
  - category/defense-evasion
---

## Hypothesis

> *"I believe SERPENTINE#CLOUD or a similar campaign abusing TryCloudflare tunnels for RAT delivery is present in the environment because the technique relies on Cloudflare's own reputable domain/TLS infrastructure to evade domain-reputation and DPI-based defenses, which would manifest as robocopy/WebDAV traffic to trycloudflare.com subdomains, cscript.exe executing dropped .wsf files, obfuscated batch/Python execution chains, and suspended-process network activity indicative of Early Bird APC injection."*

**Why this is worth hunting:**
- `trycloudflare.com` subdomains are frequently allowlisted or simply unmonitored because the parent domain is reputationally clean — signature/reputation-based network defenses are unlikely to catch this delivery layer
- The campaign has been under active, iterative development since at least November 2025 (three observed evolution phases), meaning static IOCs (hashes, specific subdomains) age out quickly — behavioral hunting on the delivery mechanism itself is far more durable
- The final payload (Donut-packed shellcode via Early Bird APC injection) never touches disk, making file-based detection alone insufficient — process-behavior hunting is required
- Commodity RATs delivered (AsyncRAT, Remcos) are broadly available and widely used across many campaigns beyond this specific cluster, so hits here may surface unrelated but equally serious intrusions

## Assumptions & Scope

- **Environment:** Windows endpoints enrolled in CrowdStrike Falcon with process, file, and DNS telemetry enabled
- **Timeframe:** Look back 90 days given the technique has been continuously active and evolving since November 2025; this is a durable delivery pattern, not a single burst campaign
- **Data sources:** CrowdStrike process events, file events, DNS/network events; Databricks unified log tables
- **Assumptions:**
  - No legitimate business process in this environment uses `robocopy` to pull files over a WebDAV path on a `trycloudflare.com` subdomain — if Cloudflare Tunnel is used legitimately, it should be via `cloudflared` with named/persistent tunnels, not ephemeral `trycloudflare.com` random subdomains
  - `cscript.exe` executing `.wsf` files from `%TEMP%` is rare in a managed environment; legitimate WSH usage is typically from known application directories
  - `python.exe` running from user-profile temp/appdata paths (rather than a managed Python install) is anomalous unless the environment has a known developer population — tune accordingly
  - `notepad.exe` (or another commonly-abused native binary) making outbound network connections is never legitimate

## Hunt Plan

1. **Hunt for robocopy/WebDAV traffic to trycloudflare.com**
   Search for `robocopy` process creation where the command line references a `trycloudflare[.]com@SSL\DavWWWRoot` path — the highest-confidence, most specific indicator of this delivery chain's Stage 1→2 transition.

2. **Hunt for cscript.exe executing .wsf from %TEMP%**
   Search for Windows Script Host (`cscript.exe`/`wscript.exe`) executing `.wsf` files from `%TEMP%` or other user-writable temp locations, especially when the parent process is `cmd.exe` spawned by an LNK.

3. **Hunt for DNS queries to trycloudflare.com subdomains**
   Broad net: any DNS resolution to `*.trycloudflare.com`. Expect false positives from legitimate Cloudflare Tunnel users — cross-reference against a known-good allowlist of sanctioned tunnel use cases.

4. **Hunt for python.exe executing from non-standard paths**
   Search for `python.exe` process creation where the executing path is not a recognized Python installation directory (not `C:\Python*`, not under `Program Files`, not a known dev-tooling path).

5. **Hunt for suspended-process network activity (Early Bird APC signature)**
   Correlate process creation with `CREATE_SUSPENDED`-style behavior (if visible in telemetry) or, more practically, correlate a commonly-abused native binary (`notepad.exe`) being created and then shortly after initiating an outbound network connection — atypical for that binary under any legitimate use.

6. **Hunt for Startup-folder persistence drops**
   Search for new `.vbs`/`.bat` file writes to `\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\` shortly following any of the above signals.

7. **Hash hunt for known SERPENTINE#CLOUD artifacts**
   Search all file write and execution events for the known SHA256 hashes documented in [[Malware & TTPs/TryCloudflare Tunnel Abuse for RAT Delivery - Research Extraction]] — useful for retroactive sweep, but expect these to age out quickly given active campaign iteration.

## Queries

### CrowdStrike FQL

```
// Hunt 1: robocopy pulling payloads over a trycloudflare.com WebDAV tunnel
#repo=base_sensor #event_simpleName=ProcessRollup2
| ImageFileName=/robocopy/i
| CommandLine=/trycloudflare\.com@SSL\\DavWWWRoot/i
| select(Timestamp, ComputerName, UserName, CommandLine, ParentBaseFileName)
| sort(-Timestamp)
```

```
// Hunt 2: cscript.exe/wscript.exe executing .wsf from %TEMP%
#repo=base_sensor #event_simpleName=ProcessRollup2
| ImageFileName=/(cscript|wscript)\.exe/i
| CommandLine=/\\AppData\\Local\\Temp\\.*\.wsf/i
| select(Timestamp, ComputerName, UserName, CommandLine, ParentBaseFileName)
| sort(-Timestamp)
```

```
// Hunt 3: DNS queries to trycloudflare.com subdomains
#repo=base_sensor #event_simpleName=DnsRequest
| DomainName=/\.trycloudflare\.com$/i
| select(Timestamp, ComputerName, UserName, ImageFileName, DomainName)
| sort(-Timestamp)
```

```
// Hunt 4: python.exe executing from a non-standard path
#repo=base_sensor #event_simpleName=ProcessRollup2
| ImageFileName=/python\.exe/i
| !FileName=/(C:\\Python|\\Program Files\\|\\AppData\\Local\\Programs\\Python)/i
| select(Timestamp, ComputerName, UserName, FileName, CommandLine)
| sort(-Timestamp)
```

```
// Hunt 5: notepad.exe (or similar) creating outbound network connections
#repo=base_sensor #event_simpleName=/(ProcessRollup2|NetworkConnectIP4)/
| ImageFileName=/notepad\.exe/i
| select(Timestamp, ComputerName, UserName, ImageFileName, RemoteAddressIP4, RemotePort)
| sort(-Timestamp)
```

```
// Hunt 6: new .vbs/.bat writes to the Startup folder
#repo=base_sensor #event_simpleName=/(FileCreateInfo|FileWriteInfo)/
| TargetFileName=/Start Menu\\Programs\\Startup\\.*\.(vbs|bat)$/i
| select(Timestamp, ComputerName, UserName, TargetFileName, ImageFileName)
| sort(-Timestamp)
```

```
// Hunt 7: hash match — known SERPENTINE#CLOUD artifacts
#repo=base_sensor #event_simpleName=/(ProcessRollup2|NewExecutableWritten)/
| SHA256HashData=(AC6EB3435CEC6058FFEA590AC51507B3313A74EA07893B984F2D87BE12E17027, 4D2FCCAD69BB02305948814F1AA6EF76C85423EB780EC5F3751B7FFBF8B74CA3C, 715CEF51FFCFAEC05A080A0E0DB4D88BB5123E2ADE4A1C72FD8C10F412310C1D)
| select(Timestamp, ComputerName, UserName, TargetFileName, CommandLine)
```

### Databricks SQL

```sql
-- Hunt 1: robocopy pulling payloads over a trycloudflare.com WebDAV tunnel
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  command_line,
  parent_base_file_name
FROM crowdstrike.process_events
WHERE image_file_name RLIKE '.*robocopy.*'
  AND command_line RLIKE '.*trycloudflare\\.com@SSL\\\\DavWWWRoot.*'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- Hunt 2: cscript.exe/wscript.exe executing .wsf from %TEMP%
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  command_line,
  parent_base_file_name
FROM crowdstrike.process_events
WHERE image_file_name RLIKE '.*(cscript|wscript)\\.exe'
  AND command_line RLIKE '.*\\\\AppData\\\\Local\\\\Temp\\\\.*\\.wsf'
ORDER BY timestamp DESC
LIMIT 500;
-- TODO: tune exclusions — known internal WSH-based logon/admin scripts
```

```sql
-- Hunt 3: DNS queries to trycloudflare.com subdomains
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
-- TODO: tune exclusions — sanctioned internal Cloudflare Tunnel use cases
```

```sql
-- Hunt 4: python.exe executing from a non-standard path
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
-- TODO: tune exclusions — developer/build endpoints with non-standard Python installs (pyenv, venv, uv)
```

```sql
-- Hunt 5: notepad.exe (or similar) creating outbound network connections
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  image_file_name,
  remote_address,
  remote_port
FROM crowdstrike.network_events
WHERE image_file_name RLIKE '.*notepad\\.exe'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- Hunt 6: new .vbs/.bat writes to the Startup folder
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  target_file_name,
  image_file_name
FROM crowdstrike.file_events
WHERE target_file_name RLIKE '.*Start Menu\\\\Programs\\\\Startup\\\\.*\\.(vbs|bat)$'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- Hunt 7: hash match — known SERPENTINE#CLOUD artifacts
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  target_file_name,
  sha256_hash
FROM crowdstrike.file_events
WHERE sha256_hash IN (
  'AC6EB3435CEC6058FFEA590AC51507B3313A74EA07893B984F2D87BE12E17027',
  '4D2FCCAD69BB02305948814F1AA6EF76C85423EB780EC5F3751B7FFBF8B74CA3C',
  '715CEF51FFCFAEC05A080A0E0DB4D88BB5123E2ADE4A1C72FD8C10F412310C1D'
)
ORDER BY timestamp DESC;
```

## Findings

### Hits
_(No results yet — hunt not executed)_

### False Positives / Tuning Notes
- **Hunt 1 (robocopy/WebDAV):** No known legitimate use case for `robocopy` against a `trycloudflare.com` WebDAV path — this should be treated as very high confidence if it fires at all.
- **Hunt 2 (cscript/.wsf in %TEMP%):** Some legacy internal logon or software-deployment scripts use WSH from temp locations — confirm against a known-script inventory before escalating.
- **Hunt 3 (DNS to trycloudflare.com):** Expect real false positives — Cloudflare Tunnel is a legitimate product used by developers for local dev-server exposure and by some SaaS integrations. Build an allowlist of sanctioned tunnel subdomains/use cases; prioritize hits correlated with Hunt 1 or Hunt 2.
- **Hunt 4 (non-standard python.exe):** Developer, data science, and CI/build endpoints will generate significant noise — exclude known dev asset tags/ComputerName patterns.
- **Hunt 5 (notepad.exe network activity):** Extremely low false-positive rate expected — `notepad.exe` has no legitimate networking behavior. Treat any hit as high priority.
- **Hunt 6 (Startup folder .vbs/.bat):** Some legitimate software installers drop Startup-folder shortcuts/scripts — verify the file is a script (not a `.lnk` shortcut) and correlate with other hunt hits before escalating.
- **Hunt 7 (hash match):** Static hashes from this campaign age out quickly given active operator iteration — treat a miss as inconclusive, rely primarily on Hunts 1, 2, and 5 for durable detection.

## Outcome
- [ ] No evidence of TryCloudflare tunnel RAT delivery activity found
- [ ] Suspicious activity found — escalate for investigation
- [ ] Detection rule created based on hunt findings

## Related Notes
- [[Attack Techniques/TryCloudflare Tunnel Abuse for RAT Delivery]]
- [[Malware & TTPs/TryCloudflare Tunnel Abuse for RAT Delivery - Research Extraction]]
- [[40 - Resources/Query Library/Hunt Queries]]
- [[20 - Areas/Detection Engineering/Detections]]
