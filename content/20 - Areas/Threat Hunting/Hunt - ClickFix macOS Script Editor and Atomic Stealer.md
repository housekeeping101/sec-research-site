---
title: Hunt - ClickFix macOS Script Editor and Atomic Stealer
date: 2026-04-10
type: hunt
status: active
hypothesis: Attackers are using the applescript:// URL scheme to invoke Script Editor as a proxy executor for macOS ClickFix payloads, bypassing Terminal paste-command scanning introduced in macOS 15.4, which would manifest as Script Editor spawning shell child processes and binaries being staged and executed from /tmp with quarantine flags removed.
priority: high
platform: CrowdStrike, Databricks
mitre_id: T1204.001, T1059.004, T1140, T1105, T1218.005
tags:
  - type/hunt
  - status/active
  - platform/macos
  - platform/crowdstrike
  - platform/databricks
  - category/infostealer
  - category/defense-evasion
---

## Hypothesis

> *"I believe ClickFix-style social engineering is occurring on macOS endpoints using Script Editor as the execution proxy — bypassing macOS 15.4's Terminal paste-command scanning — which would manifest as Script Editor spawning shell child processes, curl commands with TLS validation disabled, base64/gzip in-memory decode chains, and Mach-O binaries staged in `/tmp` with quarantine flags stripped before execution."*

**Why this is worth hunting:**
- macOS 15.4 introduced Terminal paste-command scanning as a ClickFix defense; attacker pivot to Script Editor renders this control ineffective — endpoints on 15.4 are not protected from this variant
- Script Editor spawning shell processes is effectively never legitimate in an enterprise environment — near-zero false positive rate
- `/tmp` is a common staging location for macOS malware; quarantine stripping via `xattr -c` is a strong behavioral signal with limited benign use
- Atomic Stealer (AMOS) is a commodity infostealer — suggests broad, opportunistic targeting rather than nation-state; potential for wide exposure across macOS fleet

## Assumptions & Scope

- **Environment:** macOS endpoints enrolled in CrowdStrike Falcon with process execution telemetry enabled
- **Timeframe:** Look back 30 days initially; tighten to 7 days if signal is strong
- **Data sources:** CrowdStrike process events, file events, DNS events; Databricks unified log tables
- **Assumptions:**
  - Script Editor (`/Applications/Script Editor.app`) is not used legitimately by enterprise users
  - `xattr -c` on `/tmp` paths is anomalous in this environment
  - No known-good software uses `curl -k` piped to `base64 -d | gunzip | zsh`

## Hunt Plan

1. **Hunt for Script Editor spawning shell or download tools**
   Search for any process where the parent is Script Editor and the child is `zsh`, `bash`, `sh`, `curl`, or `osascript`. This is the highest-confidence signal — should be zero in a normal enterprise environment.

2. **Hunt for `xattr -c` on `/tmp` paths**
   `xattr -c` strips quarantine flags. Combined with a `/tmp` path, this is a strong indicator of Gatekeeper bypass before executing a downloaded binary.

3. **Hunt for in-memory decode/execute chains**
   Look for `zsh` or `bash` commands containing both `base64` and `gunzip` — this is the decode-and-pipe pattern used in stage 2 of this attack.

4. **Hunt for `curl -k` to untrusted external hosts**
   curl with TLS validation disabled to non-approved infrastructure. Cross-reference against known-good update domains.

5. **Hunt for new executables written to `/tmp` followed by `chmod +x` and execution**
   Correlate: file creation in `/tmp` → `chmod +x` on that path → execution of that path. This is the Atomic Stealer binary staging sequence.

6. **DNS/network pivot on known IOC domains**
   Query for DNS lookups or HTTP connections to `dryvecar.com` and `cleanupmac.mssg.me`. Any hit is high-confidence compromise.

7. **Hash hunt for Atomic Stealer binary**
   Search for SHA256 `3d3c91ee762668c85b74859e4d09a2adfd34841694493b82659fda77fe0c2c44` across all file write or execution events.

## Queries

### CrowdStrike FQL

```
// Hunt 1: Script Editor spawning shell or download tools (highest confidence)
#repo=base_sensor #event_simpleName=ProcessRollup2
| ParentImageFileName=/Script Editor/
| ImageFileName=/(zsh|bash|sh|curl|osascript)$/
| select(Timestamp, ComputerName, UserName, ParentImageFileName, ImageFileName, CommandLine)
| sort(-Timestamp)
```

```
// Hunt 2: xattr -c on /tmp — quarantine stripping (Gatekeeper bypass)
#repo=base_sensor #event_simpleName=ProcessRollup2
| ImageFileName=/\/xattr$/
| CommandLine=/-c.*\/tmp\//
| select(Timestamp, ComputerName, UserName, ImageFileName, CommandLine)
| sort(-Timestamp)
```

```
// Hunt 3: In-memory decode/execute — base64 + gunzip piped to zsh
#repo=base_sensor #event_simpleName=ProcessRollup2
| ImageFileName=/(zsh|bash|sh)$/
| CommandLine=/base64/
| CommandLine=/gunzip/
| select(Timestamp, ComputerName, UserName, ImageFileName, CommandLine)
| sort(-Timestamp)
```

```
// Hunt 4: curl -k to external host (TLS bypass)
#repo=base_sensor #event_simpleName=ProcessRollup2
| ImageFileName=/\/curl$/
| CommandLine=/ -k /
| !CommandLine=/(apple\.com|jamf\.com|microsoft\.com|adobe\.com)/
| select(Timestamp, ComputerName, UserName, CommandLine)
| sort(-Timestamp)
```

```
// Hunt 5: New executable in /tmp with subsequent chmod+x
#repo=base_sensor #event_simpleName=NewExecutableWritten
| TargetFileName=/\/tmp\//
| select(Timestamp, ComputerName, UserName, TargetFileName)
| sort(-Timestamp)
```

```
// Hunt 6: DNS lookup for known IOC domains
#repo=base_sensor #event_simpleName=DnsRequest
| DomainName=/(dryvecar\.com|cleanupmac\.mssg\.me|storage-fixes\.squarespace\.com)/
| select(Timestamp, ComputerName, UserName, DomainName)
| sort(-Timestamp)
```

```
// Hunt 7: Hash hunt — Atomic Stealer binary
#repo=base_sensor #event_simpleName=/(ProcessRollup2|NewExecutableWritten)/
| SHA256HashData=3d3c91ee762668c85b74859e4d09a2adfd34841694493b82659fda77fe0c2c44
| select(Timestamp, ComputerName, UserName, TargetFileName, CommandLine)
```

### Databricks SQL

```sql
-- Hunt 1: Script Editor spawning shell processes
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  parent_image_file_name,
  image_file_name,
  command_line
FROM crowdstrike.process_events
WHERE parent_image_file_name LIKE '%Script Editor%'
  AND image_file_name RLIKE '.*(zsh|bash|sh|curl|osascript)$'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- Hunt 2: xattr -c on /tmp (quarantine stripping)
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  command_line
FROM crowdstrike.process_events
WHERE image_file_name LIKE '%/xattr'
  AND command_line LIKE '%-c%/tmp/%'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- Hunt 3: In-memory decode chain (base64 + gunzip piped to zsh)
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  command_line
FROM crowdstrike.process_events
WHERE image_file_name RLIKE '.*(zsh|bash|sh)$'
  AND command_line LIKE '%base64%'
  AND command_line LIKE '%gunzip%'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- Hunt 4: curl with -k flag to non-approved external hosts
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  command_line
FROM crowdstrike.process_events
WHERE image_file_name LIKE '%/curl'
  AND command_line LIKE '% -k %'
  AND command_line NOT RLIKE '.*(apple\.com|jamf\.com|microsoft\.com|adobe\.com).*'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- Hunt 5: New executable written to /tmp
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  target_file_name
FROM crowdstrike.file_events
WHERE event_type IN ('NewExecutableWritten', 'FileCreateInfo')
  AND target_file_name LIKE '/tmp/%'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- Hunt 6: DNS lookups to known IOC domains
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  domain_name
FROM crowdstrike.dns_events
WHERE domain_name RLIKE '.*(dryvecar\.com|cleanupmac\.mssg\.me|storage-fixes\.squarespace\.com).*'
ORDER BY timestamp DESC;
```

```sql
-- Hunt 7: Hash match — Atomic Stealer binary
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  target_file_name,
  sha256_hash
FROM crowdstrike.file_events
WHERE sha256_hash = '3d3c91ee762668c85b74859e4d09a2adfd34841694493b82659fda77fe0c2c44'
ORDER BY timestamp DESC;
```

## Findings

### Hits
_(No results yet — hunt not executed)_

### False Positives / Tuning Notes
- **Hunt 1 (Script Editor children):** No known-good enterprise use case. Developer endpoints with active AppleScript development may generate hits — review CommandLine for benign scripts. Exclude specific developer machines by ComputerName if needed.
- **Hunt 2 (xattr -c on /tmp):** Some package managers or build tools may strip attributes in /tmp during builds. Review parent process for context — if parent is `xcode`, `make`, or `brew`, likely benign.
- **Hunt 3 (base64+gunzip pipe):** Legitimate admin scripts occasionally use base64 encoding. Review CommandLine for URL patterns (http://) as a tiebreaker — benign scripts rarely fetch from external URLs.
- **Hunt 4 (curl -k):** Internal tools using self-signed certs for internal services may hit this. Build an allowlist of known-good internal hostnames and exclude. Developer machines may have higher volume.
- **Hunt 5 (executables in /tmp):** Some legitimate macOS apps write temporary executables to /tmp during updates. Correlate with subsequent `xattr -c` or `chmod +x` to confirm staging behavior.

## Outcome
- [ ] No evidence of ClickFix macOS Script Editor activity found
- [ ] Suspicious activity found — escalate for investigation
- [ ] Detection rule created based on hunt findings

## Related Notes
- [[Attack Techniques/ClickFix macOS via Script Editor]]
- [[Malware & TTPs/ClickFix macOS Script Editor and Atomic Stealer - Research Extraction]]
- [[40 - Resources/Query Library/Hunt Queries]]
- [[20 - Areas/Detection Engineering/Detections]]
