---
title: Hunt - smd Persistence via Login Items and Background Task Management
date: 2026-07-11
type: hunt
status: active
hypothesis: An attacker or malicious app is establishing persistence on macOS endpoints by registering LaunchAgents/LaunchDaemons or login items through smd/ServiceManagement (SMLoginItemSetEnabled, SMAppService, SMJobBless) outside a normal installer flow, which would manifest as new entries in the Background Task Management (BTM) store, plist writes under LaunchAgents/LaunchDaemons initiated by scripting engines or unsigned binaries, and possible deletion of the on-disk plist shortly after registration to evade file-based detection.
priority: medium
platform: CrowdStrike, Databricks
mitre_id: T1543.001, T1543.004, T1547, T1059
tags:
  - type/hunt
  - status/active
  - platform/macos
  - platform/crowdstrike
  - platform/databricks
  - category/persistence
---

## Hypothesis

> *"I believe persistence mechanisms are being registered on macOS endpoints via smd/ServiceManagement APIs outside legitimate installer or MDM flows, because this technique persists in Apple's Background Task Management (BTM) database independent of the on-disk LaunchAgent/LaunchDaemon plist, which would manifest as BTM registration events with no corresponding user-facing 'login item added' notification, scripting engines or unsigned binaries invoking SMLoginItemSetEnabled/SMAppService.register/SMJobBless, and cases where the registering plist is deleted from disk shortly after registration."*

**Why this is worth hunting:**
- `smd`/BTM registrations are a durable artifact — the BTM store (`BackgroundItems-v4.btm`) can retain evidence of a login item/LaunchAgent even after the malware deletes its own plist, making this a good corroborating source when file-based persistence hunts come up empty
- Legitimate apps almost always register login items through their own signed GUI binary, not through `osascript`/shell/Python — a scripting engine calling into ServiceManagement APIs is a high-signal anomaly
- This complements existing LaunchAgent/LaunchDaemon file-write hunts (see [[Hunt - macOS Gaslight Backdoor]]) by covering the API-driven registration path, which doesn't always require a direct plist file write caught by file telemetry
- Relevant to the org's existing macOS malware research — both macOS.Gaslight and ClickFix/Atomic Stealer clusters rely on LaunchAgent-based persistence, and BTM/smd visibility strengthens detection coverage for that TTP class generally, not just those specific samples

## Assumptions & Scope

- **Environment:** macOS endpoints (Ventura+) enrolled in CrowdStrike Falcon with process, file, and log/predicate telemetry enabled
- **Timeframe:** Look back 30 days initially; extend to 90 days if tuning requires a larger baseline of legitimate login item registrations
- **Data sources:** CrowdStrike process events, file events; Databricks unified log tables; local `sfltool dumpbtm` / unified log (`log show --predicate 'process == "smd"'`) for endpoint-level triage
- **Assumptions:**
  - Legitimate login item registration is normally performed by a signed, notarized GUI application binary, not by `osascript`, `bash`/`zsh`, or Python
  - A LaunchAgent/LaunchDaemon plist deleted within minutes of its BTM registration event, with no corresponding software update/uninstall activity, is anomalous
  - MDM-managed configuration profiles that install LaunchDaemons are a known, allowlist-able source of noise and should be excluded via management authority signature or known bundle IDs
  - `smd` itself is never expected to spawn child processes — any child process of `smd` is inherently suspicious

## Hunt Plan

1. **Hunt for LaunchAgent/LaunchDaemon plist writes by scripting engines or unsigned binaries**
   Search for file writes to `~/Library/LaunchAgents/*.plist`, `/Library/LaunchAgents/*.plist`, or `/Library/LaunchDaemons/*.plist` where the writing process is `osascript`, `bash`, `zsh`, `python`, `perl`, or an unsigned/ad hoc signed binary — rather than an installer, softwareupdated, or a known MDM agent.

2. **Hunt for scripting-engine invocation of ServiceManagement APIs**
   Look for process/library-load telemetry showing `osascript`, shell, or Python processes loading `ServiceManagement.framework` or invoking `SMLoginItemSetEnabled`/`SMAppService`/`SMJobBless` — a strong signal of programmatic login item registration outside a normal app bundle.

3. **Hunt for BTM registration without a corresponding user notification**
   Correlate writes to `BackgroundItems-v4.btm` with the expected `UserNotificationCenter` "login item added" event; flag registrations with no matching notification (may indicate registration via an API path that suppresses the prompt, or notification center tampering).

4. **Hunt for plist deleted shortly after BTM registration (cleanup evasion)**
   Correlate a LaunchAgent/LaunchDaemon plist creation/BTM registration event with a `FileDelete` of the same plist path within a short window (e.g., 10 minutes), with no uninstall/software-update activity on the host in between.

5. **Hunt for child processes of smd**
   `smd` should not normally spawn children. Any `ParentBaseFileName == smd` process event is worth investigating directly.

## Queries

### CrowdStrike FQL

```
// Hunt 1: LaunchAgent/LaunchDaemon plist write by scripting engine or unsigned binary
#repo=base_sensor #event_simpleName=/(FileWriteInfo|FileCreateInfo)/
| TargetFileName=/Library\/(LaunchAgents|LaunchDaemons)\/.*\.plist$/
| ImageFileName=/(osascript|bash|zsh|python|perl)/
| select(Timestamp, ComputerName, UserName, ImageFileName, TargetFileName)
| sort(-Timestamp)
```

```
// Hunt 2: Scripting engine invoking ServiceManagement APIs
#repo=base_sensor #event_simpleName=/(ImageLoad|ProcessRollup2)/
| ImageFileName=/(osascript|bash|zsh|python)/
| ModuleName=/ServiceManagement/
| select(Timestamp, ComputerName, UserName, ImageFileName, ModuleName, CommandLine)
| sort(-Timestamp)
```

```
// Hunt 3: BTM store written (baseline for manual notification correlation)
#repo=base_sensor #event_simpleName=/(FileWriteInfo|FileCreateInfo)/
| TargetFileName=/BackgroundItems-v4\.btm$/
| select(Timestamp, ComputerName, UserName, ImageFileName, TargetFileName)
| sort(-Timestamp)
```

```
// Hunt 4: LaunchAgent/Daemon plist created then deleted within 10 minutes
#repo=base_sensor #event_simpleName=FileCreateInfo
| TargetFileName=/Library\/(LaunchAgents|LaunchDaemons)\/.*\.plist$/
| join(#event_simpleName=FileDeleteInfo TargetFileName=/Library\/(LaunchAgents|LaunchDaemons)\/.*\.plist$/, field=[ComputerName, TargetFileName], max=10m)
| select(Timestamp, ComputerName, UserName, TargetFileName)
```

```
// Hunt 5: Child process of smd
#repo=base_sensor #event_simpleName=ProcessRollup2
| ParentBaseFileName=smd
| select(Timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine)
| sort(-Timestamp)
```

### Databricks SQL

```sql
-- Hunt 1: LaunchAgent/LaunchDaemon plist write by scripting engine or unsigned binary
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  image_file_name,
  target_file_name
FROM crowdstrike.file_events
WHERE target_file_name RLIKE '.*Library/(LaunchAgents|LaunchDaemons)/.*\\.plist$'
  AND image_file_name RLIKE '.*(osascript|bash|zsh|python|perl).*'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- Hunt 3: BTM store written
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  image_file_name,
  target_file_name
FROM crowdstrike.file_events
WHERE target_file_name LIKE '%BackgroundItems-v4.btm'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- Hunt 4: LaunchAgent/Daemon plist created then deleted within 10 minutes
WITH created AS (
  SELECT device_id, computer_name, timestamp AS create_ts, target_file_name
  FROM crowdstrike.file_events
  WHERE event_simple_name = 'FileCreateInfo'
    AND target_file_name RLIKE '.*Library/(LaunchAgents|LaunchDaemons)/.*\\.plist$'
),
deleted AS (
  SELECT device_id, timestamp AS delete_ts, target_file_name
  FROM crowdstrike.file_events
  WHERE event_simple_name = 'FileDeleteInfo'
    AND target_file_name RLIKE '.*Library/(LaunchAgents|LaunchDaemons)/.*\\.plist$'
)
SELECT c.create_ts, c.computer_name, c.target_file_name, d.delete_ts
FROM created c
JOIN deleted d
  ON c.device_id = d.device_id
  AND c.target_file_name = d.target_file_name
  AND d.delete_ts BETWEEN c.create_ts AND c.create_ts + INTERVAL 10 MINUTES
ORDER BY c.create_ts DESC;
```

```sql
-- Hunt 5: Child process of smd
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  parent_base_file_name,
  image_file_name,
  command_line
FROM crowdstrike.process_events
WHERE parent_base_file_name = 'smd'
ORDER BY timestamp DESC
LIMIT 500;
```

## Findings

### Hits
_(No results yet — hunt not executed)_

### False Positives / Tuning Notes
- **Hunt 1 (plist write by scripting engine):** Some legitimate provisioning tools (Homebrew formulas, dotfile managers, dev environment scripts) write LaunchAgents via shell during setup — build an allowlist of known dev-tool paths/ComputerNames before escalating.
- **Hunt 2 (ServiceManagement API from scripting engine):** Confirm module load telemetry granularity is available in the environment; this hunt may need to fall back to command-line/heuristic matching (`osascript -e` containing `SMLoginItemSetEnabled` or `SMAppService`) if ImageLoad telemetry isn't reliable for framework loads.
- **Hunt 3 (BTM write):** High-volume by itself — this is a baseline query, not a standalone alert. Correlate manually against Hunt 1/2 hits or use as an enrichment source during investigation rather than a direct detection.
- **Hunt 4 (create-then-delete):** MDM/software update flows can legitimately replace or briefly touch plists during version upgrades — cross-reference against `softwareupdated`/MDM agent activity on the host in the same window before escalating.
- **Hunt 5 (child of smd):** Extremely high fidelity — there is no known legitimate reason for `smd` to spawn a child process. Any hit should be treated as high priority.

## Outcome
- [ ] No evidence of smd/BTM persistence abuse found
- [ ] Suspicious activity found — escalate for investigation
- [ ] Detection rule created based on hunt findings

## Related Notes
- [[DFIR & Forensics/Forensics/macOS]]
- [[Hunt - macOS Gaslight Backdoor]]
- [[Hunt - ClickFix macOS Script Editor and Atomic Stealer]]
- [[40 - Resources/Query Library/Hunt Queries]]
- [[20 - Areas/Detection Engineering/Detections]]
