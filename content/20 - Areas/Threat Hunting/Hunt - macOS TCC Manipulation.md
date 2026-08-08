---
title: Hunt - macOS TCC Manipulation
date: 2026-07-25
type: hunt
status: active
hypothesis: I believe TChCh-Changes-style AppleScript malware may be manipulating the macOS TCC database to self-grant permissions, because this technique remains viable on unpatched hosts and on developer endpoints with existing Full Disk Access, which would manifest as synthetic TCC.db entries with no corresponding EDR grant event, tccd terminations, and Script Editor spawning compilation/signing tooling.
priority: high
platform: [CrowdStrike, Databricks]
mitre_id: T1566.001, T1059.002, T1564.004, T1027, T1547, T1217, T1071.001, T1547.015
tags:
  - type/hunt
  - status/active
  - platform/macos
  - category/privilege-escalation
---

## Hypothesis
"I believe TChCh-Changes-style AppleScript malware is manipulating the macOS TCC database to escalate privileges without user consent, because the technique remains effective on unpatched macOS builds and on any host where an attacker-controlled process already holds Full Disk Access, which would manifest as synthetic `TCC.db` entries lacking a corresponding consent-prompt event, forced `tccd` restarts, and Script Editor processes spawning `osacompile`/`codesign`/`curl`."

Why this is worth hunting:
- Cryptocurrency organizations are the explicit target sector, and TCC bypass grants silent access to sensitive data (keychain, files, screen recording) without alerting the user
- The technique overlaps tactically with DPRK-aligned actors (Sapphire Sleet/BlueNoroff/UNC1069), so a hit here has high-confidence nation-state escalation value
- Patch coverage is inconsistent — many fleets lag Tahoe 26.4.1 / Sequoia 15.7.7, and developer endpoints with standing Full Disk Access remain exposed regardless of patch level
- Native, living-off-the-land tooling (Script Editor, osacompile, codesign, sqlite) means this activity is unlikely to trip traditional malware signature detection

## Assumptions & Scope
- Environment: macOS fleet (Tahoe, Sequoia, and earlier) with CrowdStrike Falcon sensor coverage and Endpoint Security Framework telemetry
- Timeframe: last 90 days, prioritizing hosts not yet updated to Tahoe 26.4.1+/Sequoia 15.7.7+
- Data sources available: CrowdStrike process/file/network events via Databricks; ESF `tcc_modify` events if ingested; DNS/network logs; local/live-response access to `xprotectd`'s unified log on flagged hosts (not centrally ingested — see Step 8)

## Hunt Plan
1. Pull all macOS hosts and their current OS build/version; flag those below Tahoe 26.4.1 or Sequoia 15.7.7 as higher-priority scope (patch reintroduces user-consent requirement for the Finder AppleEvents path).
2. Query process telemetry for `tccd` termination via `kill -9` issued by a non-root, non-system user context — this is abnormal outside of macOS internals/updates.
3. Query for Script Editor (`ImageFileName`/`ParentBaseFileName` = Script Editor) spawning `curl`, `osacompile`, or `codesign` as children within a short time window of each other (same session, <5 min apart).
4. Query file-write events targeting `TCC.db` (system and user paths) from any process other than `tccd`/`syspolicyd`; cross-reference each hit against ESF `tcc_modify` consent-grant events for the same timestamp/user — a write with no matching consent event is a strong positive.
5. Query LaunchAgent creation under `~/Library/LaunchAgents/` occurring within 30 minutes of any Script Editor/osacompile activity on the same host.
6. Query DNS/network logs for the known C2 domains (`cigalsn.com`, `ecoferros.com`) and the `.php?req=contact`/`.php?req=tell` URI patterns, independent of the above — this catches beaconing even if the TCC-write step was missed.
7. For any host with 2+ hits across steps 2–6, pivot to full process-tree reconstruction and file-hash comparison against the known IOC list in [[Malware & TTPs/macOS TCC Manipulation - Research Extraction]].
8. On any host flagged in step 7 (macOS 26.4+/Sequoia 15.4+ only — this control doesn't exist on earlier builds), pull `xprotectd`'s local unified log for the incident window. Confirmed via testing: `xprotectd` logs every paste operation system-wide under `com.apple.security.xprotectd:main`, including a Safe Browsing URL-reputation lookup pass and a plaintext `"Source process is not a browser"` decision branch. This is a live-response/triage step, not a fleet-wide query — it isn't centrally ingested by CrowdStrike/Databricks today, so it only helps on hosts you can already reach directly.

## Queries

### CrowdStrike FQL

```
// Step 2: tccd killed via command line, non-system context
#repo=base_sensor #event_simpleName=/ProcessRollup2/
| CommandLine=/tccd/i
| CommandLine=/kill\s+-9/i
| select(Timestamp, ComputerName, UserName, CommandLine, ParentBaseFileName)
| sort(-Timestamp)
```

```
// Step 3: Script Editor spawning compile/sign/download tooling
#repo=base_sensor #event_simpleName=/ProcessRollup2/
| ParentBaseFileName=/Script Editor/i
| FileName=/(osacompile|codesign|curl)/i
| select(Timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName)
| sort(-Timestamp)
```

```
// Step 4: TCC.db writes outside expected system processes
#repo=base_sensor #event_simpleName=/(FileWriteInfo|FileOpenInfo)/
| TargetFileName=/com\.apple\.TCC\/TCC\.db$/
| !ImageFileName=/(tccd|syspolicyd)/i
| select(Timestamp, ComputerName, UserName, ImageFileName, TargetFileName)
| sort(-Timestamp)
// TODO: tune exclusions for approved MDM/config-management tooling that legitimately writes TCC profiles
```

```
// Step 5: LaunchAgent creation following Script Editor activity
#repo=base_sensor #event_simpleName=/(LaunchAgentDefinitionFileWritten|FileCreateInfo)/
| TargetFileName=/LaunchAgents\/.*\.plist$/
| select(Timestamp, ComputerName, UserName, TargetFileName)
| sort(-Timestamp)
// TODO: tune exclusions for known-legitimate LaunchAgents (MDM, EDR, first-party apps)
```

```
// Step 6: beaconing to known TChCh-Changes C2
#repo=base_sensor #event_simpleName=/(DnsRequest|NetworkConnectIP4|HttpRequestHeader)/
| (DomainName=/(cigalsn\.com|ecoferros\.com)/ OR RequestURI=/\.php\?req=(contact|tell)/)
| select(Timestamp, ComputerName, UserName, ImageFileName, DomainName, RequestURI)
| sort(-Timestamp)
```

### macOS Unified Log (local/live-response — not centrally ingested)

```bash
# Step 8: xprotectd paste-processing telemetry on a specific flagged host, live
log stream --process xprotectd --level debug --info

# Or retrospectively, if the host is reachable within the log retention window
log show --predicate 'process == "xprotectd" AND subsystem == "com.apple.security.xprotectd"' --style syslog --info --debug --last 24h
```
// TODO: pasted content and source bundle IDs are `<private>` by default — enabling private-data logging unmasks them but also exposes the responder's own paste activity for the capture window; scope deliberately
// TODO: evaluate forwarding this subsystem into centralized log ingestion so this becomes a fleet-wide query instead of a manual triage step

### Databricks SQL

```sql
-- Step 2: tccd killed via command line
SELECT timestamp, device_id, computer_name, user_name, command_line, parent_base_file_name
FROM crowdstrike.process_events
WHERE command_line RLIKE '(?i).*tccd.*'
  AND command_line RLIKE '(?i).*kill\\s+-9.*'
ORDER BY timestamp DESC
LIMIT 500;
-- TODO: tune exclusions for OS update/patch processes that legitimately restart tccd
```

```sql
-- Step 3: Script Editor spawning osacompile/codesign/curl
SELECT timestamp, device_id, computer_name, user_name, file_name, command_line, parent_base_file_name
FROM crowdstrike.process_events
WHERE parent_base_file_name RLIKE '(?i).*Script Editor.*'
  AND file_name RLIKE '(?i).*(osacompile|codesign|curl).*'
ORDER BY timestamp DESC
LIMIT 500;
-- TODO: tune exclusions for internal dev/QA teams that legitimately compile AppleScript
```

```sql
-- Step 4: TCC.db writes outside tccd/syspolicyd
SELECT timestamp, device_id, computer_name, user_name, image_file_name, target_file_name
FROM crowdstrike.file_events
WHERE target_file_name RLIKE '.*com\\.apple\\.TCC/TCC\\.db$'
  AND image_file_name NOT RLIKE '(?i).*(tccd|syspolicyd).*'
ORDER BY timestamp DESC
LIMIT 500;
-- TODO: tune exclusions for MDM profile-push tooling (Jamf, Kandji, etc.)
```

```sql
-- Step 6: beaconing to known C2 infrastructure
SELECT timestamp, device_id, computer_name, user_name, image_file_name, domain_name, request_uri
FROM crowdstrike.network_events
WHERE domain_name RLIKE '.*(cigalsn\\.com|ecoferros\\.com).*'
   OR request_uri RLIKE '.*\\.php\\?req=(contact|tell).*'
ORDER BY timestamp DESC
LIMIT 500;
```

## Findings

### Hits
-

### False Positives / Tuning Notes
- MDM/config-management tools (Jamf, Kandji, Mosyle) legitimately write TCC configuration profiles — exclude known MDM agent binaries from Step 4 query
- Internal developer/QA workflows that compile and sign AppleScript apps as part of build tooling — exclude known CI/build-agent hosts from Step 3 query
- macOS update/patch installers may restart `tccd` as part of normal servicing — exclude Apple Software Update / `softwareupdated` contexts from Step 2 query
- IT/helpdesk remote-support tooling with standing Full Disk Access may trigger benign TCC-related file activity — maintain an allowlist of approved RMM/support tools
- `xprotectd` paste-processing log entries (Step 8) fire on *every* paste, benign or not — this is a correlation aid for hosts already flagged by steps 2–7, not a standalone detection signal on its own

## Outcome
- [ ] No evidence found — hypothesis closed
- [ ] Suspicious activity found — escalated to investigation
- [ ] Detection rule created → [[link to rule]]

## Related Notes
- [[Attack Techniques/macOS TCC Manipulation via AppleScript]]
- [[Malware & TTPs/macOS TCC Manipulation - Research Extraction]]
- [[40 - Resources/Query Library/Hunt Queries]]
