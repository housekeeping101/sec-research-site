---
title: Hunt - Overlord RAT via Fake Zoom Installer
date: 2026-08-13
type: hunt
status: active
hypothesis: A fake-Zoom-installer campaign is delivering the Overlord remote access framework to macOS (and Windows) endpoints via a .NET 10 downloader, which would manifest as a Zoom-branded binary running from /tmp, a com.zoom-labeled LaunchAgent not matching Zoom's genuine code signature, Mach-O binaries with embedded PE content, and outbound WebSocket traffic to hub.zoom.com[.]kg.
priority: high
platform: CrowdStrike, Databricks
mitre_id: T1204.002, T1027, T1140, T1036.005, T1547.014, T1059.004, T1082, T1071.001, T1056.001, T1113, T1123, T1005, T1041
tags:
  - type/hunt
  - status/active
  - platform/macos
  - platform/windows
  - platform/crowdstrike
  - platform/databricks
  - category/rat
  - category/multi-platform
---

## Hypothesis

> *"I believe the Overlord RAT campaign (delivered via a fake Zoom installer) is present in the environment because the sample was undetected by static AV engines at time of public disclosure and relies on brand-mimicking persistence and generic WebSocket C2 that blends with normal traffic, which would manifest as a Zoom-named binary executing from /tmp, a com.zoom-labeled LaunchAgent whose binary isn't genuinely signed by Zoom, a Mach-O executable with embedded PE-format content, and outbound WebSocket connections to hub.zoom.com[.]kg:5173."*

**Why this is worth hunting:**
- The sample was reported as undetected by static engines on VirusTotal at time of Jamf's writeup — behavioral/artifact-based hunting is necessary, not just hash blocking
- The campaign concurrently delivers a genuine Zoom installer alongside the payload, meaning a victim's "it worked, Zoom installed fine" experience gives no indication of compromise — this defeats user-reporting as a detection source entirely
- The `com.zoom` LaunchAgent label overlaps with FlexibleFerret, a DPRK-attributed family tied to Contagious Interview — if this pattern is confirmed present, it's worth escalating regardless of final attribution
- Cross-platform (.NET 10 single-file) delivery means Windows endpoints in the same environment should be hunted in parallel, not just macOS
- WebSocket C2 with `TLSInsecureSkipVerify=true` is a distinctive network fingerprint (self-signed cert on a non-standard port, 5173) that is unlikely to appear in legitimate enterprise WebSocket traffic

## Assumptions & Scope

- **Environment:** macOS and Windows endpoints enrolled in CrowdStrike Falcon with process, file, and DNS/network telemetry enabled
- **Timeframe:** Look back 60 days initially given the sample was reported as recently as 2026-08-06 and delivery vector is still under investigation; extend to 90 days if no hits and the environment has broad exposure to third-party download sources
- **Data sources:** CrowdStrike process events, file events, DNS/network events; Databricks unified log tables
- **Assumptions:**
  - Legitimate Zoom installations run from `/Applications/zoom.us.app` and are signed by Zoom Video Communications, Inc. — a LaunchAgent labeled `com.zoom` whose binary isn't signed by Zoom is anomalous
  - No legitimate enterprise software embeds a PE-format executable inside a Mach-O binary — this is unique to .NET's cross-platform single-file publishing and is a very low-noise, high-signal indicator
  - Outbound WebSocket traffic to port 5173 is not part of any approved application in this environment (tune if a legitimate app uses that port)
  - `ioreg -rd1 -c IOPlatformExpertDevice` is a normal diagnostic command but unusual when invoked programmatically by a newly-seen, unsigned process rather than a human running Terminal

## Hunt Plan

1. **Hunt for the com.zoom LaunchAgent**
   Search for LaunchAgent plist writes to `~/Library/LaunchAgents/com.zoom.plist`. Cross-reference the code signature of the writing/owning process — anything not signed by Zoom Video Communications, Inc. is high priority.

2. **Hunt for Zoom-named binaries executing from /tmp**
   Search for process execution where the image name matches `ZoomMeetings`, `ZoomInstallerFull`, or `zoomMacArm` and the executing path is `/tmp/` rather than `/Applications/`.

3. **Hunt for nohup-backgrounded Zoom-named execution**
   Search for `nohup` spawning a child process whose command line references `ZoomMeetings`, `ZoomInstallerFull`, or `zoomMacArm`.

4. **Hunt for embedded PE content in Mach-O binaries**
   Where file-content scanning is available, search for Mach-O executables (`cffaedfe`/`feedface` magic) containing embedded `MZ` (PE) header bytes — a strong, low-false-positive indicator specific to .NET single-file macOS builds.

5. **Hunt for outbound traffic to the known C2 domain/port**
   Search DNS and network connection logs for `hub.zoom.com.kg` or any connection to port 5173 with a self-signed/untrusted certificate.

6. **Hunt for the com.zoom Application Support directory**
   Search for file writes to `~/Library/Application Support/Overlord/` or a subpath named `com.zoom` — the Overlord agent's self-copy destination.

7. **Hash hunt for known Overlord/downloader artifacts**
   Search all file write and execution events for the known SHA256 hashes documented in [[Malware & TTPs/Overlord RAT via Fake Zoom Installer - Research Extraction]].

8. **Windows parity check**
   Given the shared .NET 10 codebase, repeat hunts 2, 3, 5, and 7 against Windows endpoints, substituting the `.exe` lure naming pattern and Windows persistence locations (Run keys/scheduled tasks — not confirmed in source, verify if Windows agent samples are recovered).

## Queries

### CrowdStrike FQL

```
// Hunt 1: com.zoom LaunchAgent plist write
#repo=base_sensor #event_simpleName=/(LaunchAgentDefinitionFileWritten|FileCreateInfo)/
| TargetFileName=/LaunchAgents\/com\.zoom\.plist$/
| select(Timestamp, ComputerName, UserName, TargetFileName, ImageFileName)
| sort(-Timestamp)
```

```
// Hunt 2: Zoom-named binary executing from /tmp
#repo=base_sensor #event_simpleName=ProcessRollup2
| ImageFileName=/(ZoomMeetings|ZoomInstallerFull|zoomMacArm)/
| FileName=/^\/tmp\//
| select(Timestamp, ComputerName, UserName, ImageFileName, FileName, CommandLine)
| sort(-Timestamp)
```

```
// Hunt 3: nohup backgrounding a Zoom-named binary
#repo=base_sensor #event_simpleName=ProcessRollup2
| ImageFileName=/nohup/
| CommandLine=/(ZoomMeetings|ZoomInstallerFull|zoomMacArm)/
| select(Timestamp, ComputerName, UserName, CommandLine, ParentBaseFileName)
| sort(-Timestamp)
```

```
// Hunt 5: Outbound traffic to known C2 domain or port 5173
#repo=base_sensor #event_simpleName=/(DnsRequest|NetworkConnectIP4)/
| DomainName=/hub\.zoom\.com\.kg/ OR RemotePort=5173
| select(Timestamp, ComputerName, UserName, ImageFileName, DomainName, RemotePort)
| sort(-Timestamp)
```

```
// Hunt 6: Overlord Application Support directory write
#repo=base_sensor #event_simpleName=/(FileCreateInfo|FileWriteInfo)/
| TargetFileName=/Application Support\/Overlord\//
| select(Timestamp, ComputerName, UserName, TargetFileName, ImageFileName)
| sort(-Timestamp)
```

```
// Hunt 7: Hash match — known Overlord/downloader artifacts
#repo=base_sensor #event_simpleName=/(ProcessRollup2|NewExecutableWritten)/
| SHA256HashData=(7a2318127cabf28552a8aeed14a8445c8f36fbda5e57d8b122cf6f1c6b51a522, 2c0bb97632bb9b90ee97be2ac350a557b08d84a7dad1f3ef63ffd83be1ab1f00, d4cf150d6effeea315f136cdf448e32f4a8daac9e95f46def6a31ba18787dae3, 7878031f2bd907e7300133b3e8ce640f3cdcba56686eaca3539d4c22773bc233)
| select(Timestamp, ComputerName, UserName, TargetFileName, CommandLine)
```

```
// Hunt 8: Windows parity — Zoom-named .exe lure execution
#repo=base_sensor #event_simpleName=ProcessRollup2
| event_platform=Win
| ImageFileName=/(ZoomMeetings|ZoomInstallerFull)\.exe/
| select(Timestamp, ComputerName, UserName, ImageFileName, FileName, CommandLine)
| sort(-Timestamp)
```

### Databricks SQL

```sql
-- Hunt 1: com.zoom LaunchAgent plist write
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  target_file_name,
  image_file_name
FROM crowdstrike.file_events
WHERE target_file_name LIKE '%LaunchAgents/com.zoom.plist'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- Hunt 2: Zoom-named binary executing from /tmp
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  image_file_name,
  file_name,
  command_line
FROM crowdstrike.process_events
WHERE image_file_name RLIKE '.*(ZoomMeetings|ZoomInstallerFull|zoomMacArm).*'
  AND file_name LIKE '/tmp/%'
ORDER BY timestamp DESC
LIMIT 500;
-- TODO: tune exclusions — legitimate QA/build endpoints that stage test binaries in /tmp
```

```sql
-- Hunt 3: nohup backgrounding a Zoom-named binary
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  command_line,
  parent_base_file_name
FROM crowdstrike.process_events
WHERE parent_base_file_name = 'nohup'
  AND command_line RLIKE '.*(ZoomMeetings|ZoomInstallerFull|zoomMacArm).*'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- Hunt 5: Outbound traffic to known C2 domain or port 5173
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  image_file_name,
  domain_name,
  remote_port
FROM crowdstrike.dns_events
WHERE domain_name LIKE '%hub.zoom.com.kg%'
   OR remote_port = 5173
ORDER BY timestamp DESC
LIMIT 500;
-- TODO: tune exclusions — any internal services legitimately using port 5173 (e.g. some Vite dev servers default to 5173; expect noise on developer endpoints)
```

```sql
-- Hunt 6: Overlord Application Support directory write
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  target_file_name,
  image_file_name
FROM crowdstrike.file_events
WHERE target_file_name LIKE '%Application Support/Overlord/%'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- Hunt 7: Hash match — known Overlord/downloader artifacts
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  target_file_name,
  sha256_hash
FROM crowdstrike.file_events
WHERE sha256_hash IN (
  '7a2318127cabf28552a8aeed14a8445c8f36fbda5e57d8b122cf6f1c6b51a522',
  '2c0bb97632bb9b90ee97be2ac350a557b08d84a7dad1f3ef63ffd83be1ab1f00',
  'd4cf150d6effeea315f136cdf448e32f4a8daac9e95f46def6a31ba18787dae3',
  '7878031f2bd907e7300133b3e8ce640f3cdcba56686eaca3539d4c22773bc233'
)
ORDER BY timestamp DESC;
```

```sql
-- Hunt 8: Windows parity — Zoom-named .exe lure execution
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  image_file_name,
  file_name,
  command_line
FROM crowdstrike.process_events
WHERE event_platform = 'Win'
  AND image_file_name RLIKE '.*(ZoomMeetings|ZoomInstallerFull)\\.exe'
ORDER BY timestamp DESC
LIMIT 500;
```

## Findings

### Hits
_(No results yet — hunt not executed)_

### False Positives / Tuning Notes
- **Hunt 1 (com.zoom LaunchAgent):** Verify the code signature of the plist-writing process and the referenced executable — Zoom's own installer/updater may legitimately touch LaunchAgent paths under different labels (`us.zoom.*`); confirm `com.zoom` specifically is not a label Zoom itself ever uses before escalating on label alone.
- **Hunt 2/3 (Zoom-named binary in /tmp, nohup):** Developer/QA endpoints that build or test Zoom SDK integrations could stage similarly-named binaries in `/tmp` — check for a known dev/build asset tag before escalating.
- **Hunt 5 (port 5173 / C2 domain):** Port 5173 is the default port for the Vite JavaScript dev server — expect false positives on developer laptops; the domain-based match (`hub.zoom.com.kg`) is far higher confidence and should be prioritized for auto-escalation, while the bare port-5173 match should route to manual triage.
- **Hunt 6 (Overlord Application Support dir):** No known legitimate software uses this path; low false-positive rate expected, but confirm no internal tooling happens to reuse "Overlord" as a product name before treating as a hard IOC.
- **Hunt 7 (hash match):** Hashes are sample-specific and will rotate in future campaign waves — treat a hash miss as inconclusive, not as evidence of absence; rely primarily on Hunts 1, 2, 4, and 5 for durable detection.
- **Hunt 8 (Windows parity):** Windows persistence mechanism and file paths were not detailed in the source article — this query is provisional and should be revisited once a Windows sample is recovered and analyzed.

## Outcome
- [ ] No evidence of Overlord RAT / fake Zoom installer activity found
- [ ] Suspicious activity found — escalate for investigation
- [ ] Detection rule created based on hunt findings

## Related Notes
- [[Attack Techniques/Overlord RAT via Fake Zoom Installer]]
- [[Malware & TTPs/Overlord RAT via Fake Zoom Installer - Research Extraction]]
- [[40 - Resources/Query Library/Hunt Queries]]
- [[20 - Areas/Detection Engineering/Detections]]


