---
title: Overlord RAT via Fake Zoom Installer
date: 2026-08-13
type: ttp
mitre_id: T1204.002, T1027, T1140, T1036.005, T1547.014, T1059.004, T1082, T1071.001, T1056.001, T1113, T1123, T1005, T1041
mitre_tactic: Execution, Persistence, Defense Evasion, Discovery, Collection, Command and Control, Exfiltration
threat_actors: [Unattributed — LaunchAgent label/plist overlap with FlexibleFerret (DPRK-attributed, Contagious Interview cluster)]
tools_used: [.NET 10 single-file deployment, Go (garble-obfuscated), CGEventTap, miniaudio, ioreg, nohup, WebSocket]
platforms: [macOS, Windows]
tags:
  - type/ttp
  - status/active
  - platform/macos
  - platform/windows
  - category/rat
  - category/multi-platform
  - category/defense-evasion
source:
  url: https://www.jamf.com/blog/fake-zoom-installer-delivers-overlord-rat-macos/
  author: Ferdous Saljooki (Jamf Threat Labs)
  date: 2026-08-06
---

## Summary
A two-stage campaign delivers Overlord, an open-source remote access framework, via a fake Zoom installer. Stage 1 is a .NET 10 self-contained downloader (unusual for macOS malware) that fingerprints the host, fetches a platform-specific Overlord agent, and simultaneously downloads a genuine Zoom installer to sustain the social-engineering lure. Stage 2 is a `garble`-obfuscated Go binary offering full surveillance capability (keylogging, screen/audio/webcam capture, filesystem/process control, script execution) over a WebSocket C2 channel with certificate validation disabled by default.

## How It Works

### Step 1 — Lure Execution (T1204.002)
- Victim downloads and runs a fake Zoom installer (`ZoomMeetings` or `ZoomInstallerFull`) — the exact delivery mechanism (malvertising, fake download site, phishing link, etc.) was unconfirmed and under investigation at time of publication
- The binary is a .NET 10 self-contained single-file deployment bundling 34 DLLs in PE format — an unusual runtime choice for macOS malware that lets one codebase target both macOS and Windows

### Step 2 — Obfuscated Fingerprinting & Anti-Detection (T1027, T1140, T1082)
- Uses .NET's `RuntimeInformation` APIs to detect OS and architecture and select the correct payload
- Strings throughout the downloader are obfuscated with Base64 + XOR (key `0x94`); method/field names are replaced with meaningless identifiers (e.g. `__o_8ca0ad3ec7b40770`)
- Generates a random 6-character alphanumeric `ts=` token per execution and includes it on requests to the C2 server; the server returns HTTP 401 without a valid token, which both authenticates the request and defeats naive static-URL or replay-based detection
- Runs `ioreg -rd1 -c IOPlatformExpertDevice` to collect hardware UUID, serial number, and model identifier for host fingerprinting/tracking (T1082)

### Step 3 — Payload Retrieval & Lure Maintenance (T1036.005)
- Downloads the platform-specific Overlord agent from attacker infrastructure
- Concurrently fetches the **legitimate** Zoom installer (`.pkg` on macOS, `.exe` on Windows) so the victim still gets a working Zoom install — maintaining the disguise regardless of whether the malicious payload succeeds
- Prints a generic success message regardless of whether the malicious payload actually downloaded, reducing user suspicion on failure

### Step 4 — Backgrounded Execution (T1059.004)
- Stage 2 agent is written to `/tmp/ZoomMeetings`
- Launched via `nohup`, backgrounding the process so the downloader can exit cleanly without terminating its child — avoids a lingering parent process tied to the initial execution

### Step 5 — Optional Persistence (T1547.014)
- The Overlord agent embeds a LaunchAgent plist template, written to `~/Library/LaunchAgents/com.zoom.plist` with label `com.zoom` — deliberately mimicking the legitimate Zoom app to blend into `launchctl list` output
- Gated behind an `OVERLORD_ENABLE_PERSISTENCE` build/config toggle — persistence is opt-in per build, not automatic. One observed variant installs the LaunchAgent immediately on first run regardless
- Agent also self-copies to `~/Library/Application Support/Overlord/com.zoom`
- Notably, the `com.zoom` / `com.zoom.plist` label/filename pair matches the pattern used by FlexibleFerret, a DPRK-attributed macOS malware family from the Contagious Interview campaign — either coincidental convergence on a common evasion trick, or a deliberate imitation

### Step 6 — C2 Channel Establishment (T1071.001)
- Communicates over a secure WebSocket to a hardcoded default server `hub.zoom.com[.]kg:5173`
- `TLSInsecureSkipVerify` defaults to `true`, disabling certificate validation — likely accommodating a self-signed cert on attacker infrastructure and simultaneously weakening any MITM-based defensive interception attempt against the agent itself
- Optional (disabled by default) Solana blockchain-based C2 resolver reads server addresses from on-chain transactions, providing built-in domain-fluxing resilience if activated in future builds

### Step 7 — Surveillance & Collection (T1056.001, T1113, T1123, T1005)
- Keylogging via `CGEventTap`
- Screen capture with streaming frame delivery
- Microphone audio capture via the miniaudio library
- Webcam video capture
- Filesystem operations: browse, read, write, upload, download, move, rename, delete, chmod, zip
- Process control: list, kill, suspend, resume
- Arbitrary script execution via bash, python3, ruby, node, perl, or PowerShell (`pwsh`)
- Plugin system supports loading native dylibs or WebAssembly modules to extend capability at runtime

### Step 8 — Exfiltration & Remote Access (T1041)
- Captured data (keystrokes, screen/audio/webcam, filesystem contents) is transmitted back over the same WebSocket C2 channel
- Supports full remote desktop streaming over WebSocket or WebRTC peer-to-peer, giving the operator direct interactive access in addition to passive collection
- Self-update capability allows the agent to be refreshed in place without requiring a fresh delivery

## Detection Opportunities

### Key Log Sources
- **Endpoint telemetry (CrowdStrike/EDR):** Process execution of unsigned `.NET`/Go binaries named `ZoomMeetings`/`ZoomInstallerFull`/`zoomMacArm`; `nohup` spawning binaries from `/tmp`
- **File system monitoring:** LaunchAgent plist writes to `~/Library/LaunchAgents/com.zoom.plist`; writes to `~/Library/Application Support/Overlord/`
- **Network:** WebSocket connections to `hub.zoom.com[.]kg:5173`; HTTP requests carrying a `ts=` random-token parameter to non-Zoom infrastructure
- **macOS Unified Log / ESF:** LaunchAgent load events; `CGEventTap` creation calls from unsigned or newly-seen processes; audio-device access events

### Behavioral Indicators
- New LaunchAgent labeled `com.zoom` whose binary does not carry a genuine Zoom code signature
- A process named `ZoomMeetings` or similar running from `/tmp` rather than `/Applications/zoom.us.app`
- Mach-O binary containing embedded PE-format content (`.MZ` magic bytes) — an artifact unique to .NET's cross-platform single-file publishing that legitimate macOS software will not exhibit
- Outbound WebSocket traffic (not HTTPS REST) to a domain that superficially resembles Zoom's brand under an unusual TLD (`.kg`)
- Script interpreter children (bash/python3/ruby/node/perl/pwsh) spawned by a process named `zoomMacArm` or similar Overlord agent binary name

### Artifacts Left Behind
- `/tmp/ZoomMeetings` (Stage 2 write location)
- `~/Library/Application Support/Overlord/com.zoom`
- `~/Library/LaunchAgents/com.zoom.plist` (label: `com.zoom`)
- SHA256 hashes and PDB debug path (`.../TheEgg/obj/Release/net10.0/osx-arm64/...`) documented in [[Malware & TTPs/Overlord RAT via Fake Zoom Installer - Research Extraction]]

## Query Stubs

### CrowdStrike FQL

```
// Suspicious LaunchAgent labeled com.zoom not matching a genuine Zoom code signature
#repo=base_sensor #event_simpleName=/(LaunchAgentDefinitionFileWritten|FileCreateInfo)/
| TargetFileName=/LaunchAgents\/com\.zoom\.plist$/
| select(Timestamp, ComputerName, UserName, TargetFileName, ImageFileName)
| sort(-Timestamp)
```

```
// Binary named ZoomMeetings/ZoomInstallerFull/zoomMacArm executing from /tmp
#repo=base_sensor #event_simpleName=ProcessRollup2
| ImageFileName=/(ZoomMeetings|ZoomInstallerFull|zoomMacArm)/
| FileName=/^\/tmp\//
| select(Timestamp, ComputerName, UserName, ImageFileName, FileName, CommandLine)
| sort(-Timestamp)
```

```
// nohup backgrounding a suspicious Zoom-named binary
#repo=base_sensor #event_simpleName=ProcessRollup2
| ImageFileName=/nohup/
| CommandLine=/(ZoomMeetings|ZoomInstallerFull|zoomMacArm)/
| select(Timestamp, ComputerName, UserName, CommandLine, ParentBaseFileName)
| sort(-Timestamp)
```

```
// Outbound connections to the known Overlord C2 domain
#repo=base_sensor #event_simpleName=/(DnsRequest|NetworkConnectIP4)/
| DomainName=/hub\.zoom\.com\.kg/
| select(Timestamp, ComputerName, UserName, ImageFileName, DomainName, RemotePort)
| sort(-Timestamp)
```

```
// Hash match on known Overlord/downloader artifacts
#repo=base_sensor #event_simpleName=/(ProcessRollup2|NewExecutableWritten)/
| SHA256HashData=(7a2318127cabf28552a8aeed14a8445c8f36fbda5e57d8b122cf6f1c6b51a522, 2c0bb97632bb9b90ee97be2ac350a557b08d84a7dad1f3ef63ffd83be1ab1f00, d4cf150d6effeea315f136cdf448e32f4a8daac9e95f46def6a31ba18787dae3, 7878031f2bd907e7300133b3e8ce640f3cdcba56686eaca3539d4c22773bc233)
| select(Timestamp, ComputerName, UserName, TargetFileName, CommandLine)
```

### Databricks SQL

```sql
-- LaunchAgent plist written with label com.zoom
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
-- Zoom-named binary executing from /tmp
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
```

```sql
-- Outbound traffic to the known Overlord C2 domain
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  image_file_name,
  domain_name
FROM crowdstrike.dns_events
WHERE domain_name LIKE '%hub.zoom.com.kg%'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- Hash match on known Overlord/downloader artifacts
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

## Threat Actor Usage

| Actor | Notes |
|---|---|
| Unattributed | Jamf Threat Labs does not attribute this campaign to a specific actor. Notes the `com.zoom`/`com.zoom.plist` LaunchAgent label/filename overlaps with FlexibleFerret, a DPRK-attributed macOS malware family tied to the Contagious Interview campaign (SentinelOne, February 2025). Separately, the underlying Overlord framework itself has been linked by Proofpoint to UNK_DeadDrop, assessed "likely North Korean." Treat as contextual overlap, not confirmed attribution. |

## References
- [Fake Zoom Installer Delivers Overlord RAT for macOS — Jamf Threat Labs (Ferdous Saljooki, 2026-08-06)](https://www.jamf.com/blog/fake-zoom-installer-delivers-overlord-rat-macos/)

## Related Notes
- [[Malware & TTPs/Overlord RAT via Fake Zoom Installer - Research Extraction]]
- [[20 - Areas/Threat Hunting/Hunt - Overlord RAT via Fake Zoom Installer]]
- [[Attack Techniques/macOS Gaslight Backdoor]] — related DPRK-aligned macOS implant with similar LaunchAgent-masquerading persistence pattern
