---
title: ClickFix macOS via Script Editor
date: 2026-04-10
type: ttp
mitre_id: T1204.001, T1059.004, T1140, T1105, T1218.005
mitre_tactic: Execution, Defense Evasion, Command and Control
threat_actors: []
tools_used: [Script Editor, AppleScript, curl, zsh, base64, gunzip, xattr, chmod, tr]
platforms: [macOS]
tags:
  - type/ttp
  - status/active
  - platform/macos
  - category/infostealer
  - category/defense-evasion
source:
  url: https://www.jamf.com/blog/clickfix-macos-script-editor-atomic-stealer/
  author: Thijs Xhaflaire (Jamf Threat Labs)
  date: 2026-04-08
---

## Summary
ClickFix macOS via Script Editor is a macOS-specific adaptation of the ClickFix social engineering technique. Attackers abuse the `applescript://` URL scheme to open Script Editor pre-loaded with malicious AppleScript code, bypassing macOS 15.4's Terminal paste-command scanning control. This technique has been observed delivering Atomic Stealer (AMOS), a commodity macOS infostealer. The technique is notable because it demonstrates attacker adaptation to platform-specific defenses by pivoting execution context from Terminal to Script Editor.

## How It Works

### Step 1 — Lure Delivery (T1204.001)
- Victim is directed to a fake Apple maintenance or system-fix webpage (observed: `storage-fixes.squarespace.com`)
- Page presents a convincing UI prompt instructing the user to click "Fix" or similar CTA
- Clicking triggers an `applescript://` URL, which is handled natively by macOS

### Step 2 — Script Editor Invocation (T1218.005)
- The `applescript://` URL scheme causes macOS to open Script Editor with pre-populated malicious AppleScript code
- No Terminal interaction required — bypasses macOS 15.4's Terminal paste-command scanning entirely
- User is prompted or guided to run the pre-filled script (one click in Script Editor)
- Script Editor is a signed Apple binary, providing implicit trust

### Step 3 — Stage 1 Payload — Obfuscated Curl (T1140)
- AppleScript executes a shell command containing a `tr`-obfuscated curl command
- The `tr` cipher reconstructs the payload URL at runtime, evading static string matching
- `curl -k` fetches the stage 2 payload from attacker infrastructure (TLS validation disabled)

### Step 4 — Stage 2 Payload — In-Memory Decode and Execute (T1059.004, T1140)
- Retrieved blob is base64-encoded and gzip-compressed
- Decoded entirely in-memory via pipe: `base64 -d | gunzip | zsh`
- Payload never written to disk as a standalone file — minimizes forensic footprint

### Step 5 — Binary Staging and Execution (T1105)
- Decoded script downloads Atomic Stealer Mach-O binary to `/tmp/helper`
- `xattr -c /tmp/helper` strips the macOS quarantine extended attribute — bypasses Gatekeeper
- `chmod +x /tmp/helper` sets execute permission
- Binary is executed, beginning credential and data harvesting

## Detection Opportunities

### Key Log Sources
- **Endpoint telemetry (CrowdStrike/EDR):** Process execution chains — `Script Editor` → shell → `curl` / `zsh` / `base64`
- **File system monitoring:** New Mach-O binaries written to `/tmp`; `xattr` executed on `/tmp` paths
- **Network:** DNS/HTTP requests to `dryvecar.com`, `cleanupmac.mssg.me`; curl with `-k` flag to unknown hosts
- **macOS Unified Log / ESF:** `applescript://` URL scheme invocations from browser processes
- **macOS Unified Log (`xprotectd`):** `com.apple.security.xprotectd:main` subsystem/category logs every paste operation system-wide (not ESF-gated, no entitlement required to read) — see Vendor Response section below

### Behavioral Indicators
- Script Editor (`/Applications/Script Editor.app`) spawning child shell processes (`zsh`, `bash`, `curl`)
- `xattr -c` executed on a file in `/tmp`
- `curl` with `-k` flag combined with `base64 -d | gunzip | zsh` pipe pattern
- New executable written to `/tmp` followed immediately by `chmod +x` and execution
- `osascript` or Script Editor invoked from a browser process via URL scheme

### Artifacts Left Behind
- `/tmp/helper` — Atomic Stealer Mach-O binary (SHA256: `3d3c91ee762668c85b74859e4d09a2adfd34841694493b82659fda77fe0c2c44`)
- Browser history referencing `storage-fixes.squarespace.com` or similar fake Apple lure pages
- macOS Unified Log entries for Script Editor launch and `applescript://` URL handling

## Query Stubs

### CrowdStrike FQL

```
// Script Editor spawning shell or download tools — high-signal ClickFix macOS indicator
#repo=base_sensor #event_simpleName=ProcessRollup2
| ParentImageFileName=/Script Editor/
| ImageFileName=/(zsh|bash|sh|curl|osascript)$/
| select(Timestamp, ComputerName, UserName, ParentImageFileName, ImageFileName, CommandLine)
| sort(-Timestamp)
```

```
// xattr -c on /tmp — quarantine removal before execution
#repo=base_sensor #event_simpleName=ProcessRollup2
| ImageFileName=/xattr$/
| CommandLine=/-c.*\/tmp\//
| select(Timestamp, ComputerName, UserName, ImageFileName, CommandLine)
| sort(-Timestamp)
```

```
// Mach-O binary written to /tmp followed by chmod+execute
#repo=base_sensor #event_simpleName=/(NewExecutableWritten|FileCreateInfo)/
| TargetFileName=/\/tmp\//
| join(#event_simpleName=ProcessRollup2 ImageFileName=/chmod$/ CommandLine=/\+x.*\/tmp\//, field=ComputerName)
| select(Timestamp, ComputerName, UserName, TargetFileName, CommandLine)
```

```
// curl with -k flag to unknown external host (TLS bypass for payload delivery)
#repo=base_sensor #event_simpleName=ProcessRollup2
| ImageFileName=/curl$/
| CommandLine=/-k /
| !CommandLine=/(apple\.com|jamf\.com|microsoft\.com)/
| select(Timestamp, ComputerName, UserName, CommandLine)
| sort(-Timestamp)
```

### Databricks SQL

```sql
-- Script Editor spawning shell processes (ClickFix macOS execution chain)
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
-- xattr -c on /tmp path (quarantine stripping before binary execution)
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  command_line
FROM crowdstrike.process_events
WHERE image_file_name LIKE '%xattr'
  AND command_line LIKE '%-c%/tmp/%'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- In-memory decode/execute pattern: base64 -d piped to zsh
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

## Threat Actor Usage

| Actor | Notes |
|---|---|
| Unattributed | Observed in April 2026 campaign delivering Atomic Stealer (AMOS); no specific threat actor attribution in Jamf report |
| Generic ClickFix operators | ClickFix social engineering previously attributed to various financially motivated actors; macOS Script Editor variant is a newer evasion evolution |

See also: [[30 - Knowledge/Cybersecurity/Attack Techniques/ClickFix]] for Windows/Linux ClickFix variants and nation-state usage (APT36).

## Vendor Response

macOS 26.4 "Tahoe" (and the parallel Sequoia 15.4 point release, both shipped March 24, 2026) introduced a Terminal paste-scanning control: a "Possible malware, Paste blocked" dialog with "Paste Anyway"/"Cancel" options, shown on the first cross-application paste of a suspicious command into Terminal. It works by calling a private `NSPasteboard` API, `_sourceSigningIdentifier`, to read the code-signing identity of the app that placed the content on the clipboard — flagging pastes sourced from a predefined list of ~74 apps (browsers, chat clients, mail apps).

**Critically, the dialog is suppressed if Terminal was opened within the last 30 days, or if developer tools are installed** — meaning regular Terminal users and any dev-tooled Mac are automatically exempt.

This control is Terminal-specific and does not cover Script Editor at all, which directly explains this technique's `applescript://` pivot documented above: rather than finding a bypass for the Terminal paste-block, ClickFix operators sidestepped it entirely by moving execution to a different signed, trusted Apple application the control doesn't inspect.

**Endpoint Security telemetry (why third-party EDR can't see this):** `xprotectd` (`/usr/libexec/xprotectd`) implements the paste-block by subscribing to two undocumented Endpoint Security events — `ES_EVENT_TYPE_RESERVED_0` (148) and `ES_EVENT_TYPE_RESERVED_1` (149, the paste `AUTH` event, backed by an `es_event_paste_t` structure containing source/target audit tokens, the source bundle identifier, the target's responsible process, and the actual pasted content). This event was first documented by Koh M. Nakagawa at Objective by the Sea v8, and independently corroborated/expanded by Patrick Wardle (Objective-See, 2026-03-31). These events require the `com.apple.private.endpoint-security.client` entitlement, which Apple restricts to its own system binaries — third-party ES clients, including EDR sensors and tools like BlockBlock, are refused subscription outright. **This means CrowdStrike/other third-party EDR gets zero programmatic ESF subscription access to the paste event itself** (confirmed — the entitlement check hard-blocks it). However, **`xprotectd` does emit unified log (`os_log`) telemetry on every paste, system-wide** — confirmed via local testing filtering `log stream` on the `xprotectd` process itself (not the receiving app). This is a genuinely separate telemetry channel from the ES event: reading the unified log requires no special entitlement, so EDR agents that ingest `os_log` (many do) can see this even though they can't subscribe to `ES_EVENT_TYPE_RESERVED_1` directly.

Observed behavior:
- Every paste triggers a log line under subsystem/category `com.apple.security.xprotectd:main` (payload marked `<private>` by default)
- This is frequently followed by a `SafariSafeBrowsing` subsystem sequence — `xprotectd` performs a **Safe Browsing URL reputation lookup** against pasted content as part of its evaluation, a second inspection layer beyond the source-app code-signing check documented elsewhere
- A plaintext (non-redacted) decision branch was observed: `"Source process is not a browser"` — logged when `xprotectd` short-circuits the SafeBrowsing lookup because the paste's source app doesn't match its browser criteria
- Interception happens system-wide, not just for pastes into Terminal — the UI block dialog is Terminal-specific, but the inspection pipeline itself runs on every paste operation on the Mac

```bash
# Confirmed working: surfaces xprotectd's paste-evaluation decisions in real time
log stream --process xprotectd --level debug --info
```

Full pasted content and source bundle identifiers are redacted (`<private>`) by default; unmasking requires enabling private-data logging (see the profile-based method linked from [FFRI's XPRTestSuite](https://github.com/FFRI/XPRTestSuite), citing [Jamf's Unified Logs private-data guide](https://www.jamf.com/blog/unified-logs-how-to-enable-private-data/)) — note this also unmasks the operator's *own* pasted content system-wide for the duration it's enabled, so treat it as a deliberate, scoped capture rather than something left on.

## References
- [ClickFix macOS: Script Editor & Atomic Stealer — Jamf Threat Labs (Thijs Xhaflaire, 2026-04-08)](https://www.jamf.com/blog/clickfix-macos-script-editor-atomic-stealer/)
- [macOS 26.4 has new Terminal popup warning when pasting commands — 9to5Mac (2026-03-25)](https://9to5mac.com/2026/03/25/macos-26-4-has-new-terminal-popup-warning-when-pasting-commands/)
- [If your Mac blocks a Terminal command paste or script — Apple Support](https://support.apple.com/en-us/127377)
- [No Paste for You! — Objective-See (Patrick Wardle, 2026-03-31)](https://objective-see.org/blog/blog_0x87.html)
- [macOS ClickFix Campaign: AppleScript Stealers & New Terminal Protections — Netskope](https://www.netskope.com/blog/macos-clickfix-campaign-applescript-stealers-new-terminal-protections)
- [Objective by the Sea v8 talk — Koh M. Nakagawa, original es_event_paste_t / xprotectd reverse engineering](https://objectivebythesea.org/v8/talks/OBTS_v8_kNakagawa.pdf)

## Related Notes
- [[30 - Knowledge/Cybersecurity/Malware & TTPs/ClickFix macOS Script Editor and Atomic Stealer - Research Extraction]]
- [[20 - Areas/Threat Hunting/Hunt - ClickFix macOS Script Editor and Atomic Stealer]]
- [[30 - Knowledge/Cybersecurity/Attack Techniques/ClickFix]] — Windows/Linux ClickFix variants
- [[30 - Knowledge/Cybersecurity/Attack Techniques/macOS Info Stealer - Data Targeted]] — Atomic Stealer payload context
