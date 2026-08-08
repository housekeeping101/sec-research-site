---
title: macOS Gaslight Backdoor
date: 2026-07-10
type: ttp
mitre_id: T1123, T1115, T1056.004, T1571, T1008, T1543.001, T1140, T1027, T1020, T1059.004
mitre_tactic: Collection, Credential Access, Command and Control, Persistence, Defense Evasion, Execution, Exfiltration
threat_actors: [DPRK-aligned cluster (XProtect MACOS_BONZAI_COBUCH / AIRPIPE)]
tools_used: [Rust, Telegram Bot API, aes-gcm crate, serde, reqwest/hyper, CPython 3.10.18 standalone interpreter]
platforms: [macOS]
tags:
  - type/ttp
  - status/active
  - platform/macos
  - category/backdoor
  - category/credential-access
  - category/anti-analysis
source:
  url: https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/
  author: Phil Stokes (SentinelOne)
  date: 2026-06-23
---

## Summary
macOS.Gaslight is a Rust-based macOS backdoor from a DPRK-aligned activity cluster that provides interactive shell access, Keychain credential theft, and hardened Telegram-based command-and-control. Its defining technical contribution is an embedded prompt-injection payload aimed not at sandboxes or EDR, but at LLM-assisted analysts and automated AI triage pipelines — an anti-*analysis* technique that targets the human/AI review step rather than the execution environment.

## How It Works

### Step 1 — Delivery & Execution (T1059.004)
- Sample executes as a native Rust Mach-O binary, ad hoc signed (`endpoint-macos-aarch64-...`)
- Resolves its own executable path at runtime via `__NSGetExecutablePath` rather than relying on static assumptions

### Step 2 — Persistence Installation (T1543.001)
- Installs a LaunchAgent plist at `~/Library/LaunchAgents/com.apple.system.services.activity.plist`
- The label `com.apple.system.services.activity` is deliberately chosen to resemble genuine Apple system services in `launchctl list` output
- Persistence installation is gated behind a `persist_enable` serde configuration flag, indicating operator/build-time control over whether the implant persists

### Step 3 — C2 Channel Establishment (T1571, T1008)
- Uses the Telegram Bot API as C2 transport, polling via `getUpdates`
- Pins TLS to a custom trust anchor with `SecTrustSetAnchorCertificatesOnly`, resisting interception by analysis proxies
- Reads system proxy configuration via `SCDynamicStoreCopyProxies` so traffic blends with legitimate corporate egress
- Encrypts all C2 messages with AES-GCM (fresh nonce per message via `CCRandomGenerateBytes`)
- Enforces single-instance execution by handling Telegram's `Conflict` API error code

### Step 4 — Interactive Operator Commands (T1059.004)
- Exposes a command verb set: `help`, `id`, `shell`, `kill`, `upload`, `stop`
- `shell` executes arbitrary commands via `execvp`/`posix_spawnp`, giving the operator interactive remote shell access
- `IOPMAssertionCreateWithName` prevents the Mac from sleeping during active operator sessions

### Step 5 — Credential & Data Collection (T1056.004, T1115, T1123)
- Targets `login.keychain-db` for credential theft
- Collects clipboard and input data alongside keychain contents
- Optionally drops and executes an embedded ~6.6 KB base64-encoded Python stealer script under a standalone CPython 3.10.18 interpreter fetched from `astral-sh/python-build-standalone`, extending collection capability beyond native Rust code

### Step 6 — Exfiltration (T1020)
- Collected data is archived to `/tmp/collected_data.zip`
- Uploaded to the operator via Telegram's `attach://` multipart upload mechanism

### Step 7 — Anti-Analysis via LLM Prompt Injection (T1027, T1140)
- Embeds a 3.5 KB Markdown-fenced blob containing 38 fabricated "system" messages, using `{{DATA}}`-style delimiters that mimic real LLM prompt scaffolding
- Fabricated messages simulate environment failures (token expiry, OOM kills, disk exhaustion, repeated operation failures) and plant false injection/static-analysis warnings
- Goal: if the sample's contents are ingested by an LLM-assisted analysis or SOC-triage pipeline, the injected content attempts to manipulate the model into aborting, truncating, or refusing to complete analysis — degrading or denying the analyst's tooling output rather than evading a sandbox
- Also self-redacts Telegram bot tokens in any runtime output (`file/token:redacted`) to reduce value of logs/memory dumps to a human analyst

## Detection Opportunities

### Key Log Sources
- **Endpoint telemetry (CrowdStrike/EDR):** LaunchAgent/LaunchDaemon file writes; process execution of the Rust binary and any spawned shell/Python children
- **File system monitoring:** `login.keychain-db` access by non-Apple/non-browser processes; archive creation at `/tmp/collected_data.zip`
- **Network:** Outbound HTTPS to Telegram API infrastructure (`api.telegram.org`) from unexpected processes; TLS fingerprint anomalies from custom trust-anchor pinning
- **macOS Unified Log / ESF:** LaunchAgent load events; `IOPMAssertionCreateWithName` calls from unsigned/newly-seen binaries

### Behavioral Indicators
- New LaunchAgent with a `com.apple.*`-namespaced label that does not correspond to a genuine Apple-signed bundle
- Process accessing `login.keychain-db` that is not Keychain Access, a browser, or another expected Apple/first-party process
- Downloading a standalone CPython interpreter from `astral-sh/python-build-standalone` on an endpoint with no development use case
- Archive written to `/tmp` immediately followed by outbound network activity to Telegram infrastructure
- Repeated `getUpdates`-style long-polling HTTP patterns to `api.telegram.org` from a non-browser, non-messaging process

### Artifacts Left Behind
- `~/Library/LaunchAgents/com.apple.system.services.activity.plist`
- `/tmp/collected_data.zip`
- Ad hoc code signature `endpoint-macos-aarch64-5555494492fc075f441637fb9d894913dde3a2ea`
- SHA256 `6328567511d88fdc2ae0939c5ef17b7a63d2a833881900de018a4f12f4982525` (macOS.Gaslight) and related sibling/dropped-file hashes in [[30 - Knowledge/Cybersecurity/Malware & TTPs/macOS Gaslight Backdoor - Research Extraction]]

## Query Stubs

### CrowdStrike FQL

```
// Suspicious LaunchAgent masquerading in Apple's com.apple.* namespace
#repo=base_sensor #event_simpleName=/(LaunchAgentDefinitionFileWritten|FileCreateInfo)/
| TargetFileName=/LaunchAgents\/com\.apple\..*\.plist$/
| select(Timestamp, ComputerName, UserName, TargetFileName)
| sort(-Timestamp)
```

```
// Non-standard process accessing login.keychain-db
#repo=base_sensor #event_simpleName=/(FileOpenInfo|FileAccessInfo)/
| TargetFileName=/login\.keychain-db$/
| !ImageFileName=/(Keychain Access|Safari|Google Chrome|firefox|securityd)/
| select(Timestamp, ComputerName, UserName, ImageFileName, TargetFileName)
| sort(-Timestamp)
```

```
// Outbound connections to Telegram API from unexpected processes
#repo=base_sensor #event_simpleName=/(DnsRequest|NetworkConnectIP4)/
| DomainName=/api\.telegram\.org/
| !ImageFileName=/(Telegram|Slack|Discord)/
| select(Timestamp, ComputerName, UserName, ImageFileName, DomainName)
| sort(-Timestamp)
```

```
// Hash match on known macOS.Gaslight / sibling BONZAI artifacts
#repo=base_sensor #event_simpleName=/(ProcessRollup2|NewExecutableWritten)/
| SHA256HashData=(6328567511d88fdc2ae0939c5ef17b7a63d2a833881900de018a4f12f4982525, 77b4fd46994992f0e57302cfe76ed23c0d90101381d2b89fc2ddf5c4536e77ca)
| select(Timestamp, ComputerName, UserName, TargetFileName, CommandLine)
```

### Databricks SQL

```sql
-- LaunchAgent plist written under Apple's namespace but not code-signed by Apple
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  target_file_name
FROM crowdstrike.file_events
WHERE target_file_name RLIKE '.*LaunchAgents/com\\.apple\\..*\\.plist$'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- Non-browser, non-Apple process accessing login.keychain-db
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  image_file_name,
  target_file_name
FROM crowdstrike.file_events
WHERE target_file_name LIKE '%login.keychain-db'
  AND image_file_name NOT RLIKE '.*(Keychain Access|Safari|Google Chrome|firefox|securityd).*'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- Outbound traffic to Telegram API from non-messaging processes
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  image_file_name,
  domain_name
FROM crowdstrike.dns_events
WHERE domain_name LIKE '%api.telegram.org%'
  AND image_file_name NOT RLIKE '.*(Telegram|Slack|Discord).*'
ORDER BY timestamp DESC
LIMIT 500;
```

## Threat Actor Usage

| Actor | Notes |
|---|---|
| DPRK-aligned macOS activity cluster (unnamed in source) | Assessed with high confidence by SentinelOne based on code/infrastructure overlap with sibling sample BONZAI, detected by Apple XProtect rule `MACOS_BONZAI_COBUCH`, and linkage to the `AIRPIPE` rule cluster |

See also: [[30 - Knowledge/Cybersecurity/Attack Techniques/macOS Info Stealer - Data Targeted]] for broader macOS credential/data-targeting patterns used by similar clusters.

## References
- [macOS.Gaslight: Rust Backdoor Turns Prompt Injection on the Analyst, Not the Sandbox — SentinelOne SentinelLABS (Phil Stokes, 2026-06-23)](https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/)

## Related Notes
- [[30 - Knowledge/Cybersecurity/Malware & TTPs/macOS Gaslight Backdoor - Research Extraction]]
- [[20 - Areas/Threat Hunting/Hunt - macOS Gaslight Backdoor]]
- [[30 - Knowledge/Cybersecurity/Attack Techniques/macOS Info Stealer - Data Targeted]] — related macOS credential/data targeting context
