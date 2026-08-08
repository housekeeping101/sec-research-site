---
title: Hunt - macOS Gaslight Backdoor
date: 2026-07-10
type: hunt
status: active
hypothesis: A DPRK-aligned Rust-based macOS backdoor (macOS.Gaslight) is present on endpoints, persisting via an Apple-namespace-masquerading LaunchAgent and exfiltrating Keychain/clipboard/input data over Telegram Bot API C2, which would manifest as an unsigned-by-Apple LaunchAgent in the com.apple.* namespace, non-browser access to login.keychain-db, staged archives in /tmp, and outbound Telegram API traffic from unexpected processes.
priority: high
platform: CrowdStrike, Databricks
mitre_id: T1123, T1115, T1056.004, T1571, T1008, T1543.001, T1140, T1027, T1020, T1059.004
tags:
  - type/hunt
  - status/active
  - platform/macos
  - platform/crowdstrike
  - platform/databricks
  - category/backdoor
  - category/credential-access
  - category/anti-analysis
---

## Hypothesis

> *"I believe macOS.Gaslight or a closely related DPRK-aligned macOS backdoor is present in the environment because the sample remained undetected by static AV engines as of its public writeup and relies on generic-looking persistence and C2 infrastructure (Telegram), which would manifest as an Apple-namespace-masquerading LaunchAgent, non-browser processes touching `login.keychain-db`, archive staging in `/tmp` followed by Telegram API traffic, and possibly a fetched standalone CPython interpreter on endpoints with no legitimate development use case."*

**Why this is worth hunting:**
- The sample was reported as undetected by static engines on VirusTotal as of the source article — signature-based AV/EDR alone is unlikely to catch it; behavioral hunting is necessary
- Telegram Bot API as C2 blends with legitimate messaging traffic and is rarely blocked by default egress policy, making network-layer detection alone insufficient
- LaunchAgent labels masquerading as `com.apple.*` are a low-noise, high-signal artifact — legitimate third-party software should never use Apple's reserved namespace
- This is attributed to a DPRK-aligned cluster with a track record of targeting crypto, fintech, and remote-work-adjacent organizations via social engineering (fake job offers/interviews, fake apps) — relevant if the org has exposure in those verticals
- The embedded LLM prompt-injection payload is a signal in itself: if analysts or automated pipelines observe a sample behaving oddly when summarized/triaged by AI tooling (refusals, truncated output, spurious "environment failure" messages), that is itself a detection opportunity worth documenting for the SOC

## Assumptions & Scope

- **Environment:** macOS endpoints enrolled in CrowdStrike Falcon with process, file, and DNS telemetry enabled
- **Timeframe:** Look back 90 days initially given the sample was still undetected by static engines as of 2026-06-23; tighten to 30 days if signal is strong
- **Data sources:** CrowdStrike process events, file events, DNS/network events; Databricks unified log tables
- **Assumptions:**
  - No legitimate enterprise software installs a LaunchAgent labeled `com.apple.system.services.activity` or similar `com.apple.*`-namespaced labels outside genuine Apple-signed binaries
  - Non-browser, non-Apple processes reading `login.keychain-db` are anomalous in this environment
  - Telegram is not an approved business messaging tool in this environment (adjust if it is — tune to exclude the approved Telegram Desktop client)
  - Standalone CPython downloads from `astral-sh/python-build-standalone` are unusual outside developer/build endpoints

## Hunt Plan

1. **Hunt for Apple-namespace-masquerading LaunchAgents**
   Search for LaunchAgent plist writes under `~/Library/LaunchAgents/com.apple.*` where the writing/parent process is not a genuine Apple system process. This is the highest-confidence persistence signal.

2. **Hunt for non-browser keychain access**
   Search for `login.keychain-db` file access by any process other than Keychain Access, browsers, or `securityd`. Cross-reference the accessing process's code signature — unsigned or ad hoc signed binaries are high priority.

3. **Hunt for /tmp archive staging followed by Telegram traffic**
   Correlate creation of `/tmp/collected_data.zip` (or similarly-named archives in `/tmp`) with subsequent outbound HTTPS connections to `api.telegram.org` from the same host within a short time window.

4. **Hunt for unexpected Telegram Bot API polling**
   Look for repeated `getUpdates`-pattern HTTPS requests to `api.telegram.org` from processes that are not the legitimate Telegram Desktop/mobile client.

5. **Hunt for standalone CPython interpreter fetches**
   Search for downloads or executions referencing `astral-sh/python-build-standalone` or CPython 3.10.18 standalone builds on endpoints without an established developer/build use case.

6. **Hash hunt for known macOS.Gaslight and sibling BONZAI artifacts**
   Search all file write and execution events for the known SHA256 hashes documented in [[30 - Knowledge/Cybersecurity/Malware & TTPs/macOS Gaslight Backdoor - Research Extraction]].

7. **Code signature hunt**
   Search for binaries carrying the ad hoc signing ID `endpoint-macos-aarch64-5555494492fc075f441637fb9d894913dde3a2ea` or similarly-patterned `endpoint-macos-aarch64-*` ad hoc signatures.

## Queries

### CrowdStrike FQL

```
// Hunt 1: LaunchAgent masquerading in Apple's com.apple.* namespace
#repo=base_sensor #event_simpleName=/(LaunchAgentDefinitionFileWritten|FileCreateInfo)/
| TargetFileName=/LaunchAgents\/com\.apple\..*\.plist$/
| select(Timestamp, ComputerName, UserName, TargetFileName, ImageFileName)
| sort(-Timestamp)
```

```
// Hunt 2: Non-Apple/non-browser process accessing login.keychain-db
#repo=base_sensor #event_simpleName=/(FileOpenInfo|FileAccessInfo)/
| TargetFileName=/login\.keychain-db$/
| !ImageFileName=/(Keychain Access|Safari|Google Chrome|firefox|securityd)/
| select(Timestamp, ComputerName, UserName, ImageFileName, TargetFileName)
| sort(-Timestamp)
```

```
// Hunt 3: Archive staged in /tmp followed by Telegram API traffic (same host)
#repo=base_sensor #event_simpleName=/(FileCreateInfo|NewExecutableWritten)/
| TargetFileName=/\/tmp\/.*\.zip$/
| join(#event_simpleName=DnsRequest DomainName=/api\.telegram\.org/, field=ComputerName)
| select(Timestamp, ComputerName, UserName, TargetFileName, DomainName)
```

```
// Hunt 4: Telegram API polling from non-Telegram client processes
#repo=base_sensor #event_simpleName=DnsRequest
| DomainName=/api\.telegram\.org/
| !ImageFileName=/Telegram/
| select(Timestamp, ComputerName, UserName, ImageFileName, DomainName)
| sort(-Timestamp)
```

```
// Hunt 5: Standalone CPython interpreter fetch (astral-sh/python-build-standalone)
#repo=base_sensor #event_simpleName=/(DnsRequest|NetworkConnectIP4)/
| DomainName=/(astral-sh|python-build-standalone)/
| select(Timestamp, ComputerName, UserName, ImageFileName, DomainName)
| sort(-Timestamp)
```

```
// Hunt 6: Hash match — macOS.Gaslight and sibling BONZAI/dropped-file hashes
#repo=base_sensor #event_simpleName=/(ProcessRollup2|NewExecutableWritten)/
| SHA256HashData=(6328567511d88fdc2ae0939c5ef17b7a63d2a833881900de018a4f12f4982525, 77b4fd46994992f0e57302cfe76ed23c0d90101381d2b89fc2ddf5c4536e77ca, baabf249c77bc54c54ab0e66e15af798bd28aa5b4683554456a8b73ab8741239, b3c56d689414343589f38394d19ba2fe9a518133281200faa0556ba4e4136394)
| select(Timestamp, ComputerName, UserName, TargetFileName, CommandLine)
```

```
// Hunt 7: Ad hoc code signature pattern match
#repo=base_sensor #event_simpleName=ProcessRollup2
| CertificateSubject=/endpoint-macos-aarch64-/
| select(Timestamp, ComputerName, UserName, ImageFileName, CertificateSubject)
| sort(-Timestamp)
```

### Databricks SQL

```sql
-- Hunt 1: LaunchAgent masquerading in Apple's com.apple.* namespace
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  target_file_name,
  image_file_name
FROM crowdstrike.file_events
WHERE target_file_name RLIKE '.*LaunchAgents/com\\.apple\\..*\\.plist$'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- Hunt 2: Non-Apple/non-browser process accessing login.keychain-db
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
-- Hunt 3: /tmp archive staging correlated with Telegram API DNS on same host within 1 hour
WITH staged AS (
  SELECT device_id, computer_name, timestamp AS stage_ts, target_file_name
  FROM crowdstrike.file_events
  WHERE target_file_name RLIKE '^/tmp/.*\\.zip$'
),
telegram AS (
  SELECT device_id, timestamp AS dns_ts, domain_name
  FROM crowdstrike.dns_events
  WHERE domain_name LIKE '%api.telegram.org%'
)
SELECT s.stage_ts, s.computer_name, s.target_file_name, t.dns_ts, t.domain_name
FROM staged s
JOIN telegram t
  ON s.device_id = t.device_id
  AND t.dns_ts BETWEEN s.stage_ts AND s.stage_ts + INTERVAL 1 HOUR
ORDER BY s.stage_ts DESC;
```

```sql
-- Hunt 4: Telegram API polling from non-Telegram client processes
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  image_file_name,
  domain_name
FROM crowdstrike.dns_events
WHERE domain_name LIKE '%api.telegram.org%'
  AND image_file_name NOT RLIKE '.*Telegram.*'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- Hunt 5: Standalone CPython interpreter fetch
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  image_file_name,
  domain_name
FROM crowdstrike.dns_events
WHERE domain_name RLIKE '.*(astral-sh|python-build-standalone).*'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- Hunt 6: Hash match — known macOS.Gaslight / sibling artifacts
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  target_file_name,
  sha256_hash
FROM crowdstrike.file_events
WHERE sha256_hash IN (
  '6328567511d88fdc2ae0939c5ef17b7a63d2a833881900de018a4f12f4982525',
  '77b4fd46994992f0e57302cfe76ed23c0d90101381d2b89fc2ddf5c4536e77ca',
  'baabf249c77bc54c54ab0e66e15af798bd28aa5b4683554456a8b73ab8741239',
  'b3c56d689414343589f38394d19ba2fe9a518133281200faa0556ba4e4136394'
)
ORDER BY timestamp DESC;
```

```sql
-- Hunt 7: Ad hoc code signature pattern match
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  image_file_name,
  certificate_subject
FROM crowdstrike.process_events
WHERE certificate_subject LIKE '%endpoint-macos-aarch64-%'
ORDER BY timestamp DESC
LIMIT 500;
```

## Findings

### Hits
_(No results yet — hunt not executed)_

### False Positives / Tuning Notes
- **Hunt 1 (Apple-namespace LaunchAgents):** Verify code signature of the writing process — genuine Apple system processes are signed by Apple; anything else in this namespace is suspicious. Some MDM/management tools occasionally install helper LaunchAgents — confirm against known MDM baseline before escalating.
- **Hunt 2 (keychain access):** `securityd`, browsers, and password managers (1Password, Bitwarden helper processes) legitimately access the keychain — build an allowlist of approved password-manager binaries and their code signatures.
- **Hunt 3 (archive + Telegram correlation):** Backup/sync tools occasionally stage zips in `/tmp`; only escalate when correlated with Telegram API traffic specifically, not general outbound HTTPS.
- **Hunt 4 (Telegram polling):** If Telegram Desktop is an approved business tool in this environment, exclude its known signed binary path and code signature; focus on unsigned or non-standard processes making Telegram API calls.
- **Hunt 5 (CPython standalone fetch):** Developer and CI/build endpoints (e.g., using `uv`, `rye`, or similar Python tooling) legitimately fetch from `astral-sh/python-build-standalone`. Exclude known developer machines/build agents by ComputerName or asset tag.
- **Hunt 7 (ad hoc signature pattern):** `endpoint-macos-aarch64-*` naming may be specific to this actor's build tooling; confirm the pattern still holds before treating as a durable IOC — attackers change signing conventions between campaigns.

## Outcome
- [ ] No evidence of macOS.Gaslight activity found
- [ ] Suspicious activity found — escalate for investigation
- [ ] Detection rule created based on hunt findings

## Related Notes
- [[30 - Knowledge/Cybersecurity/Attack Techniques/macOS Gaslight Backdoor]]
- [[30 - Knowledge/Cybersecurity/Malware & TTPs/macOS Gaslight Backdoor - Research Extraction]]
- [[40 - Resources/Query Library/Hunt Queries]]
- [[20 - Areas/Detection Engineering/Detections]]
