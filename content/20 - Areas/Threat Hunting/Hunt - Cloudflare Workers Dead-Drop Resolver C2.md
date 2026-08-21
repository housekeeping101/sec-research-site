---
title: Hunt - Cloudflare Workers Dead-Drop Resolver C2
date: 2026-08-21
type: hunt
status: active
hypothesis: An APT-style actor is using dead-drop resolvers (Microsoft Graph API, Cloudflare Workers, Outlook API) to resolve C2 addresses at runtime and AD CS misconfiguration abuse for privilege escalation, which would manifest as OAuth2 Client Credentials Grant applications bulk-enumerating users, outbound traffic to *.workers.dev subdomains, DLL side-loading via U-Messenger.exe, NTLM relay attempts against ADCS endpoints, and modify-then-restore tampering of GPO logon scripts.
priority: high
platform: CrowdStrike, Databricks
mitre_id: T1566.002, T1021.002, T1037.001, T1574.002, T1140, T1132, T1071.001, T1008, T1550.001, T1649
tags:
  - type/hunt
  - status/active
  - platform/windows
  - platform/cloud
  - platform/crowdstrike
  - platform/databricks
  - category/c2
  - category/apt
---

## Hypothesis

> *"I believe an actor using dead-drop-resolver C2 (via Microsoft Graph API, Outlook, or Cloudflare Workers) combined with AD CS privilege escalation is present in the environment because this technique class is explicitly designed to launder C2 resolution through trusted first-party cloud services that defenders rarely block wholesale, which would manifest as anomalous OAuth2 app authentication patterns against Graph API, outbound traffic to *.workers.dev subdomains, DLL side-loading, NTLM relay attempts against certificate enrollment endpoints, and brief modify-then-restore tampering of GPO logon scripts."*

**Why this is worth hunting:**
- Both documented actors using this technique (an unnamed Chinese state-sponsored group targeting Taiwan, and Gamaredon independently) are APT-tier, meaning any hit warrants immediate high-priority escalation rather than routine commodity-malware triage
- The DDR technique is specifically engineered to defeat domain-reputation and network-allowlist defenses by hiding behind Microsoft Graph, Outlook, Google Sheets, and Cloudflare Workers — services almost every organization already trusts and rarely restricts
- AD CS misconfigurations (ESC1/3/8/11) are common in real-world Active Directory deployments — this hunt doubles as a proactive AD CS hygiene check regardless of whether active exploitation is found
- The ephemeral GPO-script-tampering anti-forensic technique (modify → execute → restore) is specifically designed to evade standard file-integrity monitoring intervals — a hunt with sufficiently granular polling may be one of the only ways to catch it
- Two unrelated nation-state-aligned actors independently converging on the same DDR/Workers tradecraft in the same reporting window (2026) suggests this is becoming a broader adopted technique class, not an isolated one-off

## Assumptions & Scope

- **Environment:** Windows endpoints and Microsoft 365/Entra ID tenant with audit logging enabled; CrowdStrike Falcon with process, module, file, and DNS telemetry
- **Timeframe:** Look back 90 days given this reflects an ongoing APT tradecraft pattern rather than a single burst campaign; extend to 180 days for the AD CS misconfiguration review specifically, since that's a standing-posture check rather than an activity hunt
- **Data sources:** CrowdStrike process/module/file/DNS events; Microsoft 365/Entra ID audit logs (OAuth app consent, sign-in logs); Databricks unified log tables; Active Directory Certificate Services configuration export
- **Assumptions:**
  - No legitimate business application in this environment should need Client Credentials Grant access to enumerate the *entire* user directory and read arbitrary user profile attribute fields like `streetAddress`
  - `*.workers.dev` outbound traffic from endpoints (not from known SaaS integrations/browsers) is unusual outside of developer testing
  - `gpupdate.bat` and other GPO logon scripts are static between deliberate change-management events — any unscheduled modification is notable regardless of whether it's later "reverted"
  - AD CS certificate templates should not grant broad Enroll permissions to Domain/Authenticated Users without an documented business reason

## Hunt Plan

1. **Hunt for anomalous OAuth2 Client Credentials Grant Graph API usage**
   Search Entra ID / M365 audit logs for service principals authenticating via Client Credentials Grant that subsequently enumerate the full org user list or read/write unusual profile attribute fields (`streetAddress`, etc.) outside HR/IT tooling.

2. **Hunt for outbound traffic to Cloudflare Workers subdomains**
   Search DNS/network logs for `*.workers.dev` connections originating from endpoint processes rather than known browser/SaaS-integration traffic.

3. **Hunt for DLL side-loading via U-Messenger.exe**
   Search for `U-Messenger.exe` (or similarly-abused legitimate signed binaries) loading an unsigned or unexpected `version.dll` or similarly-named module.

4. **Hunt for NTLM relay attempts against ADCS endpoints**
   Search authentication logs for NTLM relay patterns targeting `certsrv` (ADCS Web Enrollment) or the RPC certificate enrollment interface (ESC8/ESC11 patterns).

5. **AD CS configuration hygiene review**
   Independent of activity hunting: export and review certificate template permissions for ESC1 (broad Enroll rights to Domain/Authenticated Users) and ESC3 (Enrollment Agent template) misconfigurations. This is a standing-posture check, not a log-based hunt.

6. **Hunt for ephemeral GPO logon script tampering**
   Search Windows Security Event Log (4663/4656 object access auditing, if enabled) or file-integrity monitoring for modification events on `gpupdate.bat` and other GPO logon scripts, especially outside scheduled change-management windows.

7. **Hash hunt for known GRAPHBROTLI/GRAPHRELOOK/RCREMARK artifacts**
   Search file write/execution events for the known MD5 hashes documented in [[Malware & TTPs/Cloudflare Workers Dead-Drop Resolver C2 - Research Extraction]] — note these are MD5 only (lower confidence); treat as a supplementary check, not primary detection.

## Queries

### CrowdStrike FQL

```
// Hunt 2: Outbound connections to Cloudflare Workers subdomains
#repo=base_sensor #event_simpleName=/(DnsRequest|NetworkConnectIP4)/
| DomainName=/\.workers\.dev$/i
| select(Timestamp, ComputerName, UserName, ImageFileName, DomainName)
| sort(-Timestamp)
```

```
// Hunt 3: U-Messenger.exe loading an unexpected version.dll
#repo=base_sensor #event_simpleName=ImageHash
| ImageFileName=/U-Messenger\.exe/i
| ModuleFileName=/version\.dll$/i
| select(Timestamp, ComputerName, UserName, ImageFileName, ModuleFileName, SHA256HashData)
| sort(-Timestamp)
```

```
// Hunt 4: NTLM relay attempts against ADCS Web Enrollment
#repo=base_sensor #event_simpleName=NetworkConnectIP4
| TargetPort=(80, 443)
| RequestUri=/certsrv/i
| select(Timestamp, ComputerName, UserName, RemoteAddressIP4, RequestUri)
| sort(-Timestamp)
```

```
// Hunt 7: Hash match — known GRAPHBROTLI/GRAPHRELOOK/RCREMARK artifacts (MD5)
#repo=base_sensor #event_simpleName=/(ProcessRollup2|NewExecutableWritten)/
| MD5HashData=(6affcbf6607ee163a49bb750ae1397c1, b29ff0af33b38ec98e62a5c24d1dd06d, 45c4c4d4224c413408450e965c618742, 529abd9cf61fbab99f440e4134f27fd8)
| select(Timestamp, ComputerName, UserName, TargetFileName, CommandLine)
```

### Databricks SQL

```sql
-- Hunt 1: OAuth2 Client Credentials Grant apps enumerating the full user directory
SELECT
  timestamp,
  application_id,
  application_display_name,
  operation,
  result_status
FROM m365.audit_events
WHERE (operation = 'List users.' AND grant_type = 'client_credentials')
   OR (operation = 'Update user.' AND target_attribute = 'streetAddress')
ORDER BY timestamp DESC
LIMIT 500;
-- TODO: tune exclusions — known approved automation/HR/identity-sync service accounts
```

```sql
-- Hunt 2: Outbound connections to Cloudflare Workers subdomains
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  image_file_name,
  domain_name
FROM crowdstrike.dns_events
WHERE domain_name RLIKE '.*\\.workers\\.dev$'
ORDER BY timestamp DESC
LIMIT 500;
-- TODO: tune exclusions — legitimate developer endpoints testing Cloudflare Workers deployments
```

```sql
-- Hunt 3: U-Messenger.exe loading an unexpected version.dll
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  image_file_name,
  module_file_name,
  sha256_hash
FROM crowdstrike.module_events
WHERE image_file_name RLIKE '.*U-Messenger\\.exe'
  AND module_file_name RLIKE '.*version\\.dll$'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- Hunt 4: NTLM relay attempts against ADCS Web Enrollment
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  remote_address,
  request_uri
FROM crowdstrike.network_events
WHERE request_uri RLIKE '.*certsrv.*'
ORDER BY timestamp DESC
LIMIT 500;
```

```sql
-- Hunt 6: GPO logon script modification events (requires object-access auditing / FIM feed)
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  target_file_name,
  event_type
FROM crowdstrike.file_events
WHERE target_file_name RLIKE '.*(gpupdate\\.bat|SYSVOL.*\\\\Scripts\\\\).*'
  AND event_type IN ('FileWriteInfo', 'FileModifyInfo')
ORDER BY timestamp DESC
LIMIT 500;
-- TODO: tune exclusions — scheduled GPO change-management windows
```

```sql
-- Hunt 7: Hash match — known GRAPHBROTLI/GRAPHRELOOK/RCREMARK artifacts (MD5)
SELECT
  timestamp,
  device_id,
  computer_name,
  user_name,
  target_file_name,
  md5_hash
FROM crowdstrike.file_events
WHERE md5_hash IN (
  '6affcbf6607ee163a49bb750ae1397c1',
  'b29ff0af33b38ec98e62a5c24d1dd06d',
  '45c4c4d4224c413408450e965c618742',
  '529abd9cf61fbab99f440e4134f27fd8'
)
ORDER BY timestamp DESC;
```

## Findings

### Hits
_(No results yet — hunt not executed)_

### False Positives / Tuning Notes
- **Hunt 1 (Graph API Client Credentials Grant):** Legitimate identity-sync tools (e.g. Okta, Azure AD Connect, HR platforms) and SIEM/SOAR integrations commonly use Client Credentials Grant with broad user-read scopes — build an allowlist of approved application IDs before treating this as high-signal; the `streetAddress`-write pattern specifically is far higher confidence than bulk user-list reads alone.
- **Hunt 2 (Workers subdomains):** Developers legitimately deploy and test against `*.workers.dev` — exclude known dev/build endpoints and correlate with other hunt hits (especially Hunt 3 or Hunt 4) before escalating.
- **Hunt 3 (DLL side-loading):** Confirm `U-Messenger.exe` is genuinely present/used in this environment before relying on this hunt — if it's not deployed here, generalize the search pattern to other commonly side-loaded legitimate binaries instead.
- **Hunt 4 (NTLM relay to ADCS):** Some legitimate certificate auto-enrollment traffic will hit `certsrv` — baseline normal enrollment volume/sources first; relay attempts typically show as enrollment requests from unexpected source hosts relaying another user's captured NTLM session, not a host enrolling its own certificate.
- **Hunt 5 (AD CS hygiene review):** This is a posture check, not an activity hunt — findings here should generate a remediation ticket (tighten template permissions, disable NTLM on ADCS endpoints) regardless of whether active exploitation is observed.
- **Hunt 6 (GPO script tampering):** Requires object-access auditing (4663/4656) or a file-integrity monitoring feed with sufficiently granular polling to catch a modify-then-restore window — if that telemetry isn't currently collected, this hunt step should first drive a logging-gap remediation request.
- **Hunt 7 (hash match):** MD5-only IOCs are low-confidence and easily invalidated by minor sample recompilation — treat a miss as inconclusive, prioritize Hunts 1–4 for durable detection.

## Outcome
- [ ] No evidence of dead-drop-resolver C2 activity found
- [ ] Suspicious activity found — escalate for investigation
- [ ] Detection rule created based on hunt findings

## Related Notes
- [[Attack Techniques/Cloudflare Workers Dead-Drop Resolver C2]]
- [[Malware & TTPs/Cloudflare Workers Dead-Drop Resolver C2 - Research Extraction]]
- [[40 - Resources/Query Library/Hunt Queries]]
- [[20 - Areas/Detection Engineering/Detections]]
