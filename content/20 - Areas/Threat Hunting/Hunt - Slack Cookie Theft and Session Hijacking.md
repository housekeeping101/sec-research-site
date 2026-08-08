---
title: Hunt - Slack Cookie Theft and Session Hijacking
date: 2026-03-08
type: hunt
status: active
hypothesis: A post-compromise adversary with local filesystem access is extracting unencrypted Slack session cookies from the local SQLite database to impersonate users and access Slack workspaces without triggering MFA.
priority: medium
platform: [CrowdStrike, Databricks]
mitre_id: T1539, T1555, T1213.003
tags:
  - type/hunt
  - status/active
  - platform/macos
  - platform/windows
  - category/credential-access
  - category/lateral-movement
---

## Hypothesis

> I believe a post-compromise adversary is reading the local Slack `Cookies` SQLite database using a non-Slack process (e.g., `sqlite3`, Python, or a custom tool) to extract authentication tokens, because Slack stores session cookies in plaintext with no expiry, which would manifest as anomalous file access to the Slack application support directory, unexpected new Slack sessions, or deletion of `root-state.json` for cleanup.

**Why this is worth hunting:**
- Slack cookies never expire and survive password resets — a stolen cookie gives persistent, silent access
- The technique bypasses MFA entirely — no alerting on the identity side
- It requires only read access to a user's home directory, achievable post-initial-access
- Slack is used heavily in enterprise environments and frequently contains sensitive communications, credentials, and file transfers
- Vendor declined to encrypt the cookie store (as of SpecterOps disclosure, 2020) — issue may persist

---

## Assumptions & Scope
- Environment: macOS endpoints (primary) and Windows endpoints (secondary)
- Timeframe: Rolling 30 days
- Data sources available:
  - CrowdStrike EDR — file access events (`FileOpenInfo`), process events (`ProcessRollup2`)
  - Databricks — file event telemetry
  - Slack audit logs (if Enterprise Grid or Plus plan is available)
  - macOS Unified Log (if collected)

---

## Hunt Plan

1. **Identify non-Slack processes accessing the Slack cookie store**
   Hunt for any process reading `Slack/Cookies` where the image name is not the Slack application binary. This is the most direct signal.

2. **Hunt for database tools targeting Slack directories**
   Look for `sqlite3`, Python, or scripting engines with command-line arguments referencing Slack paths. Attackers need a way to read the SQLite DB — this is the most common method.

3. **Hunt for workspace enumeration activity**
   Look for processes reading `slack-workspaces` or `slack-downloads` outside of normal Slack app activity — this indicates reconnaissance of available workspaces.

4. **Hunt for `root-state.json` deletion**
   Deletion of this file is a cleanup step described in the SpecterOps research. It is not normal user behavior.

5. **Correlate with Slack audit logs (if available)**
   Cross-reference new Slack login sessions with endpoint file access events. A login from an unexpected IP/device within minutes of file access is high confidence.

6. **Review network telemetry for Slack API calls from unexpected processes**
   Legitimate Slack API calls should only originate from the Slack app. A `curl`, `python`, or custom binary making calls to `slack.com/api/` is suspicious.

---

## Queries

### CrowdStrike FQL

> Parameterized: `40 - Resources/Query Library/queries/hunting/cs-hunt-slack-cookie-theft.md`

```fql
// 1. Non-Slack process accessing Slack Cookies file (macOS)
event_simpleName=FileOpenInfo
| FilePath=*/Library/Application Support/Slack/Cookies
| NOT ImageFileName IN ("*/Slack.app/Contents/MacOS/Slack", "*/Slack Helper*")
| table _time, ComputerName, UserName, ImageFileName, FilePath

// 2. Non-Slack process accessing Slack Cookies file (Windows)
event_simpleName=FileOpenInfo
| FilePath=*\Roaming\Slack\Cookies
| NOT ImageFileName IN ("*\Slack\app-*\slack.exe", "*\slack.exe")
| table _time, ComputerName, UserName, ImageFileName, FilePath

// 3. sqlite3 or python referencing Slack directory
event_simpleName=ProcessRollup2
| ImageFileName IN ("*/sqlite3", "*/python3", "*/python", "*\sqlite3.exe", "*\python.exe")
| CommandLine=*Slack*
| table _time, ComputerName, UserName, ImageFileName, CommandLine

// 4. Workspace enumeration — reads to slack-workspaces or slack-downloads by non-Slack
event_simpleName=FileOpenInfo
| FilePath IN ("*slack-workspaces*", "*slack-downloads*")
| NOT ImageFileName IN ("*/Slack.app/*", "*\slack.exe")
| table _time, ComputerName, UserName, ImageFileName, FilePath

// 5. root-state.json deletion
event_simpleName=FileDeleteInfo
| FilePath=*root-state.json*
| table _time, ComputerName, UserName, ImageFileName, FilePath
```

### Databricks SQL

> Parameterized: `40 - Resources/Query Library/queries/hunting/db-hunt-slack-cookie-theft.md`

```sql
-- Non-Slack process accessing Slack cookie store (macOS + Windows)
SELECT
  timestamp,
  device_id,
  user,
  process_name,
  file_path
FROM file_events
WHERE
  (file_path LIKE '%Slack/Cookies%' OR file_path LIKE '%Slack\\Cookies%')
  AND process_name NOT LIKE '%Slack%'
ORDER BY timestamp DESC;

-- sqlite3 or scripting engine accessing Slack path
SELECT
  timestamp,
  device_id,
  user,
  process_name,
  command_line
FROM process_events
WHERE
  process_name IN ('sqlite3', 'python3', 'python', 'sqlite3.exe', 'python.exe')
  AND command_line LIKE '%Slack%'
ORDER BY timestamp DESC;

-- root-state.json deletion
SELECT
  timestamp,
  device_id,
  user,
  process_name,
  file_path,
  action
FROM file_events
WHERE
  file_path LIKE '%root-state.json%'
  AND action = 'DELETE'
ORDER BY timestamp DESC;
```

---

## Findings

### Hits
-

### False Positives / Tuning Notes
- Backup agents (Time Machine, Backblaze, etc.) may legitimately read Slack directories — exclude known backup process image names
- IT tooling or MDM agents performing file inventories may access app support directories — document and exclude
- Developer tools or automation scripts that interact with Slack via the filesystem should be reviewed and allowlisted if legitimate
- Slack's own helper processes (e.g., `Slack Helper (Renderer)`) may access `Cookies` — confirm and exclude these image names

---

## Outcome
- [ ] No evidence found — hypothesis closed
- [ ] Suspicious activity found — escalated to investigation
- [ ] Detection rule created → [[link to rule]]

---

## Related Notes
- [[30 - Knowledge/Cybersecurity/Attack Techniques/Abusing Slack for Offensive Operations]] — source TTP note with full attack breakdown and file paths
- [[30 - Knowledge/Cybersecurity/Malware & TTPs/macOS Info Stealer - Data Targeted]] — macOS stealer data targeting (session cookies are the same vector)
- [[20 - Areas/Threat Hunting/Threat Hunting macOS]]
- [[20 - Areas/Detection Engineering/Detections]]
