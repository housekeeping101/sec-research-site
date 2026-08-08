---
title: Abusing Slack for Offensive Operations
date: 2026-03-07
type: ttp
mitre_id: T1539, T1555, T1213.003, T1083
mitre_tactic: Credential Access, Collection, Lateral Movement, Discovery
threat_actors: []
tools_used: [sqlite3, python, curl, Slack client files]
platforms: [Windows, macOS]
tags:
  - type/ttp
  - status/active
  - platform/macos
  - platform/windows
  - category/credential-access
  - category/lateral-movement
  - category/session-hijacking
source:
  url: https://specterops.io/blog/2020/03/04/abusing-slack-for-offensive-operations/
  author: SpecterOps
  date: 2020-03-04
---

## Summary
An attacker with read access to a user's local Slack client directory can extract unencrypted authentication cookies from the `Slack/Cookies` SQLite database and use them to impersonate the user in Slack — including bypassing MFA. Slack stores session cookies in plaintext, they never expire, and they persist across password resets unless explicitly revoked. This makes local Slack data a high-value target for post-compromise credential harvesting and insider reconnaissance.

## How It Works

### Step 1: Enumerate Slack Workspaces
Read the workspace metadata file to identify all registered workspaces and their URLs.

**Windows path:**
```
%AppData%\Roaming\Slack\storage\slack-workspaces
```
**macOS path:**
```
~/Library/Application Support/Slack/storage/slack-workspaces
```

### Step 2: Extract Download History (Reconnaissance)
The `slack-downloads` file reveals what files the user has downloaded — useful for understanding what sensitive data they handle.

```
Slack/storage/slack-downloads
```

### Step 3: Steal Authentication Cookie (T1539)
The `Slack/Cookies` file is an unencrypted SQLite database containing the `d` cookie — the primary authentication token for the Slack API.

```
~/Library/Application Support/Slack/Cookies   (macOS)
%AppData%\Roaming\Slack\Cookies               (Windows)
```

Extract with:
```bash
sqlite3 Cookies "SELECT host_key, name, value FROM cookies WHERE name='d';"
```

The stolen cookie can then be used to authenticate as the victim — no password or MFA required.

### Step 4: MFA Bypass
Because authentication is done via the local cookie (not a fresh login), MFA is never prompted. Even if MFA is enforced on the account, cookie-based session hijacking sidesteps it entirely.

**Exception:** Workspaces with ADFS/SSO integration that enforce re-authentication will require a fresh credential challenge.

### Step 5: Post-Compromise Cleanup
To avoid detection, attackers should delete `root-state.json` which logs session state, and avoid clicking unread messages or leaving search queries that other admins can see.

```
Slack/storage/root-state.json   ← delete post-exploitation
```

---

## Technical Reference

### File Paths & Artifacts

#### macOS
```
~/Library/Application Support/Slack/storage/slack-workspaces   # Workspace metadata (team names, URLs, IDs)
~/Library/Application Support/Slack/storage/slack-downloads    # User download history
~/Library/Application Support/Slack/Cookies                    # SQLite DB — contains auth cookie (plaintext)
~/Library/Application Support/Slack/storage/root-state.json    # Session state — deleted by attacker post-exploitation
```

#### Windows
```
%AppData%\Roaming\Slack\storage\slack-workspaces
%AppData%\Roaming\Slack\storage\slack-downloads
%AppData%\Roaming\Slack\Cookies
%AppData%\Roaming\Slack\storage\root-state.json
```

### Key File Breakdown

#### `Cookies` (SQLite database)
- Contains the `d` cookie — Slack's primary authentication token
- Stored in plaintext; no encryption applied by Slack
- Can be read directly with `sqlite3` or any SQLite-capable library
- Single cookie grants full access to all workspaces the user is enrolled in

**Extraction command:**
```bash
sqlite3 ~/Library/Application\ Support/Slack/Cookies \
  "SELECT host_key, name, value FROM cookies WHERE name='d';"
```

**Cookie usage:**
```bash
# Use the extracted 'd' cookie value to make authenticated Slack API calls
curl -s https://slack.com/api/auth.test \
  -H "Cookie: d=<stolen_cookie_value>"
```

#### `slack-workspaces` / `slack-teams`
- JSON file listing all workspaces the user is enrolled in
- Contains: team name, team ID, workspace URL, user ID
- Allows attacker to enumerate all accessible workspaces before pivoting

**Sample structure:**
```json
{
  "teams": {
    "T00000000": {
      "name": "Acme Corp",
      "id": "T00000000",
      "url": "https://acmecorp.slack.com",
      "userId": "U00000000"
    }
  }
}
```

#### `slack-downloads`
- Records every file downloaded through the Slack client
- Contains: filename, download URL, local save path, timestamp
- Used by attacker for reconnaissance — reveals what sensitive files the user handles

#### `root-state.json`
- Tracks local session state
- Deleted by attacker post-exploitation to reduce forensic footprint
- Deletion is itself a detectable artifact (file deletion event on a normally persistent file)

### Relevant Slack API Endpoints
```
https://slack.com/api/auth.test          # Verify stolen cookie validity + get user info
https://slack.com/api/conversations.list # Enumerate accessible channels
https://slack.com/api/conversations.history # Read channel messages
https://slack.com/api/files.list         # Enumerate shared files
https://slack.com/api/users.list         # Enumerate workspace members
https://slack.com/api/search.messages    # Search messages (leaves audit trail)
```

### Attack Prerequisites
- **Minimum access required:** Read access to the victim user's home directory
  - Achievable via: initial access malware, local privilege escalation, lateral movement, insider threat
- **Platform:** Works on both Windows and macOS without modification
- **Slack plan:** Works against all Slack plan tiers; SSO/ADFS is the only meaningful mitigation

### MFA Bypass Mechanism
- The `d` cookie is set after the user completes authentication (including MFA)
- Using the pre-authenticated cookie skips the login flow entirely — Slack does not re-challenge for MFA
- The session is treated as already authenticated
- **Exception:** Workspaces enforcing ADFS/SSO with mandatory re-authentication will prompt for fresh credentials

### Attacker Stealth Considerations
- **Avoid clicking unread messages** — marks them as read, visible to other users and admins
- **Clear search history** — Slack search queries are visible to workspace admins
- **Delete `root-state.json`** — reduces local forensic footprint
- **Do not trigger notifications** — avoid actions that send notifications to the victim account
- Accessing Slack via API rather than the desktop client reduces UI-side visibility

### Vendor Response
- SpecterOps disclosed this to Slack prior to publication
- Slack declined to encrypt the local cookie store, reasoning that an attacker with local access "already has sufficient access"
- As of disclosure (2020), the `Cookies` file remains unencrypted
- This is a known design decision, not an unpatched vulnerability

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Steal Web Session Cookie | T1539 | Extracting the `d` cookie from the Slack/Cookies SQLite database |
| Credentials from Password Stores | T1555 | Local Slack client directory as credential store |
| Data from Information Repositories: Code Repositories | T1213.003 | Accessing Slack channels and files via stolen cookie |
| File and Directory Discovery | T1083 | Enumerating `slack-workspaces`, `slack-downloads` files |

---

## Detection Opportunities

### Key Log Sources
- File integrity monitoring / SACLs on Slack client directory
- Slack audit logs (Standard, Plus, or Enterprise Grid plans required)
- EDR file access telemetry — reads to `Slack/Cookies` by non-Slack processes
- Network/proxy logs — unexpected Slack API calls from new IPs or user agents

### Behavioral Indicators
- Process other than `Slack.exe` / `Slack` reading `Slack/Cookies` or `slack-workspaces`
- Concurrent active Slack sessions from geographically distinct IPs
- Slack login without a corresponding password change or MFA event
- Deletion of `Slack/storage/root-state.json`
- Unusual Slack API calls (bulk message reads, workspace enumeration, file downloads)
- `sqlite3` or similar DB tool accessing Slack's application support directory

### Artifacts Left Behind
- Access timestamp on `Slack/Cookies` updated by non-Slack process
- `root-state.json` deleted or overwritten
- Slack audit log showing new login from unexpected IP/device

---

## Query Stubs

### CrowdStrike FQL
```fql
// Non-Slack process accessing Slack Cookies file
event_simpleName=FileOpenInfo
| FilePath=*/Slack/Cookies
| NOT ImageFileName IN ("*/Slack.app/*", "*/Slack/*")

// sqlite3 accessing application support directories
event_simpleName=ProcessRollup2
| ImageFileName=*/sqlite3
| CommandLine=*Slack*
```

### Databricks SQL / Sysmon
```sql
-- File access to Slack cookie store by unexpected processes
SELECT timestamp, device_id, process_name, file_path, user
FROM file_events
WHERE file_path LIKE '%Slack/Cookies%'
  AND process_name NOT LIKE '%Slack%'
ORDER BY timestamp DESC
```

---

## Tools Reference

| Tool | Usage |
|---|---|
| `sqlite3` | Native CLI tool to query the `Cookies` SQLite DB |
| Python `sqlite3` module | Scripted extraction in post-exploitation frameworks |
| `curl` / `requests` | Make authenticated Slack API calls with stolen `d` cookie |
| Any file read primitive | Reading `slack-workspaces`, `slack-downloads` (plaintext JSON) |

---

## Threat Actor Usage
No specific named threat actor usage documented in source, but this technique is applicable to:
- Post-compromise lateral movement after initial endpoint access
- Insider threat scenarios
- Red team operations targeting organizations that use Slack heavily

---

## References
- [SpecterOps: Abusing Slack for Offensive Operations (2020)](https://specterops.io/blog/2020/03/04/abusing-slack-for-offensive-operations/)

## Related Notes
- [[macOS Info Stealer - Data Targeted]]
- [[20 - Areas/Threat Hunting/Hunt - Slack Cookie Theft and Session Hijacking]] — active hunt hypothesis derived from this TTP
- [[30 - Knowledge/Cybersecurity/Tools & Platforms/Cobalt Strike]]
- [[20 - Areas/Threat Hunting/Threat Hunt]]
- [[40 - Resources/Query Library/Hunt Queries]]
