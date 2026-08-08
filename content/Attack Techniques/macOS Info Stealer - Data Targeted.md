---
title: macOS Info Stealer - Data Targeted
date: 2026-03-07
type: ttp
mitre_id: T1555.003, T1005, T1115, T1552.004, T1056.002
mitre_tactic: Credential Access, Collection
threat_actors: [DazzleSpy, KeySteal, Pureland, XLoader, CrateDepression/Poseidon, OSX.Zuru]
tools_used: [security CLI, NSPasteboard, shutil.copytree, osascript]
platforms: [macOS]
tags:
  - type/ttp
  - status/active
  - platform/macos
  - category/infostealer
source:
  url: https://www.sentinelone.com/blog/session-cookies-keychains-ssh-keys-and-more-7-kinds-of-data-malware-steals-from-macos-users/
  author: Phil Stokes (SentinelOne)
  date: 2023
---

## Summary
macOS info stealers consistently target seven categories of sensitive data: session cookies, login keychain, user passwords, browser credentials, SSH keys, system environment info, and pasteboard contents. As macOS adoption in enterprise environments increased, attackers shifted focus from ransomware toward credential and session theft — enabling persistent, stealthy access via stolen tokens that bypass MFA.

## How It Works

### 1. Session Cookies (T1539)
- Stolen from `~/Library/Cookies/*.binarycookies` and app-specific locations
- Allows attackers to impersonate authenticated sessions without credentials
- Real-world example: CircleCI breach — attacker used stolen session cookies to access production systems

**Key paths:**
```
~/Library/Cookies/*.binarycookies
~/Library/Application Support/Google/Chrome/Default/Cookies
~/Library/Application Support/Slack/Cookies
~/Library/Application Support/zoom.us/data/zoomus.enc.db
```

### 2. Login Keychain (T1555.001)
- Targets `.keychain` and `.keychain-db` files
- KeySteal malware uses 3DES encryption on exfiltrated keychain files
- Native `security` CLI tool used to query keychain contents when Full Disk Access is available

**Key paths:**
```
/Library/Keychains/
~/Library/Keychains/login.keychain-db
```

### 3. User Login Passwords (T1056.002)
- Password spoofing via fake `osascript` dialog prompts (social engineering)
- Keyloggers capture credentials during normal authentication
- Pureland stealer captures passwords via custom dialog alerts

### 4. Browser Passwords & Data (T1555.003)
- Chrome, Firefox, and other browsers store credentials in SQLite DBs
- Targeted alongside cookies, history, and search records
- XLoader and Pureland both harvest Chrome data

**Key paths:**
```
~/Library/Application Support/Google/Chrome/Default/Login Data
~/Library/Application Support/Firefox/Profiles/*/logins.json
```

### 5. SSH Keys (T1552.004)
- Entire `~/.ssh/` directory recursively copied via `shutil.copytree()` (OSX.Zuru)
- CrateDepression/Poseidon supply chain attack also exfiltrates SSH and AWS keys
- Enables lateral movement to servers and cloud infrastructure

**Key paths:**
```
~/.ssh/id_rsa
~/.ssh/id_ed25519
~/.aws/credentials
```

### 6. System Environment Reconnaissance (T1082)
- Serial numbers, hardware UUIDs, macOS version, username, WiFi SSID
- DazzleSpy performs detailed fingerprinting before payload execution
- Used for selective delivery — payloads only execute in target environments

### 7. Pasteboard / Clipboard (T1115)
- Accessed via `NSPasteboard` API or command-line utilities
- XLoader harvests clipboard alongside browser data
- Can capture sensitive data mid-copy (passwords, crypto keys, MFA codes)

---

## Detection Opportunities

### Key Log Sources
- Unified Log (macOS `log stream`) — process access to sensitive paths
- EDR telemetry (SentinelOne, CrowdStrike) — file access events under `~/Library/`
- Full Disk Access (FDA) grants — unexpected processes with FDA
- `security` CLI invocations outside of expected admin activity

### Behavioral Indicators
- Process (non-browser) accessing `~/Library/Cookies/` or `~/Library/Keychains/`
- `security` command-line tool executed by non-root, non-admin processes
- `osascript` spawning dialog prompts requesting passwords
- Process recursively reading or archiving `~/.ssh/`
- Unusual `NSPasteboard` API calls from unsigned or ad-hoc signed binaries
- Unexpected outbound network connections following file access patterns

### Artifacts Left Behind
- Staged archive files (`.zip`, `.tar`) in `/tmp/` or `~/Library/Caches/`
- Launch Agent plist in `~/Library/LaunchAgents/` for persistence
- Dropped Python scripts or shell scripts in world-writable directories
- Unsigned or ad-hoc signed Mach-O binaries in `~/Downloads/` or `/tmp/`

---

## Query Stubs

### CrowdStrike FQL
```fql
// Processes reading keychain files outside expected apps
event_simpleName=FileOpenInfo
| FilePath=/Users/*/Library/Keychains/*
| NOT ImageFileName IN ("/usr/bin/security", "/System/Library/CoreServices/*")

// osascript password dialog abuse
event_simpleName=ProcessRollup2
| ImageFileName=/usr/bin/osascript
| CommandLine=*password* OR CommandLine=*keychain*
```

### Databricks SQL / Sysmon
```sql
-- SSH directory access by non-SSH processes
SELECT timestamp, process_name, file_path, user
FROM file_events
WHERE file_path LIKE '%/.ssh/%'
  AND process_name NOT IN ('ssh', 'scp', 'sftp', 'ssh-agent')
ORDER BY timestamp DESC
```

---

## Threat Actor Usage
| Malware | TTPs Used | Notes |
|---|---|---|
| DazzleSpy | T1082, T1005 | Fingerprints target before payload delivery |
| KeySteal | T1555.001 | Targets `.keychain-db`, uses 3DES on exfil |
| Pureland | T1056.002, T1555.003 | Dialog spoofing + Chrome/Zoom harvesting |
| XLoader | T1115, T1555.003 | Clipboard and browser credential theft |
| OSX.Zuru | T1552.004 | Python-based SSH key exfiltration |
| CrateDepression / Poseidon | T1552.004, T1195 | Supply chain, SSH + AWS key exfil |

---

## References
- [Phil Stokes - SentinelOne: Session Cookies, Keychains, SSH Keys & More](https://www.sentinelone.com/blog/session-cookies-keychains-ssh-keys-and-more-7-kinds-of-data-malware-steals-from-macos-users/)
- [CircleCI Official Incident Report – Jan. 13, 2023](https://circleci.com/blog/jan-4-2023-incident-report/) — Primary post-mortem; infostealer on engineer laptop stole 2FA-backed SSO session cookie, attacker exfiltrated customer env vars, tokens, and encryption keys from production DBs
- [BleepingComputer: CircleCI's hack caused by malware stealing engineer's 2FA-backed session](https://www.bleepingcomputer.com/news/security/circlecis-hack-caused-by-malware-stealing-engineers-2fa-backed-session/)
- [Help Net Security: CircleCI breach post-mortem — Attackers got in by stealing engineer's session cookie](https://www.helpnetsecurity.com/2023/01/16/circleci-breach/)
- [Infosecurity Magazine: CircleCI Confirms Data Breach Was Caused By Infostealer on Employee Laptop](https://www.infosecurity-magazine.com/news/circleci-breach-caused-by/)

## Related Notes
- [[Abusing Slack for Offensive Operations]]
- [[DFIR & Forensics/Forensics/Mac Forensics]]
- [[40 - Resources/Query Library/Hunt Queries]]
