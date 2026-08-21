# macOS Forensic Investigation

**Research Framework & Artifact Reference Guide**

*A structured reference for cybersecurity investigators conducting digital forensic analysis on Apple macOS systems*

Version 1.9 | May 2026

## Table of Contents

- 1. Introduction & Scope

- 2. Investigative Framework Overview

- 3. Phase 1 — Evidence Preservation & Acquisition

- 4. Phase 2 — User Activity & Behavioral Artifacts

- 5. Phase 3 — File System & Storage Artifacts

- 6. Phase 4 — Network & Communications Artifacts

- 7. Phase 5 — System & Security Artifacts

- 8. Phase 6 — Cloud & iCloud Artifacts

- 9. Tooling Reference

- 10. Database Query Reference

- 11. Legal Considerations & Chain of Custody

- 12. Quick Reference Card

- Appendix A — macOS 26 (Tahoe) Forensic Changes

- Appendix B — BTM Attribution Compare Script

- Appendix C — Shell History & SSH Artifacts

- Appendix D — Live Response Collection Reference

## 1. Introduction & Scope

This framework provides a structured methodology for conducting digital forensic investigations on macOS systems. It is designed for use by cybersecurity investigators, incident responders, legal professionals, and forensic analysts working in lawful investigative contexts including corporate security incidents, law enforcement investigations, and regulatory compliance reviews.

macOS presents a uniquely rich forensic surface due to Apple's tightly integrated ecosystem. Unlike Windows or Linux environments, macOS artifacts often span multiple interrelated SQLite databases, binary plist files, unified logs, and Apple-proprietary formats — many of which are undocumented or only partially reverse-engineered by the research community.

### 1.1 Scope of This Document

- Coverage of macOS 10.15 (Catalina) through macOS 26 (Tahoe)

- Focus on artifacts stored in local databases, plists, and log files

- Inclusion of cloud-connected artifacts (iCloud, iMessage, FaceTime)

- Tooling guidance for both commercial and open-source solutions

- Legal and chain-of-custody considerations

### 1.2 What This Framework Does Not Cover

- Live memory forensics (RAM acquisition)

- iOS/iPadOS device forensics (separate discipline)

- Network packet capture or traffic analysis

- Malware reverse engineering

## 2. Investigative Framework Overview

The framework is organized into six sequential phases. Each phase builds on the previous, and investigators should generally follow this order to preserve evidence integrity and avoid inadvertent modification of artifacts.

| Phase | Focus Area | Key Goal | Priority |
|----|----|----|----|
| 1 | Evidence Preservation & Acquisition | Create forensic copy without modifying source | Critical |
| 2 | User Activity & Behavior | Establish timeline of user actions | High |
| 3 | File System & Storage | Identify file access, deletion, and transfers | High |
| 4 | Network & Communications | Map network activity and communications | High |
| 5 | System & Security | Detect persistence, privilege escalation, policy violations | Medium |
| 6 | Cloud & iCloud | Recover synced data and off-device activity | Medium |

### 2.1 Guiding Principles

- **Order of Volatility:** Always acquire the most volatile evidence first (RAM > swap > running processes > logs > disk).

- **Write Protection:** Never mount a suspect drive without hardware or software write blockers in place.

- **Hashing:** Compute MD5 and SHA-256 hashes of all acquired images immediately and record them in your case notes.

- **Documentation:** Photograph physical evidence, record serial numbers, and maintain timestamped case logs throughout.

- **Minimise Footprint:** Use read-only tools and avoid running analysis software on the suspect system itself wherever possible.

## 3. Phase 1 — Evidence Preservation & Acquisition

### 3.1 Pre-Acquisition Checklist

- Obtain proper legal authority (warrant, consent, corporate policy authorization)

- Photograph the system in situ before touching anything

- Note the system state: on/off, screen content, connected peripherals, network status

- If the system is on and you have authorisation, consider live acquisition before shutdown

- Prepare write-blocked external storage with sufficient capacity (at least 2x source drive size)

### 3.2 macOS-Specific Acquisition Considerations

#### 3.2.1 Apple Silicon (M-Series) Devices

Apple Silicon Macs use a Secure Enclave and T2/Apple Silicon security architecture that significantly complicates traditional imaging approaches. Key considerations:

- Target Disk Mode is replaced by Sharing Mode on Apple Silicon; it does not present a raw block device

- FileVault 2 encryption is always active and tied to the Secure Enclave; decryption requires valid credentials or a recovery key

- Some APFS volumes may be cryptographically sealed and cannot be read without booting into macOS

- Apple Configurator 2 or DFU restore mode may be required for locked or unresponsive devices

- macOS 26 (Tahoe) is the last version to support Intel Macs — from macOS 27 onward, all supported hardware is Apple Silicon

#### 3.2.2 Intel-Based Macs

Intel Macs offer more traditional acquisition paths, though FileVault 2 remains a significant consideration:

- Target Disk Mode presents the drive as a block device via Thunderbolt or FireWire

- Boot to macOS Recovery to disable SIP (System Integrity Protection) if required for acquisition

- T2 chip-equipped Intel Macs share some of the same acquisition complications as Apple Silicon

### 3.3 APFS Volume Structure

Modern macOS systems use the Apple File System (APFS). Understanding its structure is essential for forensic acquisition:

| Volume Role | Mount Point | Forensic Relevance |
|----|----|----|
| System | / | OS files; read-only, cryptographically sealed on Apple Silicon |
| Data | /System/Volumes/Data | User data, applications, preferences — primary evidence location |
| Preboot | (internal) | Boot assets; useful for identifying OS version and boot history; contains Recovery account info on Apple Silicon |
| Recovery | (internal) | Recovery environment; may contain evidence of recovery/wiping attempts |
| VM | (internal) | Swap files; potentially contains memory artifacts |

### 3.4 Acquisition Tools

- **dd / dcfldd:** Command-line disk imaging. Use with write blocker. Supports hashing during imaging.

- **FTK Imager (Exterro):** GUI-based imaging supporting E01, AFF, raw formats. Windows-based but widely used.

- **Recon Imager:** macOS-native acquisition tool; supports APFS and Apple Silicon natively.

- **mac_apt:** Open-source Python toolkit; can operate on mounted images or live systems in read-only mode.

## 4. Phase 2 — User Activity & Behavioral Artifacts

This phase focuses on reconstructing what the user did on the system — applications launched, files accessed, web browsing, and general activity patterns. These artifacts are among the most forensically valuable for establishing timelines.

### 4.1 KnowledgeC Database

KnowledgeC is arguably the most valuable single artifact on modern macOS systems. It is managed by the CoreDuet daemon and records a rich history of user and system activity.

| Detail        | Value                                             |
|-------------------|-------------------------------------------------------|
| Location (system) | /private/var/db/CoreDuet/Knowledge/knowledgeC.db      |
| Location (user)   | ~/Library/Application Support/Knowledge/knowledgeC.db |
| Format            | SQLite database                                       |
| macOS Version     | 10.14 (Mojave) and later                              |
| Key Tables        | ZOBJECT, ZSTRUCTUREDMETADATA, ZSOURCE                 |

> **Live acquisition note:** the system-level path (`/private/var/db/CoreDuet/Knowledge/`) is SIP-protected. Per [UAC](https://github.com/tclahr/uac)'s collector definition, this path is only collectible on a live system if System Integrity Protection is disabled; on a SIP-enabled live system, plan to collect the user-level path instead, or acquire the system path via a forensic image/offline mount rather than live collection. The same SIP caveat applies to Biome's system-level path (4.2) and Powerlog (4.11).

#### 4.1.1 What KnowledgeC Records

- Application launch and termination events with timestamps

- Device lock and unlock events

- Battery charge/discharge events (useful for establishing physical presence)

- Safari and third-party browser activity

- Audio and media playback events

- Location data (if Location Services enabled)

- Notification delivery and interaction

- Screen time and app usage statistics

#### 4.1.2 Key SQLite Query — Application Usage Timeline

**KNOWLEDGEC.DB — APP USAGE TIMELINE**

```sql
SELECT datetime(ZSTARTDATE + 978307200, 'unixepoch', 'localtime') AS start_time,
datetime(ZENDDATE + 978307200, 'unixepoch', 'localtime') AS end_time,
ZBUNDLEID AS app,
ZDEVICEID AS device
FROM ZOBJECT
WHERE ZSTREAMNAME = '/app/usage'
ORDER BY ZSTARTDATE DESC;
```

### 4.2 Biome Framework

Introduced alongside KnowledgeC enhancements in macOS 12+, Biome stores structured data about user and system activity in a proprietary binary format. It extends and in some cases supersedes KnowledgeC data.

| Detail | Value |
|----|----|
| System location | /private/var/db/biome/streams/ |
| User location | ~/Library/Biome/streams/restricted/*/local |
| Format | Protobuf binary (requires specialised parsing) |
| macOS Version | 12 (Monterey) and later |
| Key Streams | AppInstall, AppUsage, TextInput, UserNotification, Spotlight |

> **Both Biome paths are forensically relevant**
>
> The system path (/private/var/db/biome/) is collected by most forensic tools and contains system-level behavioral data. The user-home path (~/Library/Biome/streams/restricted/) contains per-user restricted streams and is the path collected by UAC. Acquire both paths — they are complementary halves of the Biome dataset.

Parsing biome data requires tools such as biome_parser or Cellebrite Advanced Services. The streams of highest forensic interest include AppInstall (application installation history) and UserNotification (notification content and timestamps).

### 4.3 IntelligencePlatform Database — views.db

Introduced silently in macOS 14 (Sonoma) as infrastructure for what became Apple Intelligence in macOS 15.1, the IntelligencePlatform folder and its databases are present on all Macs running macOS 14 or later — regardless of whether Apple Intelligence is enabled or whether the hardware supports it. This makes it a universally relevant artifact across modern Mac investigations.

| Detail | Value |
|----|----|
| Path | ~/Library/IntelligencePlatform/Artifacts/internal/views.db |
| Format | SQLite database |
| macOS Version | 14 (Sonoma) and later — present on all hardware including Intel |
| Apple Intelligence required? | No — folder and database present even on unsupported devices |
| Tool support | mac_apt WIFI_INTELLIGENCE plugin; Velociraptor artifact (submitted to Artifact Exchange) |
| Attribution | Yogesh Khatri — swiftforensics.com (January 2025) |

#### 4.3.1 wifiContextEvents — WiFi Connection History

Empirical analysis confirms that wifiContextEvents stores WiFi network identity as a plaintext prefixed string inside the behaviorIdentifier field. The format is Connect:SSID or Disconnect:SSID — the SSID is directly human-readable. The behaviorType field is 10 for all WiFi events regardless of direction; the Connect/Disconnect prefix encodes directionality, not the integer type code.

| Column | Type | Confirmed Meaning |
|----|----|----|
| behaviorType | INTEGER NOT NULL | Always 10 for WiFi events — does not distinguish connect from disconnect |
| behaviorIdentifier | TEXT NOT NULL | Plaintext prefixed SSID — format: Connect:<SSID> or Disconnect:<SSID>. The network name is directly readable |
| timestamp | REAL NOT NULL | Apple/Cocoa epoch (seconds since 2001-01-01). Add 978307200 to convert to Unix epoch |
| timeSincePreviousEvent | REAL | Seconds elapsed since the preceding event for this network — enables dwell time calculation between connect/disconnect pairs |

Example rows (from empirical testing): behaviorType=10, behaviorIdentifier='Connect:WutangLAN', timestamp=<Apple epoch>. The SSID is stored verbatim with no encoding or hashing, making this table immediately readable without any decoding step.

#### 4.3.2 Retention Characteristics

The wifiContextEvents table is periodically emptied by the system. In practice, events typically cover the current month plus a small number of prior months. This has two important implications for investigations: first, acquire and preserve this database early — it will shrink over time as older events are purged. Second, absence of older WiFi events does not indicate the table has been tampered with; rolling retention is normal system behaviour.

#### 4.3.3 Forensic Significance

- SSID in plaintext — unlike most system WiFi artifacts, the network name is stored verbatim and is immediately readable without any decoding, making this one of the most accessible location-corroborating artifacts on macOS 14+

- Network placement history — corroborates or challenges alibi claims by showing exactly which WiFi networks the device connected to and disconnected from, with precise timestamps, even after those networks are removed from system preferences

- Survives system WiFi history clearing — stored in the IntelligencePlatform database independently of System Preferences network history; clearing the standard Known Networks list does not purge wifiContextEvents

- Dwell time reconstruction — each Connect/Disconnect pair allows calculation of precisely how long the device was at a given location; timeSincePreviousEvent cross-validates these windows

- Cross-reference with other artifacts — timestamps align with the Apple epoch used in KnowledgeC.db and can be correlated against QuarantineEvents downloads, Unified Logs, and geo context tables in the same database

**VIEWS.DB — WIFICONTEXTEVENTS QUERIES**

```sql
-- Full WiFi event history
SELECT
datetime(timestamp + 978307200, 'unixepoch', 'localtime') AS event_time,
SUBSTR(behaviorIdentifier, INSTR(behaviorIdentifier,':')+1) AS ssid,
CASE WHEN behaviorIdentifier LIKE 'Connect:%'
THEN 'Connect' ELSE 'Disconnect' END AS event_type,
ROUND(timeSincePreviousEvent / 60.0, 1) AS mins_since_prev
FROM wifiContextEvents
ORDER BY timestamp DESC;
-- Networks seen — frequency and date range per SSID
SELECT
SUBSTR(behaviorIdentifier, INSTR(behaviorIdentifier,':')+1) AS ssid,
COUNT(*) AS total_events,
SUM(CASE WHEN behaviorIdentifier LIKE 'Connect:%' THEN 1 ELSE 0 END) AS connects,
datetime(MIN(timestamp) + 978307200, 'unixepoch', 'localtime') AS first_seen,
datetime(MAX(timestamp) + 978307200, 'unixepoch', 'localtime') AS last_seen
FROM wifiContextEvents
GROUP BY ssid
ORDER BY total_events DESC;
```

#### 4.3.4 Geo Context Tables — Status on ARM64/macOS 15

> **Research Note — Corrected Finding (v1.8)**
>
> Earlier versions of this document stated geo context tables are empty on Intel Mac hardware. The test device is ARM64 (Apple Silicon) running macOS 15 (Sequoia). These tables are empty on the test device. The current working hypothesis is that population requires Location Services to be enabled and configured for Apple Intelligence features — this is a settings/permissions question, not a hardware limitation. Investigation ongoing.

The views.db schema includes three additional context event tables that share the identical four-column structure as wifiContextEvents:

| Table | Precision | Expected behaviorIdentifier format | ARM64/macOS 15 populated? |
|----|----|----|----|
| coarseGeoHashContextEvents | ~1km (city-block) | Geohash string — short prefix (4-5 chars) | Not confirmed — see note above |
| specificGeoHashContextEvents | ~10–100m (building) | Geohash string — longer prefix (7-9 chars) | Not confirmed — see note above |
| loiContextEvents | Inferred location | LOI identifier — encoding TBD | Not confirmed — see note above |
| loiEntityInteractionEvents | Inferred location | Person entity interaction at a specific LOI | Not confirmed — see note above |

#### 4.3.5 Investigation Notes

- The IntelligencePlatform folder contains a large ecosystem of databases beyond views.db — confirmed inventory includes: behaviors.db (master behavioral event log — empty on ARM64/macOS 15 despite fully-built schema), graph.db (ML knowledge graph with embeddings), globalKnowledge.db (live and static knowledge graphs), and Artifacts/siri/remembers/view.db (Siri interaction donation log — not an explicit memory store)

- wifiContextEvents SSID is stored in plaintext and requires no decoding — one of the most immediately accessible location artifacts on macOS 14+

- photosObservedAges table is populated on ARM64/macOS 15 with observedAge=3 (likely adult enum value) — populated regardless of Apple Intelligence feature enablement status

- entity_alias contains Contacts parsed into name components (first_provided_alias, full_provided_alias, family_provided_alias, me_alias) with confirmation_confidence=1.0

- The full scope of the IntelligencePlatform ecosystem is still being characterised by the forensic community — document table row counts and schema during every acquisition to support future analysis

### 4.4 Spotlight Metadata & Database

Spotlight indexes file metadata across the system. Even after a file is deleted, Spotlight indexes may retain evidence of its existence.

- Volume-level store: `/.Spotlight-V100/Store-V2/<UUID>/store.db` (and a hidden `.store.db` variant at the same location; keyed by volume UUID)

- User-level store, by macOS version:
  - **10.13 – 11:** `~/Library/Metadata/CoreSpotlight/index.spotlightV3/`
  - **12+ (through at least Sonoma; expected to still apply on Tahoe, unverified):**
    - `~/Library/Metadata/CoreSpotlight/NSFileProtectionComplete/index.spotlightV3/`
    - `~/Library/Metadata/CoreSpotlight/NSFileProtectionCompleteUnlessOpen/index.spotlightV3/`
    - `~/Library/Metadata/CoreSpotlight/NSFileProtectionCompleteUntilFirstUserAuthentication/index.spotlightV3/`
    - Cache variants also exist under `~/Library/Caches/com.apple.helpd/NSFileProtection*/index.spotlightV3/`
  - Files under `NSFileProtectionCompleteUnlessOpen`/`NSFileProtectionCompleteUntilFirstUserAuthentication` are expected to be **encrypted at rest** (Data Protection class) — plan for a live/decrypted extraction rather than an offline read of these specific paths

- Auxiliary files: `store.db` requires accompanying `dbStr-*.map.data` files present in the same folder to parse correctly — extract the whole containing folder, not just `store.db` in isolation

- Format: binary proprietary, block-based storage. Header signature `7tsd` (0x37 0x74 0x73 0x64) or `8tsd` (0x38 0x74 0x73 0x64) depending on version; internal block signatures `1mbd`/`2mbd` (block 0) and `2pbd` (data blocks). Verify signature before selecting a parser.

- Contains: file names, content snippets, metadata, application associations, timestamps

- Useful for: proving a file existed even after deletion, identifying user searches

- Parser: [mac_apt](https://github.com/ydkhatri/mac_apt) (`plugins/spotlight.py`, `plugins/helpers/spotlight_parser.py`) — paths, version scoping, and format signatures above verified directly against plugin source (`spotlight.py` docstring + `spotlight_parser.py` signature checks) on 2026-08-21, not independently confirmed against a live Tahoe system. See also: [mac_apt wiki — Search and Indexing](https://deepwiki.com/ydkhatri/mac_apt/5.4-search-and-indexing)

Use mdls <filename> to inspect all Spotlight-indexed metadata for a specific file, or mdimport -t -d2 <filename> to see what the mdimporter for that file type would extract. Note: mdimport has been known to crash on macOS Sonoma and later — mdls is the more reliable option for field use.

### 4.5 Recent Items & Launch Services

#### 4.5.1 Recent Applications, Documents & Servers

Stored in: ~/Library/Application Support/com.apple.sharedfilelist/

These SFL2 (Shared File List) binary files record recently accessed applications, documents, and servers. They can be parsed with tools such as sflparser or mac_apt's RECENTFILES plugin.

Additional named MRU-bearing plists (recent searches/places, sidebar favorites) live alongside the above under `~/Library/Preferences/`: `com.apple.finder.plist`, `com.apple.recentitems.plist`, `com.apple.sidebarlists.plist`, and `*.LSSharedFileList.plist` — source: [UAC](https://github.com/tclahr/uac) `artifacts/files/system/macos_mru.yaml`, 2026-08-21, unverified against a live system.

#### 4.5.2 Dock Plist

Location: ~/Library/Preferences/com.apple.dock.plist

Records pinned applications and recently used apps. Modifications to this file may indicate installed applications that have since been removed.

#### 4.5.3 Spotlight Shortcuts

Records terms the user has searched and launched via Spotlight, with timestamps. Useful for establishing what a user was actively searching for during an incident timeframe. Stored as a plist; location has moved across macOS releases — check all of the following, most recent first:

| macOS Version | Path |
|---|---|
| ≥ 14 (Sonoma+; expected to still apply on Tahoe, unverified) | `~/Library/Group Containers/group.com.apple.spotlight/com.apple.spotlight.Shortcuts.v3` |
| 11 – 13 | `~/Library/Application Support/com.apple.spotlight/com.apple.spotlight.Shortcuts.v3` |
| 10.15 | `~/Library/Application Support/com.apple.spotlight/com.apple.spotlight.Shortcuts` |
| 10.10 – 10.14 | `~/Library/Application Support/com.apple.spotlight.Shortcuts` |
| ≤ 10.9 (Mavericks or older) | `~/Library/Preferences/com.apple.spotlight.plist` |

Note: an earlier revision of this doc listed only the 10.10–10.14 path without version-scoping it — that path is not the current one for any actively-supported macOS release. Table above sourced directly from mac_apt's `spotlightshortcuts.py` plugin (`__Plugin_ArtifactOnly_Usage` docstring and `user_plist_rel_paths` tuple), verified 2026-08-21. The ≥14 path is mac_apt's newest documented entry and has not been independently confirmed against a live Tahoe system.

Parser: [mac_apt](https://github.com/ydkhatri/mac_apt) `SPOTLIGHTSHORTCUTS` plugin (`plugins/spotlightshortcuts.py`). See also: [mac_apt wiki — Search and Indexing](https://deepwiki.com/ydkhatri/mac_apt/5.4-search-and-indexing)

### 4.6 Saved Application State

Location: ~/Library/Saved Application State/

Per-app bundles storing window state, open documents, scroll positions, and UI context from the last session. Named <bundle-id>.savedState. Useful for reconstructing exactly what a user had open in an application at the time of their last session — a complement to KnowledgeC app usage data.

#### 4.6.1 Terminal Saved State — Full Window Text Content

Terminal's saved-state bundle is a high-value special case worth breaking out separately: unlike the generic per-app state covered above, it can contain the **full text content of terminal windows** — not just window geometry/metadata.

| Detail | Value |
|----|----|
| Location | `~/Library/Saved Application State/com.apple.Terminal.savedState/` |
| Files | `windows.plist` (per-window metadata + AES key references) and `data.data` (encrypted window records) |
| Format | `data.data` records are AES-CBC encrypted per-window (key sourced from `windows.plist` via `NSWindowID` → `NSDataKey` mapping, zero IV); decrypted payload is an `NSKeyedArchiver` plist containing an `_NSWindow` object |
| Contains | Window title (`NSTitle`), working directory (`Tab Working Directory URL` / `Tab Working Directory URL String`), and full tab text content (`Tab Contents` / `Tab Contents v2`) |

- Can recover command output, pasted secrets, and full scrollback text that never touched shell history — this is a materially different (and often richer) artifact than `.bash_history`/`.zsh_history` (see Appendix C), since it captures on-screen content regardless of whether commands were logged
- Only present if the user had Terminal open with unsaved/restorable windows at the time of last quit or system state capture — absence does not mean nothing was ever run, only that no window state was captured at last close
- Parser: [mac_apt](https://github.com/ydkhatri/mac_apt) `TERMINALSTATE` plugin (`plugins/terminalstate.py`) — decryption and field layout verified directly against plugin source 2026-08-21, not independently confirmed against a live system

### 4.7 QuarantineEvents Database

This is a critical artifact for any investigation involving downloaded files or malware. Every file downloaded via a quarantine-aware application is logged here.

| Detail | Value |
|----|----|
| Location | ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 |
| Format | SQLite database |
| Key Fields | LSQuarantineTimeStamp, LSQuarantineAgentName, LSQuarantineDataURLString, LSQuarantineOriginURLString, LSQuarantineSenderName |

This database records the download URL, referring URL, application used, sender name (for email attachments), and timestamp. Records persist even after the file is deleted from the filesystem.

### 4.8 Web Browser Artifacts

#### 4.8.1 Safari

- History: ~/Library/Safari/History.db (SQLite)

- Downloads: ~/Library/Safari/Downloads.plist

- Cookies: ~/Library/Cookies/Cookies.binarycookies

- Cache: ~/Library/Caches/com.apple.Safari/

- Top Sites / Bookmarks: ~/Library/Safari/TopSites.plist, Bookmarks.plist

#### 4.8.2 Chrome

- Profile location: ~/Library/Application Support/Google/Chrome/Default/

- History: History (SQLite)

- Downloads: also within History database (downloads table)

- Cookies: Cookies (SQLite, may be encrypted)

- Cache: ~/Library/Caches/Google/Chrome/

#### 4.8.3 Firefox

- Profile location: ~/Library/Application Support/Firefox/Profiles/<profile>/

- History / Downloads: places.sqlite

- Form history: formhistory.sqlite

- Cookies: cookies.sqlite

#### 4.8.4 Other Browsers

Brave, Microsoft Edge, Opera, and Vivaldi all share the same Chromium profile path structure as Chrome under ~/Library/Application Support/<BrowserName>/. Artifact names and schema are identical to Chrome for all major forensic tables (History, Cookies, Login Data, Web Data).

### 4.9 Notification Center Database

Records the actual content of notifications shown to the user — title, subtitle, message body, source app, and delivery timestamp — not just that a notification event occurred. Distinct from (and more detailed than) the passing `UserNotification` Biome stream and BTM "Notified" flag mentioned elsewhere in this document.

Location has moved repeatedly across macOS releases; check the version-appropriate path:

| macOS Version | Path |
|---|---|
| Sequoia (15)+ (expected to still apply on Tahoe, unverified) | `~/Library/Group Containers/group.com.apple.usernoted/db2/db` |
| Yosemite – Sonoma (10.10 – 14) | `<DARWIN_USER_DIR>/com.apple.notificationcenter/db/db` (Yosemite/El Capitan/Sierra) or `<DARWIN_USER_DIR>/com.apple.notificationcenter/db2/db` (High Sierra+ — both may be present if the system was upgraded in place) |
| Mavericks (10.9) or older | `~/Library/Application Support/NotificationCenter/<UUID>.db` |

- Format: SQLite. Schema varies by version — High Sierra+ uses a `record`/`app` table pair with notification data stored as a plist blob in a `data` column (fields: `req.titl`, `req.subt`, `req.body`, `req.iden`); pre-High Sierra uses `presented_notifications`/`notifications`/`app_info` tables with an `NSKeyedArchiver`-style `$objects` array
- Screen Time notifications (`com.apple.ScreenTimeNotifications`) are stored with placeholder tokens rather than literal text and require cross-referencing against `com.apple.ScreenTimeNotifications.bundle`'s localization strings to render human-readable content
- `DARWIN_USER_DIR` is the per-user temp/cache directory (`/private/var/folders/<xx>/<yyyyyyy>/0/`) — same base directory referenced elsewhere in this document for other per-session caches
- Parser: [mac_apt](https://github.com/ydkhatri/mac_apt) `NOTIFICATIONS` plugin (`plugins/notifications.py`) — paths and schema notes verified directly against plugin source 2026-08-21, not independently confirmed against a live system

### 4.10 QuickLook Thumbnail Cache

A well-known but previously undocumented-in-this-framework artifact: macOS generates and caches a thumbnail preview for files a user has viewed (in Finder icon view, Quick Look preview, Spotlight results, etc.), and that cache can outlive the source file — recoverable visual evidence of a file's existence and appearance even after deletion. Only referenced elsewhere in this document as a bit flag (Section 5.3.1's xattr flags table, `0x00800 = quicklook`); this section covers the actual cache store.

| Detail | Value |
|----|----|
| Location (macOS < 10.15) | `<DARWIN_USER_CACHE_DIR>/com.apple.QuickLook.thumbnailcache/` |
| Location (macOS ≥ 10.15, incl. Big Sur+) | `<DARWIN_USER_CACHE_DIR>/com.apple.quicklook.ThumbnailsAgent/com.apple.QuickLook.thumbnailcache/` |
| Files | `index.sqlite` (metadata: file name, folder, hit count, last-hit timestamp, dimensions, and the byte offset/length of the thumbnail within the data file) + `thumbnails.data` (raw bitmap data, carved using the offsets from `index.sqlite`) |
| Format | SQLite index + raw bitmap blob store; carved images are BGRA or RGBA depending on OS version and must be reconstructed with the correct width (computed from `bytesperrow / (bitsperpixel/bitspercomponent)`, not a directly-stored field on newer schema versions) |

- `DARWIN_USER_CACHE_DIR` is the same per-user cache base directory referenced for Notification Center (4.9) and other per-session caches — typically `/private/var/folders/<xx>/<yyyyyyy>/0/`
- On macOS 10.15+, thumbnail records are keyed by file inode rather than a stored path — resolving inode → original file path requires cross-referencing the volume's APFS metadata (or the `Combined_Inodes` table if working from a mac_apt-processed image); a thumbnail with no resolvable inode is recovered as an "Unknown" entry, image intact but original filename lost
- `hit_count` and `last_hit_date` provide a rough proxy for how often/recently a file was viewed, independent of any modification-time-based evidence
- Because this is a **cache**, entries persist after the source file is deleted and are not necessarily cleared by normal file deletion — a materially different (and frequently missed) recovery path compared to Trash/FSEvents-based deleted-file evidence covered in Section 5.5
- Parser: [mac_apt](https://github.com/ydkhatri/mac_apt) `QUICKLOOK` plugin (`plugins/quicklook.py`) — paths, schema-version branching, and thumbnail-carving logic verified directly against plugin source 2026-08-21, not independently confirmed against a live system. Plugin author credits prior public research: [OSX-QuickLook-Parser (Mari DeGrazia)](https://github.com/mdegrazia/OSX-QuickLook-Parser), [Analysing the QuickLook Database in macOS — EasyMetadata (Dave)](http://www.easymetadata.com/2015/01/sqlite-analysing-the-quicklook-database-in-macos/)

### 4.11 Powerlog — CurrentPowerlog.PLSQL

Arguably the single richest pattern-of-life database on macOS, on par with or exceeding KnowledgeC (4.1) and Biome (4.2) in granularity — yet it was entirely absent from this document prior to this revision. Powerlog logs fine-grained per-app and per-subsystem activity primarily for power/battery accounting purposes, but as a side effect captures an extremely detailed activity timeline: app installs, launches, foreground/background transitions, screen state, battery level, network usage correlation, and dozens of other subsystem-specific event streams.

| Detail | Value |
|----|----|
| Current log | `/private/var/db/powerlog/Library/BatteryLife/CurrentPowerlog.PLSQL*` |
| Archived logs | `/private/var/db/powerlog/Library/BatteryLife/Archives/*.PLSQL.gz` — the device rotates the current log into a compressed daily archive, so a full activity timeline requires collecting **all** archive files, not just the current one |
| Format | SQLite (despite the `.PLSQL` extension — it is a standard SQLite database) |
| Table naming convention | `PL<Agent>_<EventType>_<Purpose>`, e.g. `PLAPPLICATIONAGENT_EVENTNONE_APPINFO`, `PLAPPLICATIONAGENT_EVENTFORWARD_APPLIFECYCLE`, `PLSCREENSTATEAGENT_EVENTFORWARD_SCREENSTATE` |

**Critical timestamp gotcha:** raw `TIMESTAMP` values in Powerlog tables are frequently *not* directly usable Unix epoch time. They must be corrected by adding a per-record offset (`SYSTEM` column) sourced via join against `PLSTORAGEOPERATOR_EVENTFORWARD_TIMEOFFSET` — the corrected value is `DATETIME(TIMESTAMP + SYSTEM, 'UNIXEPOCH')`. Querying `TIMESTAMP` directly without this join can produce timestamps that are off by hours, or occasionally land in the future/past relative to the true event time. This is not optional — every reference query in the public tooling for this database performs this join.

Tables of highest forensic interest (field names as observed; not exhaustive):

| Table | Captures |
|---|---|
| `PLAPPLICATIONAGENT_EVENTNONE_APPINFO` | Installed/run application catalog — `NAME`, `EXECUTABLE`, `BUNDLEID`, `VERSION`/`SHORTVERSIONSTRING`, `BUILDMACHINEOSBUILD`, `ARCHITECTURE`. The `BUILDMACHINEOSBUILD` field can indicate whether a binary was built in an environment inconsistent with a legitimate release |
| `PLAPPLICATIONAGENT_EVENTFORWARD_APPLIFECYCLE` | App launch/foreground/background/terminate events — `BUNDLEID`, `EVENT`, `PID`, `ASN` (Application Serial Number) and `PARENTASN`, letting you trace a launch chain (what spawned what) independent of standard process-tree telemetry |
| `PLSCREENSTATEAGENT_EVENTFORWARD_SCREENSTATE` | Per-app screen/display state — `APPROLE`, `DISPLAY`, `ORIENTATION`, `SCREENWEIGHT` — useful for establishing whether an app was actually visible/foregrounded to the user at a given time, not just running |
| `PLSTORAGEOPERATOR_EVENTFORWARD_ACTIVITYSTATES` | Generic activity-ID/state transitions used across multiple subsystems |
| Battery-level tables | `LEVEL`, `RAWLEVEL`, `ISCHARGING`, `FULLYCHARGED` fields — corroborating evidence for physical device state/timeline (e.g., confirming the device was actually in use, not just powered on, at a given time) |

- Because this is a SIP-relevant location, live acquisition of `/private/var/db/powerlog/` may require SIP to be disabled or Full Disk Access equivalent, similarly to the KnowledgeC system-level path (see Section 4.1 note below)
- Cross-reference against KnowledgeC (4.1) and Biome (4.2) — the three databases overlap in what they record (app usage in particular) but differ in retention window, granularity, and schema stability across OS versions; agreement across all three strengthens a finding, disagreement is itself worth investigating
- Standard tooling: [APOLLO — Apple Pattern of Life Lazy Output'er (Sarah Edwards / mac4n6.com)](https://github.com/mac4n6/APOLLO) is the de facto reference parser and query library for this database (originally developed for iOS, extended to cover macOS versions 10.13–10.16+); table names, the timestamp-offset join pattern, and field names above verified directly against APOLLO's published query modules (`powerlog_app_info_macos.txt`, `powerlog_app_lifecycle.txt`, `powerlog_app_usage.txt`, `powerlog_activity_states.txt`) 2026-08-21, not independently confirmed against a live system
- Collection path confirmed via [UAC (Unix-like Artifacts Collector)](https://github.com/tclahr/uac) `artifacts/files/system/powerlog.yaml`

### 4.12 CoreAnalytics

A lighter-weight, complementary source to Powerlog/KnowledgeC/Biome — CoreAnalytics captures system-usage and application-execution history as individual diagnostic report files rather than a queryable database.

| Detail | Value |
|----|----|
| Location | `/Library/Logs/DiagnosticReports/` |
| Files | `*.core_analytics` |

- Files in this location are also where XProtect diagnostic `.diag` files live (see 7.6.1) — when triaging `DiagnosticReports`, don't stop at the first matching pattern you're looking for; both artifact types coexist in the same directory
- Not yet independently verified what specific fields/schema each `.core_analytics` file contains beyond "system usage and application execution history" — treat as a collection target requiring hands-on schema review, not yet a fully documented artifact in this framework
- Source: [UAC](https://github.com/tclahr/uac) `artifacts/files/system/coreanalytics.yaml`, 2026-08-21, unverified against a live system

## 5. Phase 3 — File System & Storage Artifacts

### 5.1 APFS Metadata & Timestamps

APFS records four timestamps per file — Created, Modified, Changed (metadata), and Accessed. These are stored in nanosecond precision, offering high temporal resolution for timeline reconstruction. Note that macOS disables atime updates by default to improve performance; access times may therefore be unreliable on some systems.

### 5.2 File System Events (FSEvents)

| Detail | Value |
|----|----|
| Location | /.fseventsd/ (system root), /System/Volumes/*/.fseventsd/ |
| Format | Proprietary compressed binary log |
| Records | File and directory creation, modification, deletion, renaming, permission changes |
| Retention | Rolls over; older events overwritten. Typically retains days to weeks of history. |

FSEvents logs are extremely valuable for establishing file activity timelines, particularly for detecting mass file deletion or staging of data for exfiltration. Tools: fsevents_dump, mac_apt FSEVENTS plugin.

### 5.3 File Metadata — Extended Attributes & Spotlight

macOS provides a rich metadata system where file attributes can be stored separately from file data. Understanding this system is essential for both recovering investigative context and assessing evidence integrity.

#### 5.3.1 Extended Attributes (xattrs)

Extended attributes are key-value pairs attached to files and directories at the filesystem level. They are independent of file content, meaning changes to xattrs do not modify the file's data hash. This has two forensic implications: metadata can be changed without altering evidence of the file's content integrity, and xattrs can carry investigative context even when file content has been wiped.

Forensically significant xattrs include:

| xattr Name | Spotlight Name | Forensic Significance |
|----|----|----|
| com.apple.quarantine | N/A | Present on any file downloaded by a quarantine-aware app. Contains download flags, agent bundle ID, and a UUID cross-referencing QuarantineEventsV2. This is the primary mechanism by which macOS tracks downloaded file provenance. |
| com.apple.metadata:kMDItemWhereFroms | N/A | Array of URLs recording where a file was downloaded from and the referring page. Often more complete than QuarantineEvents for multi-hop downloads. |
| com.apple.metadata:kMDItemDownloadedDate | N/A | Timestamp of file download. Can differ from filesystem creation date if the file was moved after download. |
| com.apple.metadata:kMDItemComment | Comment | User or application-set comment. Persistent across iCloud Drive sync and AirDrop transfers. Searchable via Spotlight. Suitable for up to ~3,800 bytes of UTF-8 text. |
| com.apple.metadata:kMDItemKeywords | Keywords | Tag-style keywords attached to a file. Spotlight-indexed and persistent across sync. Up to ~3,800 bytes. |
| com.apple.metadata:kMDItemSubject | Subject | Subject field. Spotlight-indexed, persistent across iCloud Drive and AirDrop. |
| com.apple.lastuseddate#PS | N/A | Last time the file was opened by the user, maintained by LaunchServices independently of filesystem atime. |
| com.apple.FinderInfo | N/A | Finder flags, label colour, and icon position. Encodes whether the file's Invisible bit was set — relevant when investigating hidden files. |

Command to list all xattrs on a file:

**BASH — LIST ALL EXTENDED ATTRIBUTES**

```bash
# List xattr names
xattr -l <filename>
# Show hex + ASCII dump of a specific xattr
xattr -p com.apple.quarantine <filename>
# Show all xattrs with values (use xattred or Metamer for GUI)
xattr -l -x <filename>
```

#### 5.3.2 Finder Comments & Tags

Finder Comments are primarily stored in the hidden .DS_Store file in the same directory as the target file, with a secondary copy written as the com.apple.metadata:kMDItemFinderComment xattr. This split storage makes them fragile — a file moved between volumes may lose its Finder Comment if the .DS_Store is not preserved. For forensic purposes, check both the xattr and the .DS_Store.

Finder Tags are stored properly as a xattr (com.apple.metadata:_kMDItemUserTags) and are more reliable. Tags are preserved in iCloud Drive and via AirDrop. They are most useful for categorisation and are limited to approximately 20-25 characters of visible label text.

#### 5.3.3 Spotlight-Indexed File Metadata

Within seconds of a file being created or saved, Spotlight's indexing services extract both metadata and, where possible, content for inclusion in the volume's Spotlight index. The metadata indexed includes:

- Standard attributes: creation/modification dates, file size, kind, type

- xattr content: the three persistent xattrs (kMDItemComment, kMDItemKeywords, kMDItemSubject) are indexed and searchable via Spotlight

- Embedded metadata: EXIF data from images, PDF document properties, Office document author/title/subject fields — extracted by the specialist mdimporter for each file type

- Content tokens: text content indexed separately for full-text search

Key forensic commands:

**BASH — SPOTLIGHT METADATA QUERIES**

```bash
# List all indexed metadata for a specific file
mdls <filename>
# Show what the mdimporter would extract (may crash on Sonoma/Sequoia)
mdimport -t -d2 <filename>
# Search Spotlight for files with a specific comment
mdfind "kMDItemComment == '*confidential*'c"
# Find all files downloaded from a specific domain
mdfind "kMDItemWhereFroms == '*example.com*'c"
# Find files by download date range
mdfind "kMDItemDownloadedDate >= $time.iso(2026-01-01)"
```

> **Forensic Note — Metadata vs. File Integrity**
>
> Changing a file's xattr metadata does not alter the file's content hash (MD5/SHA-256). An adversary can modify xattrs including timestamps like kMDItemDownloadedDate without affecting the file's cryptographic integrity. Always hash file content independently of metadata. Conversely, if an xattr is present (particularly com.apple.quarantine), its presence is itself evidence — it indicates the file passed through a quarantine-aware application regardless of any subsequent modifications.

#### 5.3.4 Embedded File Metadata (EXIF, PDF, Office)

Unlike xattrs, metadata embedded within a file's data stream is changed when the file is saved. Key sources:

- EXIF (images): GPS coordinates, camera make/model, capture timestamp, lens info. Present in JPEG, TIFF, HEIC. Extract with exiftool.

- PDF metadata: Creator application, producer, creation and modification dates, author, subject. Extract with pdfinfo or exiftool.

- Office documents (docx/xlsx): Author, last modified by, revision count, creation date. Extract with exiftool or by inspecting the embedded XML directly (unzip the .docx and read docProps/core.xml).

- Discrepancy alert: if a file's embedded creation date predates the filesystem creation date, the file was likely copied from another location or the filesystem timestamps were manipulated.

### 5.4 DS_Store Files

DS_Store files are hidden binary plist files created by Finder in every directory it opens. They record which files were visible in that directory, their icon positions, view settings, and sort order at the time Finder last accessed the folder.

- Forensic value: proves directory browsing even without explicit file access events in other logs

- Location: .DS_Store in every directory opened by Finder (recursive across the volume)

- Persistence: present even after a file within the directory is deleted — the DS_Store entry for the deleted file may remain

- Tool: ds_store Python library for parsing; mac_apt has partial support

### 5.5 Trash & Deletion Artifacts

- Trash location: ~/.Trash/ — deleted files are moved here rather than immediately erased

- APFS snapshots may retain copies of files deleted from Trash (check with tmutil listlocalsnapshots /)

- APFS does not use MFT; deleted file metadata may persist in APFS metadata structures until overwritten

- Unallocated space carving may recover deleted files; tools such as PhotoRec or Scalpel can be used on raw images

### 5.6 USB & External Device Artifacts

macOS records information about connected external devices across several locations:

- System Profiler history: /Library/Preferences/com.apple.SystemProfiler.plist — records all USB devices ever connected

- Disk Arbitration logs: present in Unified Logs; search for com.apple.DiskArbitration

- Mount history: /private/var/db/diskimages-helper-persist.plist records mounted disk images

- APFS volume creation/deletion timestamps provide evidence of external drive usage

### 5.7 Document & Office File Metadata

See Section 5.3.4 for detailed coverage of embedded file metadata. Additional points:

- Creation and modification timestamps may differ from filesystem timestamps

- Template information and embedded comments in Word/Excel documents may reveal authorship or distribution chain

- For PDFs: creator application, producer, and XMP metadata

Use tools such as exiftool or pdfinfo to extract embedded metadata from document files.

### 5.8 Time Machine Artifacts

If Time Machine backups are present, they represent a goldmine of historical evidence, potentially providing the ability to reconstruct the system state at multiple points in time.

- Local snapshots: stored on the main APFS volume in a sealed subvolume; list with tmutil listlocalsnapshots /

- External backups: stored in /Volumes/<BackupDisk>/Backups.backupdb/ (HFS+) or as APFS sparse bundles

- Snapshot timestamps indicate when each backup was taken

- Deleted files may be recoverable from earlier snapshots even if no longer present on the live system

### 5.9 DocumentRevisions & Versions Store

Backs macOS's Auto Save / Versions feature (Time Machine-independent, per-file version history). A significant and under-utilized artifact: it can hold prior revisions of a file's content — including deleted files' revision data that may still exist in chunk storage even after the live file and its database record are gone.

| Detail | Value |
|----|----|
| Root location | `/System/Volumes/Data/.DocumentRevisions-V100/` (also check plain `/.DocumentRevisions-V100/` — path prefix varies with acquisition/mount mode) |
| Revision database | `.DocumentRevisions-V100/db-V1/db.sqlite` — key tables `generations` (one row per saved revision, with `generation_add_time`, `generation_path`, `generation_size`) and `files` (`file_path`, `file_inode`, `file_last_seen`) |
| Chunk metadata database | `.DocumentRevisions-V100/.cs/ChunkStoreDatabase` — key tables `CSStorageChunkListTable` (maps a revision's storage inode to an ordered list of chunk row IDs) and `CSChunkTable` (per-chunk file location, offset, length, content-hash `cid`) |
| Actual revision content | `.DocumentRevisions-V100/.cs/ChunkStorage/` — content-addressed chunk files nested 4 directory levels deep (`xx/yy/zz/<numeric-filename>`); a single revision's content may be split across multiple chunk files and must be reassembled in order |

- Extended attributes `com.apple.genstore.origdisplayname` and `com.apple.genstore.origposixname` on a generation-path entry (if it still exists on disk) recover the file's original display/POSIX name even if the parent record's path resolution fails
- QuickLook thumbnails of versioned files can themselves be stored as a revision (`generation_path` ending in `:QLThumbnailAdditionName`, format `.png` on newer systems, `.jpeg` on older) — meaning a file's visual thumbnail can be recoverable from this store independent of the QuickLook Thumbnail Cache covered in Section 4.10
- Chunks not referenced by any current `generations` row (**orphan chunks**) can still be extracted directly from `ChunkStorage` by walking the raw chunk-file format — this is the mechanism by which deleted files' version content can survive purely at the chunk level, unlinked from any live database record
- Prior public research: [Managing macOS versioning and the DocumentRevisions-V100 folder — The Eclectic Light Company](https://eclecticlight.co/2025/09/08/managing-macos-versioning-and-the-documentrevisions-v100-folder/), [File Versioning in Mac OS X — VerSprite](https://versprite.com/vs-labs/file-versioning-mac-os-x/)
- Parser: [mac_apt](https://github.com/ydkhatri/mac_apt) `DOCUMENTREVISIONS` plugin (`plugins/documentrevisions.py`) — schema, chunk-reassembly logic, and orphan-chunk extraction verified directly against plugin source 2026-08-21, not independently confirmed against a live system

## 6. Phase 4 — Network & Communications Artifacts

### 6.1 Network Configuration & History

- Known Wi-Fi networks: /Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist — includes SSID, timestamps of last connection, and sometimes geolocation data

- IntelligencePlatform wifiContextEvents: ~/Library/IntelligencePlatform/views.db — see Section 4.3.1 for full coverage

- DHCP leases: /private/var/db/dhcpclient/leases/ — records IP address assignments with timestamps

- VPN configuration: /Library/Preferences/SystemConfiguration/preferences.plist

- Hosts file modifications: /etc/hosts — check for evidence of DNS spoofing or C2 evasion

- Network app usage: /private/var/networkd/db/netusage.sqlite — per-process byte counts with timestamps

- Cellular/wireless data usage (situational — cellular-capable Macs only): /private/var/wireless/Library/Databases/DataUsage.sqlite — per-app cellular data usage, distinct from the WiFi/Ethernet-focused netusage.sqlite above (source: [UAC](https://github.com/tclahr/uac) `artifacts/files/system/network_application_usage.yaml`, 2026-08-21, unverified against a live system)

### 6.2 iMessage & SMS/MMS

| Detail | Value |
|----|----|
| Location | ~/Library/Messages/chat.db |
| Format | SQLite database |
| Key Tables | message, handle, chat, attachment, chat_message_join |
| Contains | Message content, sender/recipient identifiers, timestamps, attachment references, read receipts, reactions |

The messages database stores all iMessage and SMS/MMS content. Even deleted messages may be recoverable if the database has not been vacuumed — SQLite does not immediately overwrite deleted records. The attachment table references file paths for sent and received attachments.

### 6.3 Mail Artifacts

- Mail database: ~/Library/Mail/V9/ (version number varies with macOS version)

- Message index: ~/Library/Mail/V9/MailData/Envelope Index (SQLite)

- Raw messages: stored as .emlx files in mailbox subdirectories

- Attachments: ~/Library/Mail/V9/<account>/Attachments/

The Envelope Index database contains sender, recipient, subject, date, read status, and flags for all indexed mail. Individual .emlx files contain the full RFC 2822 message with headers, body, and base64-encoded attachments.

### 6.4 FaceTime & Phone Call History

| Detail | Value |
|----|----|
| Location | ~/Library/Application Support/CallHistoryDB/CallHistory.storedata |
| Format | Core Data (SQLite) |
| Key Table | ZCALLRECORD |
| Contains | Call direction (in/out), duration, date, origination country, service type (FaceTime Audio/Video/Phone) |

> **macOS 26 (Tahoe) Note**
>
> FaceTime received a significant backend overhaul in Tahoe. Table schemas and file locations within the CallHistoryDB bundle may have changed. Verify paths on a reference Tahoe system before applying the queries in Section 10.3. See Appendix A for full details.

### 6.5 AddressBook / Contacts

| Detail | Value |
|----|----|
| Location | ~/Library/Application Support/AddressBook/ |
| Primary database | AddressBook-v22.abcddb (SQLite) |
| Contains | Contact names, phone numbers, email addresses, organisation, notes, photos, creation/modification timestamps |

The Contacts database is cross-referenced by the IntelligencePlatform entity_alias table, which stores parsed name components (first, last, full name) mapped to internal entity identifiers. When investigating unknown identifiers in IntelligencePlatform tables, querying AddressBook is the resolution path.

### 6.6 Apple Notes

| Detail | Value |
|----|----|
| Location | ~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite |
| Format | SQLite + blob store |
| Key Table | ZICNOTEDATA (ZDATA column contains gzip-compressed protobuf note body) |
| Contains | Note creation/modification timestamps, account source (local vs iCloud), folder structure, attachments |

Note bodies require decompression and protobuf decoding to read. Tool: mac_apt NOTES plugin handles this automatically. The ZICCLOUDSYNCINGOBJECT table tracks sync status and account membership for each note.

### 6.7 AirDrop Artifacts

AirDrop uses Bluetooth LE and Wi-Fi Direct for peer-to-peer file transfer. Forensic evidence of AirDrop activity can be found in:

- Unified Logs: search for com.apple.sharingd and AirDrop process identifiers

- Received files: appear in ~/Downloads/ with AirDrop attribution in QuarantineEvents

- Bluetooth system log: /Library/Logs/DiagnosticReports/ may contain Bluetooth connection records

- Bluetooth Low Energy (BLE) device cache: `/Library/Bluetooth/com.apple.MobileBluetooth.ledevices.*` — cached records of observed BLE devices (identifiers, metadata, last-seen activity), separate from the paired-device plists (`com.apple.Bluetooth.plist`, `com.apple.MobileBluetooth.devices.plist`). Source: [UAC](https://github.com/tclahr/uac) `artifacts/files/system/bluetooth.yaml`, 2026-08-21, unverified against a live system

### 6.8 Unified Logs — Network Events

The Unified Logging system (introduced in macOS 10.12) is an extremely rich source of network-related forensic evidence. Key subsystems to query:

- com.apple.networkd — network connection establishment and teardown

- com.apple.nsurlsessiond — URL session activity (downloads, API calls)

- com.apple.firewall — application firewall decisions

- com.apple.configd — network configuration changes

Use the log command-line tool or Console.app to query Unified Logs. Note: live logs are stored in /var/db/diagnostics/ but require macOS tools to parse correctly.

### 6.9 Remote Access Artifacts (Screen Sharing, Apple Remote Desktop, Microsoft RDC)

Prior to this revision, this document had **no coverage of remote-access-client artifacts** — a real gap for lateral-movement and unauthorized-remote-access investigations. Three distinct clients/services are documented here; all sourced directly from mac_apt plugin code, unverified against a live system.

#### 6.9.1 Screen Sharing (built-in macOS client)

macOS's native Screen Sharing app maintains a connection history — a durable record of what remote hosts a user has connected to, independent of whether the session left any other trace.

| Detail | Value |
|----|----|
| Location | `~/Library/Containers/com.apple.ScreenSharing/Data/Library/Preferences/com.apple.ScreenSharing.plist` |
| Format | Binary plist; connection details are stored in a nested serialized plist under the `connectionsStore` key |
| Contains | Per-host UUID, IP address, display name, login username, connection group name, and last-connected timestamp |

- The `sessionMetadatas`/`connectionDetails`/`connectionGroups` sub-structures must all be present to fully resolve a connection record — a partially-populated plist may still contain a host UUID without a resolvable timestamp or group
- Parser: [mac_apt](https://github.com/ydkhatri/mac_apt) `SCREENSHARING` plugin (`plugins/screensharing.py`)

#### 6.9.2 Apple Remote Desktop (ARD) — cached app usage

Distinct from Screen Sharing above — ARD is Apple's enterprise remote-management product, and its cache tracks **application usage during a remote session**, not just the connection itself.

| Detail | Value |
|----|----|
| Location | `/private/var/db/RemoteManagement/caches/UserAcct.tmp` (session start/end + UID), `/private/var/db/RemoteManagement/caches/AppUsage.plist` and `AppUsage.tmp` (per-app runtime during sessions) |
| Format | Binary plist |
| Contains | Session start/end time and UID (UserAcct.tmp); app name, path, launch time, run duration, and whether the app was frontmost during an ARD-managed session (AppUsage) |

- Requires root to access (`/private/var/db/` is root-owned)
- Parser: [mac_apt](https://github.com/ydkhatri/mac_apt) `ARD` plugin (`plugins/ard.py`)

#### 6.9.3 Microsoft Remote Desktop Client (macOS)

| Detail | Value |
|----|----|
| Database location | `~/Library/Containers/com.microsoft.rdc.macos/Data/Library/Application Support/com.microsoft.rdc.macos/com.microsoft.rdc.application-data.sqlite` |
| Thumbnails location | `~/Library/Containers/com.microsoft.rdc.macos/Data/Library/Application Support/com.microsoft.rdc.macos/SupportingImages/` — TIFF files named by Host_ID |
| Format | SQLite (Core Data-backed, `Z`-prefixed tables) |
| Key Tables | `ZBOOKMARKENTITY` (saved RDP connection profiles: hostname, friendly name, group, credential config), `ZCONNECTIONTIMEENTITY` (actual connection history: start time, minutes connected) |
| Contains | Target hostname, friendly display name, group/folder name, credential-use policy (ask each time vs. stored account), stored username, whether a nil/blank password was configured, folder-redirection mappings, and per-connection start time + duration |

- Session thumbnails (screen captures of the remote desktop at disconnect) are recoverable and correlate to a specific `Host_ID` in the database — useful for visually confirming what was on-screen during a remote session
- `ZBOOKMARKENTITY` alone shows *configured* connections (may never have been used); cross-reference against `ZCONNECTIONTIMEENTITY` to confirm actual connection activity and duration
- Parser: [mac_apt](https://github.com/ydkhatri/mac_apt) `MSRDC` plugin (`plugins/msrdc.py`). Note: the plugin's own published usage string is a copy-paste error (it currently reads "XProtect diagnostic files...") — the paths above were taken from the plugin's actual `Plugin_Start` code, not its docstring; flagging in case this is fixed upstream and the string later reads correctly

## 7. Phase 5 — System & Security Artifacts

### 7.1 Unified Logs — Overview

The Unified Logging system replaced ASL (Apple System Log) and syslog in macOS 10.12 Sierra. It is the primary source of system-level forensic evidence on modern macOS systems.

> **Correction (2026-08-21):** an earlier revision of this section mislabeled `/private/var/db/uuidtext/` as an "archive location." It is not an archive of older log entries — it is the **symbol/format-string store** that Unified Logging references to resolve human-readable message text out of the compact `.tracev3` files. Both directories are collected together for the current log; this revision also adds `timesync`, which was previously missing entirely. Paths verified against [UAC](https://github.com/tclahr/uac)'s `artifacts/files/logs/macos_unified_logs.yaml` collector definition, 2026-08-21.

| Detail | Value |
|----|----|
| Log entries | `/private/var/db/diagnostics/*.tracev3` — compact binary log records |
| Symbol/format-string store | `/private/var/db/uuidtext/` — required to resolve message format strings referenced by `.tracev3` entries; **not** an archive of old logs |
| Timesync files | `/private/var/db/diagnostics/timesync/` — **required** to convert the relative/boot-relative timestamps embedded in `.tracev3` records into absolute wall-clock time; a `.tracev3` collected without its matching timesync data cannot be timestamp-correlated correctly |
| Legacy ASL (pre-10.12 systems only) | `/private/var/log/asl.db`, `/private/var/log/asl.log`, `/private/var/log/asl/*` — collect if imaging a system that predates Sierra, or that was upgraded from one and retains legacy logs |
| Retention | Varies; typically 7 days of fine-grained logs, longer for compressed archives. Logs cycle quickly — collect rapidly. |
| Parsing tool | log (built-in CLI), Ulbow (GUI), mac_apt UNIFIEDLOGS plugin |

**Collection reminder:** always collect `.tracev3`, `uuidtext`, and `timesync` together as a set. Collecting only the `.tracev3` files (a common mistake) yields log records that cannot be fully decoded or accurately timestamped.

**BASH — UNIFIED LOG QUERIES**

```bash
# Stream live log with predicate filter
log stream --predicate 'subsystem == "com.apple.aop"' --info
# Query from archive (acquired logarchive)
log show --archive /path/to/system.logarchive \
--predicate 'subsystem == "com.apple.backgroundtaskmanagement"' --info
# SMC/AOP coprocessor events (physical presence evidence)
log show --predicate 'subsystem == "com.apple.aop"' \
--info --last 7d
# DCPEXT display connection events
log show --predicate 'subsystem BEGINSWITH "com.apple.dcpext"' \
--info --last 7d
```

### 7.2 TCC — Transparency, Consent & Control

The TCC database records which applications have been granted or denied access to sensitive user data and system resources. It is essential for understanding the privacy posture of the device and for establishing whether an application had access to data relevant to an investigation.

| Detail          | Value                                             |
|---------------------|-------------------------------------------------------|
| System TCC location | /Library/Application Support/com.apple.TCC/TCC.db     |
| User TCC location   | ~/Library/Application Support/com.apple.TCC/TCC.db    |
| Format              | SQLite database                                       |
| Key table           | access                                                |
| Access requirement  | Full Disk Access (FDA) required to read system TCC.db |

Key fields in the access table:

- client — bundle ID or path of the requesting application

- service — the resource being requested (e.g., kTCCServiceCamera, kTCCServiceMicrophone, kTCCServiceSystemPolicyAllFiles)

- auth_value — 0 = denied, 2 = allowed

- last_modified — Unix timestamp of when the grant/denial was last changed

**TCC.DB — PERMISSION AUDIT**

```sql
SELECT service,
client,
CASE auth_value WHEN 2 THEN 'Allowed' ELSE 'Denied' END AS status,
datetime(last_modified, 'unixepoch', 'localtime') AS changed
FROM access
ORDER BY last_modified DESC;
```

### 7.3 Persistence Mechanisms

A key goal in many forensic investigations is identifying whether malicious software established persistence. macOS persistence locations:

#### 7.3.1 Launch Agents & Launch Daemons

- User LaunchAgents: ~/Library/LaunchAgents/*.plist — run as the user on login

- System LaunchAgents: /Library/LaunchAgents/*.plist — run as the user for all users

- System LaunchDaemons: /Library/LaunchDaemons/*.plist — run as root at system boot

- Apple system services: /System/Library/LaunchDaemons/ and /System/Library/LaunchAgents/ (should not contain unexpected items)

- XPC launchd overrides: /private/var/db/com.apple.xpc.launchd/ — tracks disabled/overridden agents and daemons

#### 7.3.2 Background Task Management (BTM) — Login Items & Background Tasks

Since macOS 13 (Ventura), login items and all registered background tasks are managed by the Background Task Management (BTM) subsystem. The BTM database supersedes the legacy com.apple.loginitems.plist and is now the authoritative record of persistence on modern macOS systems.

| Detail | Value |
|----|----|
| Path | /private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm |
| Version on macOS 13–14 | v9 |
| Version on macOS 15.2 | v13 |
| Version on macOS 26 (Tahoe) | v16 |
| Format | NSKeyedArchive (binary plist serialisation) |
| Access | Requires root; not readable by standard users |

Multiple versioned .btm files may coexist on a single system — artefacts of previous macOS versions. Each represents the BTM state at a different point in time and should all be examined.

**BTM Type Values**

| Hex Value | Type | Forensic Relevance |
|----|----|----|
| 0x00001 | user item | Manually added by the user via System Settings |
| 0x00002 | app | Application registered as a background item |
| 0x00004 | login item | Launches at user login |
| 0x00008 | agent | LaunchAgent registered via SMAppService or legacy plist |
| 0x00010 | daemon | LaunchDaemon; runs as root at boot |
| 0x00020 | developer | Developer/Xcode entry — generally not an autostart; filter out in most investigations |
| 0x00040 | spotlight | Spotlight metadata extension |
| 0x00800 | quicklook | QuickLook preview extension |
| 0x80000 | curated | Apple-curated/system entry |
| 0x10000 | legacy | Pre-BTM legacy login item migrated into the BTM store |

**BTM Disposition Flags**

| Hex Value | Flag | Meaning |
|----|----|----|
| 0x01 | Enabled | The item is enabled. If absent, the app itself has programmatically disabled the item. |
| 0x02 | Allowed | The user has allowed this item to run. If absent ('Not Allowed'), the user has explicitly toggled it OFF in System Settings > Login Items & Extensions. |
| 0x04 | Hidden | The item runs silently without appearing in the Login Items UI. |
| 0x08 | Notified | The user has been shown a notification about this item registering. |

**BTM Red Flags — Indicators of Suspicious Entries**

| Red Flag | Why It Matters | Action |
|----|----|----|
| Absolute URL pointing outside an app bundle | Legitimate bundled extensions use relative paths. An absolute path to /tmp/, /Users/Shared/, or any writable location is highly unusual. | Examine the executable at that path; hash and submit to VirusTotal |
| Type daemon or agent with Developer Name: (null) | System-level persistence items from legitimate software are almost always signed. Null on a daemon or agent is anomalous. | Verify Team Identifier; inspect the executable |
| Hidden disposition flag (0x04) | The item is deliberately concealing itself from the Login Items & Extensions UI. No legitimate software needs this. | High priority — treat as potentially malicious |
| Team Identifier mismatch within a lineage group | All extensions of a legitimate app should share the same Team ID as the parent. | Establish who owns the foreign Team ID; check for app bundle tampering |
| Not Allowed disposition with suspicious path | Means the user noticed and disabled it — but it attempted to persist. The attempt is the finding. | Investigate what installed the item and when |

**Extraction Methods**

- Live system: sudo sfltool dumpbtm > ~/Documents/btmdump.txt

- Forensic image: mac_apt AUTOSTART plugin — deserialises NSKeyedArchive and outputs all BTM fields to a structured spreadsheet

- BTM timeline: Unified Logs, subsystem com.apple.backgroundtaskmanagement — records every registration, modification, and deletion event with timestamps

- Unknown entries: cross-reference against /System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist

#### 7.3.3 Cron Jobs & Periodic Scripts

- User crontabs: /usr/lib/cron/tabs/<username>

- System periodic scripts: /etc/periodic/daily|weekly|monthly

- Launchctl scheduled tasks: check LaunchDaemon/Agent plists for StartCalendarInterval or StartInterval keys

- One-time scheduled jobs (`at`, distinct from recurring cron jobs): /private/var/at — source: [UAC](https://github.com/tclahr/uac) `artifacts/files/system/job_scheduler.yaml`, 2026-08-21, unverified against a live system

### 7.4 Authentication & Authorization Artifacts

#### 7.4.1 Authentication Logs

- OpenDirectory logs in Unified Logs: subsystem com.apple.OpenDirectory

- sudo usage: search Unified Logs for process sudo

- SSH authentication: /var/log/auth.log (may not exist on all versions; check Unified Logs for sshd)

- Failed login attempts: Unified Logs, subsystem com.apple.securityd

#### 7.4.2 Keychain

| Detail | Value |
|----|----|
| User login keychain | ~/Library/Keychains/login.keychain-db (SQLite) |
| System keychain | /Library/Keychains/System.keychain |
| Contains | Stored passwords, certificates, private keys, tokens, WiFi passwords, VPN credentials |
| Decryption requirement | User credentials or Secure Enclave; chainbreaker tool can extract metadata without full decryption |

Even without decryption, keychain metadata (service names, account names, creation dates, modification dates) is forensically useful. The chainbreaker tool (github.com/n0fate/chainbreaker) can extract this metadata. The presence of specific service names may reveal which credentials a user had stored.

**iCloud Keychain trusted-device list:** `~/Library/Application Support/com.apple.akd/devicelist.db` — records trusted device entries used by iCloud Keychain sync (managed by the `akd` daemon). Distinct from the login/system keychain files above; useful for establishing which other Apple devices were trusted to sync keychain data with this Mac. Source: [UAC](https://github.com/tclahr/uac) `artifacts/files/system/macos_keychain_devicelist.yaml`, 2026-08-21, unverified against a live system.

### 7.5 Local User Accounts (dslocal)

| Detail | Value |
|----|----|
| Location | /private/var/db/dslocal/nodes/Default/users/ |
| Format | One binary plist per user, named <username>.plist |
| Access | Requires root |
| Contains | Username, UID, GID, real name, home directory, shell, account creation time, ShadowHashData (password hash) |

The dslocal directory is the authoritative source for local user account information on macOS. Each user has a plist file that can be read with plutil. The ShadowHashData key contains the hashed password in PBKDF2-SHA512 format and can be extracted for offline cracking if required.

### 7.6 System Integrity Protection (SIP) & Gatekeeper

Evidence of SIP being disabled is a significant finding, as it may indicate an attempt to tamper with protected system files or install unsigned software:

- SIP status recorded in NVRAM; check nvram csr-active-config output in acquisition logs

- Gatekeeper quarantine override evidence: Unified Logs, process syspolicyd

#### 7.6.1 XProtect & MRT (Malware Removal Tool)

Expanded 2026-08-21 from a single Unified Logs reference — XProtect has two independent evidence sources beyond log subsystem `com.apple.XProtect`, plus version/definition metadata for confirming detection capability at time of incident.

| Detail | Value |
|----|----|
| XProtect diagnostic files | `~/Library/Logs/DiagnosticReports/XProtect_YYYY-MM-DD-hhmmss_<Hostname>.diag` (plist) — written when the legacy signature-based scanner acts on a quarantined file |
| XProtect Behavior Service (XPBS) database | `/private/var/protected/xprotect/XPdb` (SQLite, `events` table) — the newer heuristic/behavioral detection layer, independent of the legacy signature scanner above |
| Bundle/version metadata | `/private/var/protected/xprotect/XProtect.bundle/Contents/Info.plist`, `/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist`, `/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist`, `/Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist` |

- **Diagnostic file contents:** `XProtectSignatureName` (which signature matched), `UserAction` (what the user did — allow/block/etc.), plus the same quarantine metadata as QuarantineEvents (4.7): `LSQuarantineAgentBundleIdentifier`, `LSQuarantineDataURL`, `LSQuarantineOriginURL`, `LSQuarantineTimeStamp`. Filename embeds the detection timestamp directly.
- **XPBS `events` table contents:** per-event code-signing identity for **both** the executing binary and the "responsible" (triggering/parent) process — `exec_path`, `exec_cdhash`, `exec_signing_id`, `exec_team_id`, `exec_sha256`, `exec_is_notarized`, plus the equivalent `responsible_*` fields, `violated_rule`, and whether the event was `reported` to Apple. This is materially richer than the legacy diagnostic files — it can confirm whether a flagged binary was signed/notarized and identify what parent process triggered the behavioral rule violation.
- **Version/bundle metadata use case:** confirms exactly which XProtect/MRT definition version was active at the time of an incident — relevant for assessing whether a given piece of malware could plausibly have been caught by signature-based detection at that point in time, versus genuinely being novel/undetected
- Parsers: [mac_apt](https://github.com/ydkhatri/mac_apt) `XPROTECT` plugin (`plugins/xprotect.py`) for diagnostic files and XPBS database (paths/schema verified against plugin source, 2026-08-21); bundle version paths from [UAC](https://github.com/tclahr/uac) `artifacts/files/system/xprotect.yaml`, 2026-08-21. Both unverified against a live system.

#### 7.6.2 BSM Audit Trail

A separate, parallel logging subsystem to Unified Logs (7.1) — the BSD/Sun-derived Basic Security Module (BSM) audit trail records lower-level, security-relevant kernel events (syscalls, authentication, privilege use) independent of Apple's own Unified Logging infrastructure.

| Detail | Value |
|----|----|
| Location | `/private/var/audit/` |
| Format | Binary BSM audit trail files (standard `praudit`-readable format, shared lineage with Solaris/FreeBSD/other BSD-derived audit implementations) |
| Parsing tool | `praudit` (built-in CLI) |

- Distinct value from Unified Logs: BSM auditing predates Unified Logging and operates at a different layer (closer to raw syscall/kernel audit events per the historical BSM design); may retain evidence in scenarios where Unified Log retention has already cycled out the relevant window, or where BSM auditing was specifically configured for compliance reasons (`/etc/security/audit_control`)
- Confirm auditd is actually enabled/configured before relying on this source — presence of the directory does not guarantee meaningful content if auditing was never configured beyond OS defaults
- Source: [UAC](https://github.com/tclahr/uac) `artifacts/files/logs/macos.yaml`, 2026-08-21, unverified against a live system

### 7.7 FileVault Recovery & Preboot Artifacts

Prior to this revision, this document had no coverage of FileVault/encryption-recovery artifacts.

| Detail | Value |
|----|----|
| Location | `/System/Volumes/Preboot/` (the APFS Preboot volume — present on all Apple Silicon Macs and most modern Intel Macs; boots before the main encrypted data volume unlocks) |
| Files of interest | `AdminUserRecoveryInfo.plist`, `CryptoUserInfo.plist` |
| Access | Preboot is a separate APFS volume from the main system volume — requires mounting/acquiring it explicitly, not just the primary system volume |

- These files hold FileVault-related recovery and admin-user account metadata staged in the unencrypted Preboot volume so the system can present a valid login/recovery UI before the encrypted volume is unlocked
- Relevant to investigations involving encryption status disputes, recovery-key usage claims, or establishing which admin accounts were FileVault-enrolled at a given point in time
- Source: [UAC](https://github.com/tclahr/uac) `artifacts/files/system/recovery_account_info.yaml`, 2026-08-21, unverified against a live system — field-level schema of these plists not yet documented here, verify structure directly on acquisition

## 8. Phase 6 — Cloud & iCloud Artifacts

### 8.1 iCloud Drive

- Local sync database: ~/Library/Application Support/CloudDocs/session/db/ (SQLite)

- CloudDocs daemon logs in Unified Logs: subsystem com.apple.cloudd

- iCloud Drive files locally cached in ~/Library/Mobile Documents/com~apple~CloudDocs/

- File eviction evidence: when iCloud offloads files, .icloud placeholder files remain

### 8.2 iOS Device Backups (iTunes / Finder)

| Detail | Value |
|----|----|
| Location | ~/Library/Application Support/MobileSync/Backup/ |
| Format | Folder per device, named with device UUID; Manifest.db (SQLite index), Info.plist (device metadata), files named by SHA1 hash |
| Contains | SMS/iMessage, call history, notes, health data, app data, photos |

Local iOS/iPadOS backups on a Mac are often more forensically recoverable than the device itself. Manifest.db maps SHA1 filenames to original paths on the iOS device, allowing reconstruction of the backup's directory structure. Even if the backup is encrypted, the backup timestamp and device metadata in Info.plist are available without decryption.

### 8.3 Photos Library

| Detail | Value |
|----|----|
| Location | ~/Pictures/Photos Library.photoslibrary/ |
| Database | database/Photos.sqlite (SQLite) |
| Key Tables | ZASSET, ZGENERICASSET, ZADDITIONALSETTINGASSET |
| Contains | Photo/video metadata, location data, faces, albums, iCloud sync status, timestamps |

### 8.4 Notes

| Detail | Value |
|----|----|
| Location | ~/Library/Group Containers/group.com.apple.notes/ |
| Database | NoteStore.sqlite |
| Contains | Note content (gzip-compressed protobuf in ZICNOTEDATA.ZDATA), attachments, creation/modification timestamps, account information |

See Section 6.6 for full query guidance.

### 8.5 FindMy Cache

| Detail | Value |
|----|----|
| Location | ~/Library/Caches/com.apple.findmy.fmipcore/<br>~/Library/Caches/com.apple.icloud.fmfd/ |
| Contains | Last-known locations of associated Apple devices, device names, and account association data |

FindMy cache is useful for establishing what Apple devices are associated with the subject account and their approximate locations at the time of last sync. This can corroborate or contradict claims about device locations.

### 8.6 Third-Party Messaging Applications

Beyond Apple's native messaging stack, several third-party platforms are commonly used in enterprise environments and may hold significant evidence. All store data in ~/Library/Application Support/ unless noted.

| Application | Primary macOS Path | Forensic Notes |
|----|----|----|
| WhatsApp | ~/Library/Application Support/WhatsApp/<br>~/Library/Group Containers/group.net.whatsapp.WhatsApp.shared/ | Group Containers path contains the message database and media. Cache and Local Storage (LevelDB) under Application Support. |
| Signal | ~/Library/Application Support/Signal/sql/db.sqlite | App-level encrypted SQLite database. Encryption key stored in Signal's config.json — extraction feasible on a live unlocked system. Content encrypted in transit but stored locally. |
| Telegram Desktop | ~/Library/Application Support/Telegram Desktop/tdata/ | Proprietary encrypted format in tdata/. log.txt contains operational log entries. Third-party tools required for message decryption. |
| Slack | ~/Library/Application Support/Slack/Local Storage/leveldb/ | LevelDB store contains cached workspace messages and channel history. Useful for insider threat investigations involving corporate Slack workspaces. |
| Microsoft Teams | ~/Library/Application Support/Microsoft/Microsoft Teams/Local Storage/leveldb/ | Same LevelDB structure as Slack. Contains cached messages, files, and meeting metadata. |
| Skype | ~/Library/Application Support/Microsoft/Skype for Desktop/ | Message history and media cache. |
| Facebook Messenger | ~/Library/Application Support/Messenger/ | Cache and local storage for Messenger Desktop. |
| Viber | ~/Library/Application Support/ViberPC/ | Message database and media cache. |

## 9. Tooling Reference

### 9.1 Open-Source Tools

| Tool | Purpose | Location / Source |
|----|----|----|
| mac_apt | Comprehensive macOS artifact parser; covers 40+ artifact types including KnowledgeC, TCC, BTM, FSEvents, QuarantineEvents, iMessage | github.com/ydkhatri/mac_apt |
| UAC (Unix-like Artifacts Collector) | Shell-based live collection tool; broad macOS coverage including browsers, cloud clients, remote access tools | github.com/tclahr/uac |
| osxcollector | Live collection of forensic data from macOS | github.com/Yelp/osxcollector |
| Autopsy | Cross-platform GUI forensic suite with macOS artifact support | sleuthkit.org/autopsy |
| log (built-in) | Parse and query Unified Logs from terminal | Built into macOS |
| sqlite3 (built-in) | Direct SQLite database querying | Built into macOS/Linux |
| exiftool | Extract metadata from files and documents including EXIF, PDF, Office formats | exiftool.org |
| plutil (built-in) | Convert and read binary plist files | Built into macOS |
| chainbreaker | Extract Keychain metadata without decryption | github.com/n0fate/chainbreaker |
| fsevents_dump | Parse FSEvents binary log files | github.com/nicowillis/fseventsd |
| biome_parser | Parse macOS Biome protobuf data streams | Various open-source projects |
| xattred / Metamer | GUI tools for viewing, creating, and editing extended attributes (xattrs) | eclecticlight.co/xattred-sandstrip-xattr-tools/ |

### 9.2 Commercial Tools

| Tool | Vendor | Strengths for macOS |
|----|----|----|
| Cellebrite UFED / Inspector | Cellebrite | Excellent iCloud and mobile backup parsing; strong GUI; widely accepted in court |
| Magnet AXIOM | Magnet Forensics | Strong artifact correlation; cloud acquisition support; Artifact Exchange community |
| BlackBag BlackLight | Cellebrite | macOS-native tool; deep APFS support; excellent KnowledgeC and Biome parsing |
| Recon Lab / Imager | Sumuri | macOS-native; strong Apple Silicon support; excellent for triage |
| Oxygen Forensic Detective | Oxygen Forensics | Strong iCloud acquisition; good for cases with connected mobile devices |
| FTK (Forensic Toolkit) | Exterro | Comprehensive filesystem analysis; strong indexing and search capabilities |

## 10. Database Query Reference

### 10.1 KnowledgeC.db — Key Queries

#### 10.1.1 Application Usage Timeline

**KNOWLEDGEC.DB — APP USAGE TIMELINE**

```sql
SELECT datetime(ZSTARTDATE + 978307200, 'unixepoch', 'localtime') AS start_time,
datetime(ZENDDATE + 978307200, 'unixepoch', 'localtime') AS end_time,
ZBUNDLEID AS app,
ZDEVICEID AS device
FROM ZOBJECT
WHERE ZSTREAMNAME = '/app/usage'
ORDER BY ZSTARTDATE DESC;
```

#### 10.1.2 Device Lock/Unlock Timeline

**KNOWLEDGEC.DB — DEVICE LOCK/UNLOCK TIMELINE**

```sql
SELECT datetime(ZSTARTDATE + 978307200, 'unixepoch', 'localtime') AS event_time,
ZSTREAMNAME AS event_type,
ZVALUEINTEGER AS value
FROM ZOBJECT
WHERE ZSTREAMNAME IN ('/device/isLocked', '/device/isBacklit')
ORDER BY ZSTARTDATE DESC LIMIT 200;
```

#### 10.1.3 Battery Level Events

**KNOWLEDGEC.DB — BATTERY LEVEL HISTORY**

```sql
SELECT datetime(ZSTARTDATE + 978307200, 'unixepoch', 'localtime') AS event_time,
ZVALUEINTEGER AS battery_level
FROM ZOBJECT
WHERE ZSTREAMNAME = '/device/batteryPercentage'
ORDER BY ZSTARTDATE DESC;
```

### 10.2 TCC.db — Permission Audit

**TCC.DB — FULL PERMISSION AUDIT**

```sql
SELECT service,
client,
CASE auth_value WHEN 2 THEN 'Allowed' ELSE 'Denied' END AS status,
datetime(last_modified, 'unixepoch', 'localtime') AS changed
FROM access
ORDER BY last_modified DESC;
```

### 10.3 QuarantineEvents — Download History

**QUARANTINEEVENTSV2 — DOWNLOAD HISTORY**

```sql
SELECT datetime(LSQuarantineTimeStamp + 978307200, 'unixepoch', 'localtime') AS download_time,
LSQuarantineAgentName AS app_used,
LSQuarantineDataURLString AS file_url,
LSQuarantineOriginURLString AS referring_url,
LSQuarantineSenderName AS sender
FROM LSQuarantineEvent
ORDER BY LSQuarantineTimeStamp DESC;
```

### 10.4 CallHistory — FaceTime & Phone Calls

**CALLHISTORY.STOREDATA — CALL RECORDS**

```sql
SELECT datetime(ZDATE + 978307200, 'unixepoch', 'localtime') AS call_time,
ZADDRESS AS remote_party,
ZDURATION AS duration_seconds,
ZORIGINATED AS outgoing_flag,
ZCALLTYPE AS call_type
FROM ZCALLRECORD
ORDER BY ZDATE DESC;
```

> **macOS 26 Note**
>
> FaceTime schema may have changed in Tahoe. Verify table and column names on a reference system before applying this query. See Appendix A.3.

### 10.5 Messages — chat.db

**CHAT.DB — MESSAGES WITH SENDER/RECIPIENT**

```sql
SELECT datetime(message.date / 1000000000 + 978307200,
'unixepoch', 'localtime') AS msg_time,
handle.id AS contact,
message.text AS message_text,
message.is_from_me,
message.service
FROM message
LEFT JOIN handle ON message.handle_id = handle.ROWID
ORDER BY message.date DESC LIMIT 500;
```

Note: The date encoding in chat.db changed across macOS versions. The above uses the modern nanosecond epoch offset. For older databases (pre-macOS 10.13), the offset may differ.

### 10.6 Extended Attribute Queries

**BASH — XATTR FORENSIC QUERIES**

```bash
# Show download origin for a file
xattr -p com.apple.metadata:kMDItemWhereFroms <filename> | plutil -convert xml1 - -o -
# Show quarantine info
xattr -p com.apple.quarantine <filename>
# Find all files with quarantine xattr in a directory tree
find . -xattr -name "com.apple.quarantine" 2>/dev/null
# Spotlight search for files downloaded from a domain
mdfind "kMDItemWhereFroms == '*example.com*'c"
```

## 11. Legal Considerations & Chain of Custody

### 11.1 Legal Authority

All forensic investigation must be conducted under appropriate legal authority. Proceeding without it may render evidence inadmissible and expose investigators to civil or criminal liability. Confirm the applicable legal framework before beginning:

- Criminal investigations: ensure warrant specifically covers digital evidence and the devices in question

- Corporate investigations: ensure applicable acceptable use policy authorises forensic inspection and that HR/legal have been consulted

- Consent: if relying on user consent, ensure it is informed, voluntary, and documented in writing

### 11.2 Chain of Custody Documentation

Chain of custody documentation must be maintained from the moment evidence is first touched. At minimum, record:

- Date, time, and location of evidence acquisition

- Name and role of each person who handled evidence

- Equipment used for acquisition (make, model, serial number)

- Hash values (MD5 + SHA-256) of acquired images, verified immediately after imaging

- Storage conditions and transfer methods for all evidence

- Any deviations from standard procedure and the justification for them

### 11.3 Report Writing

Forensic reports should be written for a technically non-expert audience (judges, lawyers, juries) while remaining defensible to technical peer review. Key principles:

- Separate findings (what you observed) from opinion (what it means)

- Document the tools used, their versions, and any known limitations

- Acknowledge uncertainty: where evidence is consistent with multiple explanations, present all of them

- Never overstate the significance of an artefact without corroborating evidence

## 12. Quick Reference Card

### 12.1 Top 12 Priority Artifacts

| Priority | Artifact | Location | Key Data |
|----|----|----|----|
| 1 | KnowledgeC.db | /private/var/db/CoreDuet/Knowledge/ | App usage, device lock/unlock, activity timeline |
| 2 | QuarantineEvents | ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 | All downloaded files with source URLs |
| 3 | Unified Logs | /var/db/diagnostics/ | System-wide activity, auth events, network connections |
| 4 | chat.db | ~/Library/Messages/ | iMessage/SMS content and metadata |
| 5 | FSEvents | /.fseventsd/ | File system activity timeline |
| 6 | CallHistory.storedata | ~/Library/Application Support/CallHistoryDB/ | FaceTime and phone call records |
| 7 | TCC.db | /Library/Application Support/com.apple.TCC/ | App permission grants and denials |
| 8 | BTM database | /private/var/db/com.apple.backgroundtaskmanagement/ | Persistence — all registered background items |
| 9 | Safari History.db | ~/Library/Safari/ | Web browsing history |
| 10 | IntelligencePlatform views.db | ~/Library/IntelligencePlatform/ | WiFi history, contact graph, photo age data |
| 11 | LaunchAgents/Daemons | ~/Library/LaunchAgents/, /Library/LaunchDaemons/ | Persistence mechanisms |
| 12 | Photos.sqlite | ~/Pictures/Photos Library.photoslibrary/database/ | Photo metadata, location, timestamps |

### 12.2 Common macOS Timestamp Decoding

| Format | Epoch | Conversion Formula |
|----|----|----|
| CoreData / CF Absolute Time | Jan 1, 2001 00:00:00 UTC | timestamp + 978307200 → Unix epoch |
| Unix epoch (standard) | Jan 1, 1970 00:00:00 UTC | No conversion needed |
| HFS+ timestamp | Jan 1, 1904 00:00:00 UTC | timestamp - 2082844800 → Unix epoch |
| Nanosecond (chat.db modern) | Jan 1, 2001, nanoseconds | (timestamp / 1000000000) + 978307200 → Unix epoch |
| Windows FILETIME | Jan 1, 1601 00:00:00 UTC | (timestamp / 10000000) - 11644473600 → Unix epoch |

All timestamps should be converted and presented in both UTC and the local time zone relevant to the investigation. Always document which time zone assumption was used in your report.

### 12.3 Key xattr Forensic Quick Reference

| xattr | What it tells you | Command to read |
|----|----|----|
| com.apple.quarantine | File was downloaded by a quarantine-aware app; contains app bundle ID and download timestamp flags | xattr -p com.apple.quarantine <file> |
| com.apple.metadata:kMDItemWhereFroms | Download URL and referring URL; often more complete than QuarantineEvents | xattr -p com.apple.metadata:kMDItemWhereFroms <file> \| plutil -convert xml1 - -o - |
| com.apple.metadata:kMDItemDownloadedDate | Timestamp of download; may differ from filesystem ctime if file was moved | mdls -name kMDItemDownloadedDate <file> |
| com.apple.lastuseddate#PS | Last time the file was opened (LaunchServices-tracked, independent of atime) | xattr -p "com.apple.lastuseddate#PS" <file> |
| com.apple.FinderInfo | Finder flags including Invisible bit; encodes label colour | xattr -p com.apple.FinderInfo <file> \| xxd |

## Appendix A — macOS 26 (Tahoe) Forensic Changes & New Artifacts

This appendix documents changes introduced in macOS 26 (Tahoe, released September 2025) that affect forensic investigations. Read alongside the main framework; entries here supersede or extend the equivalent sections where noted.

### A.1 Overview — Tahoe's Forensic Impact

macOS 26 (Tahoe) introduces a significant visual redesign ('Liquid Glass'), expanded Apple Intelligence features, and several structural changes to how data is stored and processed on-device. Tahoe is also the final version of macOS to support Intel-based Macs — from macOS 27 onward, all supported hardware will be Apple Silicon.

| Area | Change Type | Impact on Framework Section |
|----|----|----|
| Clipboard History | New artifact (persistent, Spotlight-indexed) | New — see A.2 |
| FaceTime databases | Restructured schema and file locations | Supersedes section 6.4 |
| Live Translation | New feature affecting message evidence | Extends section 6.2 |
| New disk image formats (ASIF / UDSB) | New file formats requiring updated tools | New — see A.5 |
| Intel Mac support ends | Last version supporting Intel hardware | Extends section 3.2 |
| Apple Intelligence features | Deliberate minimal-persistence design | Cross-cutting — see A.6 |
| Unified Log volume increase | Log fills faster in early Tahoe releases | Extends section 7.1 |
| AirDrop verification codes | New contact verification mechanism | Extends section 6.7 |

### A.2 New Artifact — Clipboard History

Clipboard History is one of the most significant new forensic artifacts introduced in Tahoe. In all prior versions of macOS, the clipboard was volatile — only the most recently copied item was retained, and only in memory. There was no persistent on-disk record of clipboard activity.

In macOS 26, Clipboard History maintains a persistent, searchable log of recently copied items. It is **off by default** and is accessed via a dedicated Clipboard pane (Cmd+Space → Cmd+4), not general Spotlight text search.

**Enablement:**
- System Settings → Spotlight → "Clipboard Search" toggle, or
- The in-Spotlight first-use prompt (offered the first time a user opens the Clipboard pane)

Because the feature is opt-in, **absence of clipboard history on a given system may indicate it was never enabled, not that it was cleared.** Verify enablement state before an examiner's report characterizes an empty result as evidence of deliberate clearing.

| Detail | Value |
|----|----|
| On-disk location | Unconfirmed — a previously documented path (`~/Library/Application Support/com.apple.ClipboardHistory/`) was tested and confirmed **not** to exist on a live macOS 26 system (2026-08-21). Treat as unlocated pending further testing. |
| Format | SQLite or binary plist — confirm with direct inspection post-acquisition, once the actual location is identified |
| Retention window | Disputed/unconfirmed — figures cited elsewhere range from ~8 hours to ~30 days; treat as an open question rather than citing either figure until independently verified |
| Tool support | Emerging — validate that your toolset has been updated for Tahoe before relying on automated parsing |

- May contain copied text, document excerpts, command-line output, URLs, passwords, and code snippets — **with the exception of items copied by apps that mark their pasteboard writes as concealed or transient** (the `org.nspasteboard.ConcealedType` / `org.nspasteboard.TransientType` convention honored by most password managers, e.g. 1Password, Bitwarden); such items are expected to be excluded from Clipboard History and should not be assumed present

- Provides direct evidence of user intent — what a user deliberately copied is often more probative than what was merely opened

- Could reveal staged data prior to exfiltration (copied credentials, internal documents) — **though see the concealed/transient caveat above: credentials copied via a compliant password manager will likely not appear here**

### A.3 FaceTime — Restructured Databases

FaceTime received a significant interface and backend overhaul in macOS 26. The databases that track call history have been reorganised. This directly affects the queries and file paths documented in Section 6.4.

- The CallHistory.storedata Core Data database remains the primary artifact, but table schemas may have changed

- File locations within the CallHistoryDB bundle may have been reorganised — verify paths on a reference system

- New metadata fields related to FaceTime's enhanced features may appear as additional columns

- The ZCALLTYPE field may include new enumeration values for Tahoe-specific call types

Recommended approach: locate the CallHistoryDB bundle at ~/Library/Application Support/CallHistoryDB/ and inspect its contents directly before applying any scripted queries.

## Appendix B — BTM Attribution Compare Script

This appendix documents the btm_attribution_compare.py script, which automates cross-referencing of BTM dump output against Apple's attributions.plist to rapidly triage persistence entries by status.

### B.1 Purpose

When investigating BTM entries, manually checking each entry's Team Identifier or Bundle ID against attributions.plist is slow. The script processes an entire sfltool dumpbtm output file in a single pass, categorises every entry, flags developer name mismatches, and outputs both a colour-coded terminal report and a CSV for case management.

### B.2 Output Categories

| Status | Meaning | Triage Priority |
|----|----|----|
| UNKNOWN | Team ID not found in attributions.plist — not a recognised legitimate application | HIGH — investigate first |
| NO_TEAM_ID | Entry has no Team Identifier — unsigned or incompletely signed | MEDIUM — review all |
| KNOWN_MISMATCH | In attributions.plist but Developer Name in BTM disagrees with attributions — possible trojanised app or certificate reuse | HIGH — verify carefully |
| KNOWN | Matched in attributions.plist with consistent developer name | LOW — can deprioritise |

### B.3 Usage

**BASH — RUN BTM ATTRIBUTION COMPARE**

```bash
# Step 1: Capture BTM dump (live system)
sudo sfltool dumpbtm > ~/Documents/btmdump.txt
# Step 2: Run comparison (uses default attributions.plist path)
python3 btm_attribution_compare.py btmdump.txt
# Step 3: With custom attributions.plist (e.g. from forensic image)
python3 btm_attribution_compare.py btmdump.txt /path/to/attributions.plist
# Output: colour-coded terminal report + btm_comparison.csv
```

### B.4 Script Source

**PYTHON — btm_attribution_compare.py**

```python
import sys, re, io, csv, plistlib
from pathlib import Path

ATTRIBUTIONS_DEFAULT = (
    "/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework"
    "/Versions/A/Resources/attributions.plist")

def parse_btm_dump(path):
    entries, current, n = [], {}, 0
    for line in Path(path).read_text().splitlines():
        m = re.match(r'^\s+(\S[^:]+):\s+(.+)$', line)
        if m:
            current[m.group(1).strip()] = m.group(2).strip()
        elif line.strip().startswith('[') and current:
            n += 1; current['_entry_num'] = n
            entries.append(current); current = {}
    if current: entries.append(current)
    return entries

def load_attributions(path):
    with open(path, "rb") as f:
        data = plistlib.load(f)
    by_team, by_bundle = {}, {}
    items = data if isinstance(data, list) else data.get("attributions", [])
    for item in items:
        team = item.get("teamIdentifier", "")
        if team: by_team.setdefault(team, []).append(item)
        for bid in item.get("bundleIdentifiers", []):
            by_bundle.setdefault(bid, []).append(item)
    return by_team, by_bundle

strip_uid = lambda s: re.sub(r"^\d+\.", "", s)

def compare(btm_entries, by_team, by_bundle):
    results = []
    for entry in btm_entries:
        team_id = entry.get("Team Identifier", "").strip()
        bundle_id = strip_uid(entry.get("Bundle Identifier", ""))
        ident = strip_uid(entry.get("Identifier", ""))
        dev_name = entry.get("Developer Name", "(null)")
        matches = (by_team.get(team_id, []) or
                   by_bundle.get(bundle_id, []) or
                   by_bundle.get(ident, []))
        if matches:
            a = matches[0]
            attr_disp = (a.get("displayName") or a.get("developerName") or
                         ", ".join(a.get("bundleIdentifiers", [])[:2]))
            attr_dev = a.get("developerName", "")
            mismatch = (attr_dev and dev_name != "(null)" and
                        attr_dev.lower() != dev_name.lower())
            status = "KNOWN_MISMATCH" if mismatch else "KNOWN"
        else:
            attr_disp, mismatch = "", False
            status = "NO_TEAM_ID" if not team_id else "UNKNOWN"
        results.append({
            "Entry": entry.get("_entry_num"), "Status": status,
            "Name": entry.get("Name", ""), "Type": entry.get("Type", ""),
            "Team ID": team_id, "Dev Name": dev_name,
            "Bundle ID": bundle_id, "Disposition": entry.get("Disposition", ""),
            "URL": entry.get("URL", ""), "Attr Match": attr_disp,
            "Name Mismatch": "YES" if mismatch else "",
        })
    return results
```

### B.5 Key Improvements Over Basic grep Approach

| Feature | Basic grep | btm_attribution_compare.py |
|----|----|----|
| Matching strategy | Single field text search | Three-tier: Team ID > Bundle ID > Identifier, with UID prefix stripping |
| Developer name mismatch detection | Not possible | Flags KNOWN_MISMATCH when attributions.plist disagrees with BTM Developer Name |
| Scale | One entry at a time | Processes entire dump in one pass |
| Output format | Raw plist XML snippets | Grouped triage report (terminal) + full CSV for case management |
| Portability | Requires macOS | Runs on any Python 3.6+ system |
| Unsigned entry detection | Only if you know to look | Automatically surfaces all NO_TEAM_ID entries as a distinct group |

## Appendix C — Shell History & SSH Artifacts

Shell history and SSH artifacts are high-value forensic sources that are absent from many macOS forensic frameworks despite being routinely collected by live response tools. zsh shell history in particular is available on every modern Mac by default.

### C.1 Shell History

macOS has used zsh as the default shell since macOS 10.15 Catalina. Bash history may also be present on systems upgraded from older macOS versions or where developers have explicitly switched shells.

| Detail | Value |
|----|----|
| zsh history | ~/.zsh_history or ~/.zhistory |
| zsh sessions | ~/.zsh_sessions/ (per-session files with precise timestamps when EXTENDED_HISTORY is set) |
| bash history | ~/.bash_history |
| bash sessions | ~/.bash_sessions/ (macOS 10.10+) |
| Format | Plain text; zsh extended history format: : <timestamp>:<elapsed>;<command> |

**C.1.1 Forensic Significance**

- Command execution timeline — shell history provides a direct record of what commands the user ran, including file operations, network tools, script execution, and data manipulation

- Tool usage evidence — presence of commands like curl, wget, nmap, netcat, python -c, or base64 may indicate data staging, exfiltration attempts, or exploitation tooling

- Timestamp extraction — zsh extended history format embeds Unix timestamps per command, enabling precise timeline reconstruction even without filesystem event logs

- Anti-forensic indicators — a suspiciously empty or truncated history file on an active system may indicate deliberate clearing; check HISTSIZE and HISTFILESIZE settings in .zshrc

**BASH — EXTRACT ZSH HISTORY WITH TIMESTAMPS**

```bash
# Read raw zsh history (extended format)
cat ~/.zsh_history
# Extract timestamp + command (extended history format)
grep -E "^: [0-9]+:" ~/.zsh_history | \
awk -F'[;:]' '{ts=$2; cmd=$4; printf "%s %s\n", strftime("%Y-%m-%d %H:%M:%S",ts), cmd}'
# Per-session history files (more granular timestamps)
ls -la ~/.zsh_sessions/
cat ~/.zsh_sessions/*.history 2>/dev/null
# Check if extended history is configured
grep -E "EXTENDED_HISTORY|HIST" ~/.zshrc ~/.zprofile 2>/dev/null
```

### C.2 SSH Artifacts

SSH artifacts reveal remote access history and may indicate lateral movement or unauthorized remote access mechanisms.

| Artifact | Path | Forensic Significance |
|----|----|----|
| known_hosts | ~/.ssh/known_hosts | Every SSH server the user has connected to. Contains hostname/IP and server public key fingerprint. A persistent record of lateral movement targets even after connection logs are cleared. |
| authorized_keys | ~/.ssh/authorized_keys | Public keys authorized to authenticate to this Mac without a password. Unexpected entries indicate a potential backdoor or persistent unauthorized access mechanism — high-priority finding. |
| SSH public keys | ~/.ssh/*.pub | User's own public keys. Multiple keys may indicate use of different identities for different target systems. |
| SSH config | ~/.ssh/config | Per-host connection settings: ProxyJump, IdentityFile, HostName aliases. Reveals which remote systems the user regularly accesses and any tunneling/proxying configured. |
| SSH rc | ~/.ssh/rc | Script executed on SSH connection establishment. Rarely used legitimately; presence of commands here warrants investigation. |

**BASH — SSH FORENSIC COLLECTION**

```bash
# List all SSH keys and their fingerprints
for f in ~/.ssh/*.pub; do echo "$f:"; ssh-keygen -l -f "$f"; done
# Show known_hosts with timestamps (if HashKnownHosts is off)
cat ~/.ssh/known_hosts
# Check authorized_keys (potential backdoor)
cat ~/.ssh/authorized_keys 2>/dev/null && echo "AUTHORIZED KEYS PRESENT"
# Show SSH config (reveals target systems)
cat ~/.ssh/config 2>/dev/null
```

> **Authorized Keys — High-Priority Finding**
>
> The presence of any entry in ~/.ssh/authorized_keys on a corporate Mac that was not provisioned through an MDM or IT process is a significant finding. It allows the key holder to authenticate to this Mac over SSH without a password, from anywhere that can reach the machine on TCP/22. Document the full public key and attempt to identify the corresponding private key holder.

## Appendix D — Live Response Collection Reference

Live response collection captures volatile artifacts that do not persist after system shutdown. This appendix provides a structured quick-reference for macOS live response, organized by collection priority. Commands should be run in order on a live system before any shutdown or imaging step.

> **Order of Collection**
>
> Collect in this order: (1) running processes, (2) network connections, (3) open files/lsof, (4) kernel state, (5) hardware/system info, (6) package inventory, (7) shell history (semi-volatile — could be cleared). Shell history and SSH keys can also be collected from a forensic image; the others require a live system.

### D.1 Process & Network State

**BASH — PROCESS & NETWORK LIVE COLLECTION**

```bash
# Running processes with start times
ps auxwww > ~/liveresponse/ps_auxwww.txt
ps -axo pid,user,lstart,args > ~/liveresponse/ps_lstart.txt
# Network connections — TCP/UDP
netstat -anp tcp > ~/liveresponse/netstat_tcp.txt
netstat -anp udp > ~/liveresponse/netstat_udp.txt
# ARP cache (LAN host mapping — expires quickly)
arp -a > ~/liveresponse/arp.txt
# All open files and network connections per process
sudo lsof -nPl > ~/liveresponse/lsof_all.txt
sudo lsof -nPli > ~/liveresponse/lsof_network.txt
sudo lsof -U > ~/liveresponse/lsof_unix_sockets.txt
# Login session history (reads utmpx/wtmp)
last > ~/liveresponse/last.txt
# Live file-system activity trace — NOTE: this is a timed capture, not an instant
# snapshot; run for a bounded window (e.g. `timeout 30 fs_usage ...`) since it
# streams continuously and will not exit on its own
sudo fs_usage -w -f filesys > ~/liveresponse/fs_usage.txt &
sleep 30 && kill %1
```

> Added 2026-08-21 (`last`, `fs_usage`) per [UAC](https://github.com/tclahr/uac)'s live_response collector definitions (`artifacts/live_response/system/last.yaml`, `artifacts/live_response/storage/fs_usage.yaml`), unverified against a live system.

### D.2 System & Kernel State

**BASH — SYSTEM & KERNEL LIVE COLLECTION**

```bash
# SIP status
csrutil status > ~/liveresponse/csrutil.txt
# NVRAM (SIP flags, boot-args, recovery state)
nvram -p > ~/liveresponse/nvram.txt
# Kernel extensions
kextstat > ~/liveresponse/kextstat.txt
# All loaded launchd services
sudo launchctl list > ~/liveresponse/launchctl_list.txt
# I/O Registry (USB devices, hardware topology)
sudo ioreg -l > ~/liveresponse/ioreg.txt
# System overview
system_profiler > ~/liveresponse/system_profiler.txt
hostinfo > ~/liveresponse/hostinfo.txt
sw_vers > ~/liveresponse/sw_vers.txt
sysctl -a > ~/liveresponse/sysctl.txt
# Virtual memory / swap pressure statistics
vm_stat > ~/liveresponse/vm_stat.txt
# Kernel ring buffer (hardware/driver/panic evidence)
dmesg > ~/liveresponse/dmesg.txt
```

> Added 2026-08-21 (`vm_stat`, `dmesg`) per [UAC](https://github.com/tclahr/uac)'s live_response collector definitions (`artifacts/live_response/system/vm_stat.yaml`, `artifacts/live_response/hardware/dmesg.yaml`), unverified against a live system.

### D.3 Storage & Volume State

**BASH — STORAGE LIVE COLLECTION**

```bash
# Disk and volume topology
diskutil list > ~/liveresponse/diskutil_list.txt
# Mounted volume sizes
df -h > ~/liveresponse/df.txt
# Time Machine backup state
tmutil listbackups > ~/liveresponse/tm_backups.txt
tmutil machinedirectory > ~/liveresponse/tm_directory.txt
tmutil listlocalsnapshots / > ~/liveresponse/tm_snapshots.txt
tmutil listlocalsnapshotdates / > ~/liveresponse/tm_snapshot_dates.txt
# DNS / network config
scutil --dns > ~/liveresponse/scutil_dns.txt
scutil --proxy > ~/liveresponse/scutil_proxy.txt
```

### D.4 Package & Software Inventory

**BASH — PACKAGE INVENTORY**

```bash
# Apple installer packages
pkgutil --packages > ~/liveresponse/pkgutil_packages.txt
# Software update history
softwareupdate --history --all > ~/liveresponse/softwareupdate_history.txt
# Homebrew (if installed)
which brew && brew list --versions > ~/liveresponse/brew_list.txt
which brew && brew leaves > ~/liveresponse/brew_leaves.txt
# Running applications (LaunchServices)
lsappinfo list > ~/liveresponse/lsappinfo.txt
# Applications directories
ls -la /Applications > ~/liveresponse/applications_system.txt
ls -la ~/Applications 2>/dev/null > ~/liveresponse/applications_user.txt
```

### D.5 EDR / Security Tool State

**BASH — EDR STATE COLLECTION**

```bash
# CrowdStrike Falcon (if installed)
test -f /Applications/Falcon.app/Contents/Resources/falconctl && {
sudo /Applications/Falcon.app/Contents/Resources/falconctl info > ~/liveresponse/falcon_info.txt
sudo /Applications/Falcon.app/Contents/Resources/falconctl stats > ~/liveresponse/falcon_stats.txt
}
# Microsoft Defender for Endpoint (if installed)
which mdatp && {
mdatp health > ~/liveresponse/mdatp_health.txt
mdatp exclusion list > ~/liveresponse/mdatp_exclusions.txt
mdatp threat list > ~/liveresponse/mdatp_threats.txt
}
```

> **EDR Exclusions — Potential Attacker Manipulation**
>
> mdatp exclusion list and equivalent Falcon exclusion queries are high-value findings. Attackers who gain sufficient privileges may add exclusions for their tooling paths or processes to blind the EDR. Any exclusion not traceable to a legitimate IT change-management record warrants investigation.

*— End of Document —*

*Document Version 1.9 | Updated May 2026 | Additions: UAC alignment review, Biome dual-path correction, third-party messaging (§8.6), shell history (Appendix C), SSH artifacts (Appendix C), live response reference (Appendix D), Homebrew/pkgutil inventory, EDR state collection*
