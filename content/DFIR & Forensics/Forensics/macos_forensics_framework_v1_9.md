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

- Main store location: /.Spotlight-V100/Store-V2/

- User-level: ~/Library/Metadata/CoreSpotlight/

- Contains: file names, content snippets, metadata, application associations, timestamps

- Useful for: proving a file existed even after deletion, identifying user searches

Use mdls <filename> to inspect all Spotlight-indexed metadata for a specific file, or mdimport -t -d2 <filename> to see what the mdimporter for that file type would extract. Note: mdimport has been known to crash on macOS Sonoma and later — mdls is the more reliable option for field use.

### 4.5 Recent Items & Launch Services

#### 4.5.1 Recent Applications, Documents & Servers

Stored in: ~/Library/Application Support/com.apple.sharedfilelist/

These SFL2 (Shared File List) binary files record recently accessed applications, documents, and servers. They can be parsed with tools such as sflparser or mac_apt's RECENTFILES plugin.

#### 4.5.2 Dock Plist

Location: ~/Library/Preferences/com.apple.dock.plist

Records pinned applications and recently used apps. Modifications to this file may indicate installed applications that have since been removed.

#### 4.5.3 Spotlight Shortcuts

Location: ~/Library/Application Support/com.apple.spotlight.Shortcuts

Records terms the user has searched and launched via Spotlight, with timestamps. Useful for establishing what a user was actively searching for during an incident timeframe.

### 4.6 Saved Application State

Location: ~/Library/Saved Application State/

Per-app bundles storing window state, open documents, scroll positions, and UI context from the last session. Named <bundle-id>.savedState. Useful for reconstructing exactly what a user had open in an application at the time of their last session — a complement to KnowledgeC app usage data.

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

## 6. Phase 4 — Network & Communications Artifacts

### 6.1 Network Configuration & History

- Known Wi-Fi networks: /Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist — includes SSID, timestamps of last connection, and sometimes geolocation data

- IntelligencePlatform wifiContextEvents: ~/Library/IntelligencePlatform/views.db — see Section 4.3.1 for full coverage

- DHCP leases: /private/var/db/dhcpclient/leases/ — records IP address assignments with timestamps

- VPN configuration: /Library/Preferences/SystemConfiguration/preferences.plist

- Hosts file modifications: /etc/hosts — check for evidence of DNS spoofing or C2 evasion

- Network app usage: /private/var/networkd/db/netusage.sqlite — per-process byte counts with timestamps

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

### 6.8 Unified Logs — Network Events

The Unified Logging system (introduced in macOS 10.12) is an extremely rich source of network-related forensic evidence. Key subsystems to query:

- com.apple.networkd — network connection establishment and teardown

- com.apple.nsurlsessiond — URL session activity (downloads, API calls)

- com.apple.firewall — application firewall decisions

- com.apple.configd — network configuration changes

Use the log command-line tool or Console.app to query Unified Logs. Note: live logs are stored in /var/db/diagnostics/ but require macOS tools to parse correctly.

## 7. Phase 5 — System & Security Artifacts

### 7.1 Unified Logs — Overview

The Unified Logging system replaced ASL (Apple System Log) and syslog in macOS 10.12 Sierra. It is the primary source of system-level forensic evidence on modern macOS systems.

| Detail | Value |
|----|----|
| Live log location | /var/db/diagnostics/ (tracev3 binary format) |
| Archive location | /var/db/uuidtext/ |
| Retention | Varies; typically 7 days of fine-grained logs, longer for compressed archives. Logs cycle quickly — collect rapidly. |
| Parsing tool | log (built-in CLI), Ulbow (GUI), mac_apt UNIFIEDLOGS plugin |

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

- XProtect detection events: /Library/Logs/DiagnosticReports/ and Unified Logs, subsystem com.apple.XProtect

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

In macOS 26, Clipboard History maintains a persistent, searchable log of recently copied items, integrated with Spotlight.

| Detail | Value |
|----|----|
| Expected location | ~/Library/Application Support/com.apple.ClipboardHistory/ (preliminary — validate on live system) |
| Format | SQLite or binary plist — confirm with direct inspection post-acquisition |
| Spotlight index | ~/Library/Metadata/CoreSpotlight/ (entries may persist here after clipboard clear) |
| Tool support | Emerging — validate that your toolset has been updated for Tahoe before relying on automated parsing |

- May contain copied text, document excerpts, command-line output, URLs, passwords, and code snippets

- Provides direct evidence of user intent — what a user deliberately copied is often more probative than what was merely opened

- Could reveal staged data prior to exfiltration (copied credentials, internal documents)

- Because it is Spotlight-indexed, residual evidence may persist in Spotlight's metadata stores even after manual clearing

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
```

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
```

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
