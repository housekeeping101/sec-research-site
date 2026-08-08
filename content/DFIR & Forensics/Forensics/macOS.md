- A very defender-useful artifact: Apple notes that when a launch is blocked due to a constraint violation, **a crash report is generated indicating the constraint was violated**.
	- https://developer.apple.com/videos/play/wwdc2023/10266/
- https://theevilbit.github.io/posts/launch_constraints_deep_dive/
- https://blog.xpnsec.com/bypassing-macos-privacy-controls/


 - Safari downloads files through
	- com.apple.Safari.SandboxBroker XPC process
	
# **macOS Detection Cheat Sheet**

## **TCC Bypass & XPC Exploitation (EXP-312)**

---

## **1. TCC (Transparency, Consent, and Control) Bypass**

  

### **Purpose of TCC**

  

Controls app access to protected resources:

- Camera
    
- Microphone
    
- Screen Recording
    
- Full Disk Access
    
- Accessibility
    

  

Attackers attempt to bypass TCC to gain **silent access** to these resources.

---

### **Key TCC Artifacts (Paths)**

```
/System/Library/PrivateFrameworks/TCC.framework
```

```
/Library/Application Support/com.apple.TCC/TCC.db
~/Library/Application Support/com.apple.TCC/TCC.db
```

```
/com.apple.tccd (daemon)
```

---

### **High-Value TCC Services**

```
kTCCServiceCamera
kTCCServiceMicrophone
kTCCServiceScreenCapture
kTCCServiceAccessibility
kTCCServiceSystemPolicyAllFiles
```

---

### **Processes That Normally Touch TCC**

  

**Expected / Low Noise**

```
System Settings
tccd
security
launchservicesd
softwareupdated
```

**Commonly Abused Apple-Signed Proxies**

```
coreaudiod
mdworker
mdworker_shared
QuickLookSatellite
VTDecoderXPCService
avconferenced
PhotoLibraryServices
```

---

### **Detection Ideas (TCC)**

  

#### **🚩 Non-GUI Process Requesting TCC Access**

```
Process requests Camera/Microphone
AND no active UI / window focus
AND NOT System Settings
```

---

#### **🚩 TCC Database File Access**

```
FileWrite or FileRead
TargetFile CONTAINS TCC.db
Image != tccd
```

---

#### **🚩 Trusted Apple Process Spawning Unsigned Child**

```
Parent IN (coreaudiod, mdworker, QuickLookSatellite)
AND Child NOT Apple-signed
```

---

#### **🚩 Screen Recording from Non-Standard App**

```
TCCService = ScreenCapture
AND Image NOT IN (zoom, slack, teams, browsers)
```

---

### **Useful Local Commands (Triage)**

```
# Inspect TCC permissions (read-only)
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"select service, client, auth_value from access;"
```

```
# Live TCC-related logs
log stream --predicate 'subsystem == "com.apple.TCC"'
```

---

### **MITRE Mapping (TCC)**

```
T1123 – Audio Capture
T1125 – Video Capture
T1056 – Input Capture
T1555 – Credential Access
```

---

## **2. XPC Exploitation & Privileged Helper Abuse**

  

### **Purpose of XPC**

  

Inter-process communication mechanism heavily used by macOS.

  

Attackers exploit:

- Weak input validation
    
- Over-privileged helpers
    
- Exposed MachServices
    

---

### **Key XPC & Privilege Artifacts (Paths)**

```
/Library/LaunchDaemons/*.plist
/Library/PrivilegedHelperTools/
```

```
MachServices (LaunchDaemon plist key)
SMJobBless
```

---

### **Normal vs Suspicious XPC Patterns**

  

**Normal**

```
App → Helper
Same Team ID
Signed binaries
Limited arguments
```

**Suspicious**

```
Shell → MachService
Unsigned caller
Helper executing shell commands
Helper writing arbitrary paths
```

---

### **Detection Ideas (XPC)**

  

#### **🚩 User Shell Talking to Privileged Helper**

```
Parent IN (zsh, bash, sh)
AND TargetPath CONTAINS /PrivilegedHelperTools/
```

---

#### **🚩 LaunchDaemon MachService Changes**

```
LaunchDaemon modified
AND MachServices key added or changed
```

---

#### **🚩 Privileged Helper Spawning a Shell**

```
ParentPath CONTAINS /PrivilegedHelperTools/
AND Child IN (sh, bash, zsh, python, perl)
```

---

#### **🚩 SMJobBless Without Installer Flow**

```
SMJobBless invoked
AND no pkg or installer execution
```

---

#### **🚩 Helper Writing to High-Risk Locations**

```
Parent = PrivilegedHelperTool
AND FileWrite TO (/Applications, /Library, /etc)
```

---

### **Useful Local Commands (Triage)**

```
# List privileged helper tools
ls -l /Library/PrivilegedHelperTools/
```

```
# Inspect MachServices exposed by LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist | grep MachServices
```

```
# Code signing info
codesign -dv --verbose=4 <binary>
```

---

### **MITRE Mapping (XPC)**

```
T1068 – Privilege Escalation
T1543.004 – Launch Daemon
T1106 – Native API
T1059 – Command Execution
```

---

## **3. smd (Service Management Daemon) & Background Task Management**

  

### **Purpose of smd / BTM**

  

`/usr/libexec/smd` backs Apple's `ServiceManagement` framework (`SMLoginItemSetEnabled`, `SMAppService`, `SMJobBless`/`SMJobSubmit`). It registers **login items** and **helper launch agents/daemons** that apps install to persist across reboots/logins.

  

Since Ventura, `smd` drives **Background Task Management (BTM)** — the subsystem behind *System Settings → General → Login Items* and the "'X' was added as a login item" user notification. BTM logs registration events even if the LaunchAgent/Daemon plist is later deleted, making it a durable persistence artifact.

  

Attackers abuse it by registering LaunchAgents/Daemons or login items via `SMAppService`/`SMLoginItemSetEnabled` (or by dropping plists directly) to survive reboot without user interaction.

---

### **Key smd / BTM Artifacts (Paths)**

```
/usr/libexec/smd
```

```
/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm
~/Library/Application Support/com.apple.backgroundtaskmanagement/
```

```
~/Library/LaunchAgents/*.plist
/Library/LaunchAgents/*.plist
/Library/LaunchDaemons/*.plist
```

---

### **Detection Ideas (smd / BTM)**

  

#### **🚩 New LaunchAgent/Daemon Registered Outside Installer Flow**

```
FileCreate on ~/Library/LaunchAgents/*.plist or /Library/Launch{Agents,Daemons}/*.plist
AND Parent NOT IN (installer, softwareupdated, Self Service, known MDM agent)
```

---

#### **🚩 BTM Database Written Without Corresponding User-Visible Notification**

```
Write to BackgroundItems-v4.btm
AND no UserNotificationCenter event for "login item added"
```

---

#### **🚩 Login Item Registered via Script/CLI Rather Than GUI App**

```
Caller IN (osascript, python, bash, zsh)
AND API call = SMLoginItemSetEnabled / SMAppService.register
```

---

#### **🚩 LaunchAgent Plist Removed Shortly After BTM Registration (Cleanup Evasion)**

```
BTM registration event for plist X
FOLLOWED BY FileDelete of plist X within short window
```

---

### **Useful Local Commands (Triage)**

```
# List all managed background items (login items, agents, daemons)
sfltool dumpbtm
```

```
# Live smd / BTM logs
log show --predicate 'process == "smd"' --last 1d
log stream --predicate 'subsystem == "com.apple.backgroundtaskmanagement"'
```

```
# Enumerate current LaunchAgents/Daemons on disk
ls -la ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons
```

---

### **MITRE Mapping (smd / BTM)**

```
T1543.001 – Launch Agent
T1543.004 – Launch Daemon
T1547 – Boot or Logon Autostart Execution
```

---

## **4. High-Fidelity Attack Chains**

  

### **TCC + XPC Proxy Abuse**

```
User App / Shell
→ XPC Helper
→ Apple-Signed Proxy Process
→ TCC Grant
→ Mic / Camera Access
```

---

### **Persistence + LPE Chain**

```
LaunchDaemon Installed
→ PrivilegedHelperTool Dropped
→ MachService Invoked from User Context
→ Root Code Execution
```

---

## **Notes**

- Apple increasingly blocks direct TCC DB writes (Ventura+)
    
- Modern malware favors **proxy execution** via trusted daemons
    
- XPC helper abuse remains one of the **highest ROI LPE paths** on macOS
    

---

# **✅ Enhancements**

  

## **A. Noise considerations / allowlists**

  

### **TCC: recommended allowlist seeds (tune per fleet)**

  

**Common legit clients requesting Camera/Mic/ScreenCapture**

```
zoom.us
com.microsoft.teams
com.apple.FaceTime
com.google.Chrome
org.mozilla.firefox
com.apple.Safari
com.tinyspeck.slackmacgap
us.zoom.xos
```

**Legit Apple-signed proxies that can create noise**

```
coreaudiod
avconferenced
VTDecoderXPCService
QuickLookSatellite
mdworker
mdworker_shared
```

**Practical tuning tips**

- Prefer **denylist logic**: alert on sensitive services from **uncommon clients**.
    
- Suppress if the client is **UI-active** (foreground app) and **signed + notarized**.
    
- Separate detections by service:
    
    - ScreenCapture is typically lower volume → easier to alert.
        
    - Full Disk Access is high-impact → treat any anomaly as high priority.
        
    

---

### **XPC: recommended allowlist seeds (tune per fleet)**

  

**Expected privileged helper ecosystems**

```
com.microsoft.autoupdate.helper
com.google.Keystone.daemon
com.adobe.ARMDC.Communicator
com.apple.installer.osinstallersetupd
```

**Tuning tips**

- Alert only when **caller** is user-controlled (shell, scripting engines, unsigned apps).
    
- Alert on helpers that **spawn shells** or run:
    
    - /usr/sbin/installer
        
    - /bin/chmod, /usr/sbin/chown
        
    - /bin/launchctl
        
    

---

## **B. Falcon LogScale query snippets (pseudo-fielded)**

  

> ⚠️ Field names vary by repo (base_sensor vs custom). Treat these as patterns to adapt.

  

### **TCC: suspicious TCC.db access**

```
#event_simpleName=FileWrite OR #event_simpleName=FileOpen
| where FilePath =~ /TCC\.db$/i
| where ImageFileName != "tccd"
| groupBy([aid, ComputerName, UserName, ImageFileName, ParentBaseFileName, FilePath], function=count())
```

### **TCC: proxy processes requesting protected services (concept)**

```
#event_simpleName IN ("ProcessRollup2","TCCAccessRequest")
| where ImageFileName in ("coreaudiod","mdworker","mdworker_shared","QuickLookSatellite","VTDecoderXPCService")
| groupBy([aid, ComputerName, UserName, ImageFileName, CommandLine], function=count())
```

### **XPC: shell → privileged helper pattern**

```
#event_simpleName=ProcessRollup2
| where ParentBaseFileName in ("zsh","bash","sh")
| where ImageFileName =~ /\/Library\/PrivilegedHelperTools\//
| groupBy([aid, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine], function=count())
```

### **XPC: privileged helper spawning a shell / script engine**

```
#event_simpleName=ProcessRollup2
| where ParentImageFileName =~ /\/Library\/PrivilegedHelperTools\//
| where ImageFileName in ("sh","bash","zsh","python","perl","ruby","osascript")
| groupBy([aid, ComputerName, UserName, ParentImageFileName, ImageFileName, CommandLine], function=count())
```

### **XPC: LaunchDaemon plist modified**

```
#event_simpleName IN ("FileWrite","FileCreate")
| where FilePath =~ /^\/Library\/LaunchDaemons\/.+\.plist$/i
| groupBy([aid, ComputerName, UserName, ImageFileName, FilePath], function=count())
```

---

## **C. Obsidian split into two notes + backlinks + tags**

  

> Copy the blocks below into **two separate files** in your vault.

---

## **Note 1: macOS TCC Bypass Detection**

```
---
tags: [macos, detection, tcc, privacy, hunt]
---

# macOS TCC Bypass Detection

Backlinks:
- [[macOS XPC Exploitation Detection]]
- [[macOS Detection Index]]

## Key Paths
- /Library/Application Support/com.apple.TCC/TCC.db
- ~/Library/Application Support/com.apple.TCC/TCC.db

## High-Value Services
- kTCCServiceCamera
- kTCCServiceMicrophone
- kTCCServiceScreenCapture
- kTCCServiceAccessibility
- kTCCServiceSystemPolicyAllFiles

## Expected Touch Points
- tccd
- System Settings
- security

## Commonly Abused Apple Proxies
- coreaudiod
- mdworker / mdworker_shared
- QuickLookSatellite
- VTDecoderXPCService

## Detections
### 1) Non-GUI requesting camera/mic
### 2) TCC.db touched by non-tccd
### 3) Apple proxy spawns unsigned child
### 4) ScreenCapture from uncommon client

## Commands
- sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db "select service, client, auth_value from access;"
- log stream --predicate 'subsystem == "com.apple.TCC"'

## References / Appendix
- See [[Real-World macOS TCC & XPC Abuse (2023–2025)]]
```

---

## **Note 2: macOS XPC Exploitation Detection**

```
---
tags: [macos, detection, xpc, lpe, launchd, hunt]
---

# macOS XPC Exploitation Detection

Backlinks:
- [[macOS TCC Bypass Detection]]
- [[macOS Detection Index]]

## Key Paths
- /Library/LaunchDaemons/*.plist
- /Library/PrivilegedHelperTools/

## Key Concepts
- MachServices
- SMJobBless

## Detections
### 1) Shell talking to privileged helper
### 2) MachServices drift in LaunchDaemons
### 3) Helper spawning shell/script engine
### 4) Helper writing to /Library /etc /Applications
### 5) SMJobBless without installer flow

## Commands
- ls -l /Library/PrivilegedHelperTools/
- plutil -p /Library/LaunchDaemons/*.plist | grep MachServices
- codesign -dv --verbose=4 <binary>

## References / Appendix
- See [[Real-World macOS TCC & XPC Abuse (2023–2025)]]
```

---

## **Note 3: macOS Detection Index (optional)**

```
---
tags: [macos, detection, index]
---

# macOS Detection Index

- [[macOS TCC Bypass Detection]]
- [[macOS XPC Exploitation Detection]]
- [[Real-World macOS TCC & XPC Abuse (2023–2025)]]
```

---

## **D. Real-World macOS TCC & XPC Abuse (2023–2025)**

  

> Use this as an appendix note: **[[Real-World macOS TCC & XPC Abuse (2023–2025)]]**

  

### **TCC bypass themes seen in modern research**

- **Spotlight importer / plugin-based access** to protected file content via TCC weaknesses.
    
- **FileProvider / iCloud access** paths that bypass user prompts.
    
- **Abusing trusted Apple-signed processes** as proxies for microphone/camera access.
    

  

### **Example cases to anchor detections**

- **“Sploitlight” (Spotlight importer plugin / TCC data exposure)**
    
    - Detection anchor: mdworker / importer plugin execution → unusual file reads/exfil.
        
    - Defensive focus: importer plugin directories, Spotlight-related process trees.
        
    
- **CVE-2024-44131 (FileProvider / TCC bypass for sensitive data)**
    
    - Detection anchor: FileProvider-related access paths + sensitive data reads without UI.
        
    - Defensive focus: abnormal access to iCloud-synced content from non-UI processes.
        
    
- **TCC bypasses in third-party macOS applications (coordinated disclosures)**
    
    - Detection anchor: app-specific helpers or plugins accessing protected resources.
        
    - Defensive focus: watch for newly installed/upgraded apps exposing new helpers.
        
    

  

### **XPC / helper exploitation themes in modern research**

- **Unvalidated XPC client checks** (missing audit-token validation / entitlement checks).
    
- **Helpers that invoke /usr/sbin/installer** on attacker-controlled packages.
    
- **Over-privileged services exposing file write or command execution primitives.**
    

  

### **Example cases to anchor detections**

- **GOG Galaxy XPC privilege escalation (third-party app helper abuse)**
    
    - Detection anchor: userland caller triggers privileged XPC → root actions.
        
    - Defensive focus: shell/script parents calling helper + installer/chmod/chown.
        
    
- **Unvalidated XPC clients leading to LPE patterns**
    
    - Detection anchor: helper accepts requests from unexpected callers.
        
    - Defensive focus: require caller identity checks (audit token) in app reviews; detect in runtime via process ancestry.
        
    

---

## **E. Quick “What to collect” checklist (SOC)**

  

### **Endpoint process telemetry**

- Process starts: parent/child, code signing, Team ID (if available), command line
    
- Script execution: osascript, python, bash/zsh, AppleScript
    

  

### **File telemetry**

- TCC.db reads/writes
    
- /Library/LaunchDaemons/*.plist changes
    
- /Library/PrivilegedHelperTools/ creations/modifications
    

  

### **Unified logs (when available)**

- subsystem: com.apple.TCC
    
- launchd / service management events
    

---
https://www.sentinelone.com/blog/session-cookies-keychains-ssh-keys-and-more-7-kinds-of-data-malware-steals-from-macos-users/

```
~/Library/Cookies/*.binarycookies

Chrome:  ~/Library/Application Support/Google/Chrome/Default/Cookies
Firefox: ~/Library/Application Support/Firefox/Profiles/[Profile Name]/
Slack :  ~/Library/Application Support/Slack/Cookies (file) 
	 ~/Library/Application Support/Slack/storage/*
         ~/Library/Containers/com.tinyspeck.slackmacgap/Data/Library/Application Support/Slack/storage
```
