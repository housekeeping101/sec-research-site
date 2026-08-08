#runAtLoad
```
index=crowdstrike_fdr RunAtLoad NOT jamfhelper
| table CommandLine ImageFileName ParentBaseFileName aid shortid
| stats count by CommandLine
```

#MacLogin
```
security find-certificate -a -p /Users/USERNAME/Library/Keychains/login.keychain
```

```
login -fp USERNAME
```

```
/usr/bin/security authorizationdb read system.login.screensaver
```

 ```"CSSMERR_TP_CERT_REVOKED" OR "com.apple.quarantine" OR "xattr -rc"```
 Remove extended attribute and bypass Gatekeeper and XProtect
 - xattr -rc


cp 

crontab

at

LSSharedFileList
LSSharedFileListInsertItemURL
LSSharedFileListCreate

 SystemUIServer
 /usr/sbin/screencapture
 /usr/sbin/screencapture -pdi -z keyboard.selection
 
 xpcproxy com.apple.screencaptureui.agent
 /System/Library/CoreServices/screencaptureui.app/Contents/MacOS/screencaptureui

---
### **A. Detect “launchd parent, unexpected responsible process”**

**Goal:** When PPID is launchd (common), pivot to “responsible” to understand _who_ initiated.

Detection idea:
- ParentBaseFileName = "launchd"
- “Responsible process” is **Terminal**, **bash/zsh**, **osascript**, **python**, etc., but the child is a **GUI app**, **privileged helper**, or **XPC service** that shouldn’t be invoked that way.
    
**Hunt pattern (pseudo-CQL):**
```
#repo=base_sensor #event_simpleName=ProcessRollup2
| where ParentBaseFileName="launchd"
| where ResponsibleBaseFileName in ("Terminal","iTerm2","zsh","bash","osascript","python3","curl","wget")
| where ImageFileName=/(?i)(\.app\/Contents\/MacOS\/|XPCServices\/|LaunchAgents\/|LaunchDaemons\/)/
| select @timestamp, aid, ComputerName, ImageFileName, CommandLine,
         ParentBaseFileName, ResponsibleBaseFileName, ResponsibleProcessId
```

### **B. Detect direct execution of helper tools that “shouldn’t run from Terminal”**
Apple’s example shows a helper tool that _used_ to run from Terminal but is blocked after adding constraints. 

So before/without constraints, attacker behavior often looks like:
- userland shell invoking an embedded helper directly
- helper accepts “privileged mode” args (e.g., --cloud in the WWDC demo)
```
#repo=base_sensor #event_simpleName=ProcessRollup2
| where CommandLine=/(?i)(\/Contents\/MacOS\/|\/Library\/PrivilegedHelperTools\/).+(\s--| -).+/
| where ParentBaseFileName in ("zsh","bash","sh","Terminal","iTerm2")
| select @timestamp, ComputerName, ImageFileName, CommandLine, ParentBaseFileName
```

### **C. Detect constraint violations via DiagnosticReports (high-signal)**
- Because Apple says a **crash report is generated** when a launch is blocked by a constraint, you can hunt for creation of crash logs that reference constraint violations.

```
#repo=base_sensor (#event_simpleName=FileCreate OR #event_simpleName=FileWrite OR #event_simpleName=FileRename)
| where TargetFileName=/(?i)\/(Library|Users\/[^\/]+\/Library)\/Logs\/DiagnosticReports\/.+\.crash$/
| where FileContents=/(?i)(launch constraint|environment constraint|SpawnConstraint|responsible process constraint)/
| select @timestamp, ComputerName, TargetFileName, InitiatingProcessFileName, InitiatingCommandLine
```
- (If you don’t have file-content visibility, still alert on bursty .crash creation in those paths, then pivot to the process tree.)
### **D. Correlate “responsibility mismatch” to persistence attempts**
Because SpawnConstraint is specifically meant to make user-approved background items “have teeth” and detect changes, you can alert on:
- modifications to LaunchAgent/Daemon plists + changes to the referenced Program/ProgramArguments
- followed by execution where responsibility is suspicious
**Hunt pattern (two-step correlation):**
1. LaunchAgent plist change:
```
#repo=base_sensor (#event_simpleName=FileWrite OR #event_simpleName=FileRename)
| where TargetFileName=/(?i)\/(Library|Users\/[^\/]+\/Library)\/Launch(Agents|Daemons)\/.+\.plist$/
```
2. Followed by execution of the referenced binary with odd responsible process (use query A ideas).
---

- opendirectoryd events
-  Safari downloads files through
	- com.apple.Safari.SandboxBroker XPC process
	
  - "signing_id":"com.apple.backgroundtaskmanagementd"
