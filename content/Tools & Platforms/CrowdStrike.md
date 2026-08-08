
## Domain name parsing
https://www.reddit.com/r/crowdstrike/s/u1guiDWxI2
```
| function.domain:=getField(?field) | function.domain="*"
| function.domain.tld:=splitString(function.domain, by="\\.", index=-1) | function.domain.sld:=splitString(function.domain, by="\\.", index=-2)
| case { function.domain=/\..+\./ | function.registered_domain:=splitString(function.domain, by="\\.", index=-3); * }
| case {
    test(length(function.domain.tld) < 3) | function.domain.sld=/^([a-z]{2}|com|org|gov|net|biz)$/ function.domain.sld!=/^(fb|id|hy|ex)$/
      | function.registered_domain:=format("%s.%s.%s", field=[function.registered_domain, function.domain.sld, function.domain.tld]);
  * | function.registered_domain:=format("%s.%s", field=[function.domain.sld, function.domain.tld])}
| drop([function.domain, function.domain.tld, function.domain.sld])
```



https://www.reddit.com/r/crowdstrike/s/3XLgDabMBf
```
#event_simpleName="MotwWritten"
// ### Make sure a URL exists in the log entry
| (( HostUrl="*" HostUrl!="" ) OR ( ReferrerUrl="*" ReferrerUrl!="" ))

// ### Extract the registered domain from the URL
// ### See last week's post for the user-function stuff
| parseurl(HostUrl)
| $get-registered_domain(field=HostUrl.host) 
| url.registered_domain:=function.registered_domain

// ### Extract the registered domain from the Referrer URL
| parseurl(ReferrerUrl) 
| $get-registered_domain(field=ReferrerUrl.host) 
| url.referrer.registered_domain:=function.registered_domain

// ### Check to see if either domain is in the NRD list
| case {
    match("domain-nrd7.csv", field=url.registered_domain, column=indicator.name);
    match("domain-nrd7.csv", field=url.referrer.registered_domain, column=indicator.name);
    }
```

## Webshell
https://www.reddit.com/r/crowdstrike/s/Whn4cXhqwS
```
#event_simpleName = FileOpenInfo
| join({#event_simpleName=ProcessRollup2 and FileName = w3wp.exe}, field=ContextProcessId, key=TargetProcessId, include=[FileName])
| select([@timestamp, ComputerName, FileName, TargetFileName])
```

## Dotnet modules

https://www.reddit.com/r/crowdstrike/s/zKRBOwiTOO
```
#event_simpleName = DotnetModuleLoadDetectInfo OR #event_simpleName = ReflectiveDotnetModuleLoad
| ImageFileName = "*w3wp.exe"
| select([@timestamp, ComputerName, ModuleILPath])

// some modules you don’t want to see
| in(field=ModuleILPath, values=[ExecuteAssembly, FileList, DeadPotato, Information, SharpToken])
```

## Process run time
```
(#event_simpleName=ProcessRollup2 ImageFileName=/\\powershell(_ise)?\.exe/i) OR (#event_simpleName=EndOfProcess event_platform=Win CLICreationCount>0)
| selfJoinFilter([aid, TargetProcessId], where=[{#event_simpleName=ProcessRollup2}, {#event_simpleName=EndOfProcess}], prefilter=true)
| regex(".+\\\(?<FileName>.+$)", field=ImageFileName, strict=false)
| groupBy([aid, TargetProcessId], function=([count(#event_simpleName, distinct=true, as=eventCount), min(ProcessStartTime, as=processStartTime), max(ContextTimeStamp, as=processEndTime), collect([CLICreationCount, FileName])]))
| test(eventCount==2)
| processStartTime := processStartTime*1000
| processEndTime := processEndTime*1000
| runTime := processEndTime-processStartTime
| formatDuration(runTime, from=ms, precision=4, as=programRunTime)
| formatTime(format="%F %T.%L", field=processStartTime, as="processStartTime")
| formatTime(format="%F %T.%L", field=processEndTime, as="processEndTime")
| drop([eventCount, runTime])
```


## Autorun or ASEP Registry Key Modification

```
event_platform=Win
| in(field=#event_simpleName,values=["RegGenericValueUpdate","RegSystemConfigValueUpdate","RegistryOperationDetectInfo","SuspiciousRegAsepUpdate","AsepValueUpdate"])
| case{ RegBinaryValue ="*" | RegValueData:=RegBinaryValue; RegStringValue="*" | RegValueData:=RegStringValue; RegNumericValue="*" | RegValueData:=RegNumericValue;}
| RegObjectName=/\\software\\Microsoft\\Windows\\CurrentVersion\\Run|\\software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Run|\\software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Run|\\software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run|\\software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\(User Shell Folders|Shell Folders)|\\software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit|\\software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell|\\software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs|\\software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs|\\software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Load|\\software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Load|\\software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run/i
| !RegValueName=/\\Microsoft Visual Studio\\Installer\\|\\ClickToRun\\OfficeClickToRun.exe|\\software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell|\\Microsoft\\OneDrive\\|\\Windows\\system32\\SearchIndexer.exe|\\Microsoft\\Teams\\|\\Microsoft\\Edge\\Application\\/i
| format(format="[PID:%s]\n[Obj]%s\n\t↪[Name]%s\n\t\t↪[Value]%s\n----", field=[ContextProcessId,RegObjectName, RegValueName, RegValueData], as="registryKey_Object_Data")
| groupBy([ComputerName],function=([count(aid, as=executeCount), min(@timestamp, as=firstSeen), max(@timestamp, as=lastSeen), collect([UserName,registryKey_Object_Data,ImageFileName,TargetCommandLineParameters,TargetFileName,RegObjectName,RegValueName,RegBinaryValue,RegStringValue,RegNumericValue,ContextProcessId], limit=1000)]))
| firstSeen:=formatTime(field=firstSeen, format="%Y/%m/%d %H:%M:%S")
| lastSeen:=formatTime(field=lastSeen, format="%Y/%m/%d %H:%M:%S")
```

## Methods for Downloading Files with PowerShell - ScriptBlock Logging
```
// Cyborg Hunter Link: https://hunter.cyborgsecurity.io/research/hunt-package/c7b320fb-ac67-45b0-92c4-b0f1e10b4e46
in(#event_simpleName, values=["ScriptControlScanInfo","ScriptControlDetectInfo"])
| event_platform=Win
| HostProcessType=/1|2/
| ScriptContent = /Invoke-WebRequest| iwr|curl|wget|Invoke-RestMethod| irm|Start-BitsTransfer| sbt|System.Net.WebClient|System.Net.Http.HttpClient/i
// CHANGE ME to your base URL for Process and Graph Explorer Links
| rootURL := "https://falcon.us-2.crowdstrike.com/"
// Gather Context Process ID if available, otherwise use TargetProcess ID
| case{ ContextProcessId ="*" | ContextId:=ContextProcessId; TargetProcessId="*" | ContextId:=TargetProcessId}
// Create URL structure for Process and Graph Explorer Links
| format("[ProcessExplorer]%sinvestigate/process-explorer/%s/%s?_cid=%s", field=["rootURL", "aid", "ContextId", "cid"], as="ProcessExplorer")
| format("[GraphExplorer]%sgraphs/process-explorer/graph?id=pid:%s:%s", field=["rootURL", "aid", "TargetProcessId"], as="GraphExplorer")
// Format Friendly Field Values
| case{ ScriptContentSource = 0 | ScriptContentSourceFriendly:="Inconclusive"; ScriptContentSource=1 | ScriptContentSourceFriendly:="File"; ScriptContentSource=2 | ScriptContentSourceFriendly:="Command"; ScriptContentSource=3 | ScriptContentSourceFriendly:="EncodedCommand"; ScriptContentSource=4 | ScriptContentSourceFriendly:="STDIN"; ScriptContentSource=5 | ScriptContentSourceFriendly:="Dynamic"; ScriptContentSource=6 | ScriptContentSourceFriendly:="Interactive" }
| case{ HostProcessType = 0 | HostProcessTypeFriendly:="Others"; HostProcessType=1 | HostProcessTypeFriendly:="PowerShell"; HostProcessType=2 | HostProcessTypeFriendly:="PowerShellISE"; HostProcessType=3 | HostProcessTypeFriendly:="WScript"; HostProcessType=4 | HostProcessTypeFriendly:="CScript"; HostProcessType=5 | HostProcessTypeFriendly:="OfficeEXE" }
// Create Execution Summary Information
| format(format="[ScriptSourceType]->%s\n[HostProcessType]->%s\n\t%s\n\t%s\n---", field=[ScriptContentSourceFriendly, HostProcessTypeFriendly, ProcessExplorer, GraphExplorer], as="ExecutionSummary")
// Group results by Source Host
| groupBy([ComputerName],function=([count(aid, as=executeCount), min(@timestamp, as=firstSeen), max(@timestamp, as=lastSeen), collect([UserName,ExecutionSummary,ScriptContent,TargetProcessId], limit=1000)]))
| firstSeen:=formattime(field=firstSeen, format="%Y/%m/%d %H:%M:%S")
| lastSeen:=formattime(field=lastSeen, format="%Y/%m/%d %H:%M:%S")
```

## AnyDesk Service Installation - Potentially Malicious RMM Tool Installation
```
// Cyborg Hunter Link: https://hunter.cyborgsecurity.io/research/hunt-package/4103B086-F093-4084-9125-15B9A6C872B8
in(field=#event_simpleName, values=[CreateService,ModifyServiceBinary,ServiceStarted,ServicesStatusInfo])
| event_platform=Win
| ServiceImagePath=/AnyDesk/i or ServiceDisplayName=/AnyDesk|AnyDeskMSI/i or CommandLine=/AnyDesk/i
// CHANGE ME to your base URL for process and graph explorer links
| rootURL := "https://falcon.us-2.crowdstrike.com/"
// If Context Process ID is available utilize it, if not utilize Target Process ID
| case{ ContextProcessId ="*" | ContextId:=ContextProcessId; TargetProcessId="*" | ContextId:=TargetProcessId}
| case{ CommandLine ="*" | ServiceExecution:=CommandLine; ServiceImagePath="*" | ServiceExecution:=ServiceImagePath}
// Create URLs for Process and Graph Explorers
| format("[ProcessExplorer]%sinvestigate/process-explorer/%s/%s?_cid=%s", field=["rootURL", "aid", "ContextId", "cid"], as="ProcessExplorer")
| format("[GraphExplorer]%sgraphs/process-explorer/graph?id=pid:%s:%s", field=["rootURL", "aid", "ContextId"], as="GraphExplorer")
// Format summary for easier analysis
| format(format="%s\n\t↳ [SourceProcess]->%s\n\t\t↳ [ServiceName]->%s \n\t\t\t [ServiceExecution]->%s\n\t\t\t [ServiceDetails]->%s\n\t\t\t %s\n\t\t\t %s ---", field=[#event_simpleName, FileName, ServiceDisplayName, ServiceExecution, ServiceObjectName, ProcessExplorer, GraphExplorer], as="EventSummary")
// Group by Source Host and File Name
| groupBy([ComputerName],function=([count(as=eventCount), min(@timestamp, as=firstSeen), max(@timestamp, as=lastSeen), collect([EventSummary,FileName,ServiceDisplayName,ServiceObjectName,ServiceImagePath,ServiceType,ServiceStart,UserName,ContextId])]), limit=1000)
| formattime(field=firstSeen, format="%Y/%m/%d %H:%M:%S", as=firstSeen)
| formattime(field=lastSeen, format="%Y/%m/%d %H:%M:%S", as=lastSeen)
```

## working outside of business hours
```
| workHour:=formatTime(format="%H", field="@timestamp")
| workHour > 19 OR workHour < 7

```

## click fix
```
Queries-Only/Helpful-CQL-Queries/ClickFixHunting.md

// Fleshed out query for clickfix detection

#event_simpleName=ProcessRollup2 | #repo=base_sensor | ParentBaseFileName=explorer.exe | TargetProcessId=* |in(field="FileName",ignoreCase=true, values=[_powershell_,_pwsh_,_cmd_,_mshta_,_wscript_,_cscript_,_rundll32_,_regsvr32_,_wmic_,_msbuild_,_installutil_,_bitsadmin_,_curl_,_ftp_,_hh_,_schtasks_,_certutil_ ]) |in(field="CommandLine",ignoreCase=true, values=[_iex_,_irm_,_iwr_,_invoke-webrequest_,_http_,_https_,_ftp_,_smb_,_download_,_encodedcommand_,_bypass_,_invoke-expression_,_reflection.assembly_,_frombase64string_,_start-process_,_comobject_,_new-object_,_datetime_,_encoded_ ]) | process_tree := format("[PT](https://github.com/CrowdStrike/logscale-community-content/blob/main/graphs/process-explorer/tree?_cid=%s&id=pid:%s:%s&investigate=true&pid=pid:%s:%s)", field=["#repo.cid","aid","TargetProcessId","aid","TargetProcessId"]) | groupBy([process_tree,ComputerName,ParentBaseFileName,FileName,CommandLine], limit=max)
```


---
- Use the following to aggregate by formatted time
- Could use this to format time by the hour or minute and correlate events
```
"SEARCHTERM"
| formatTime(format="%F",field=@timestamp,as=fmttime)
| groupBy(fmttime)
```
- Ref: 
	- https://library.humio.com/data-analysis/writing-queries-flow.html
	- 
---
Awesome — with event_platform available, you can make **one cross-platform scheduled detection** that:

- Tags **Windows vs macOS** cleanly
    
- Uses **LogScale/Humio-standard functions** (if(), in(), bucket(), groupBy(), count(), sum(), collect())
    
- Applies **different thresholds/logic per OS** (Windows ClickFix/one-liner vs macOS paste-to-run + optional persistence)
    

  

Below are two “production-grade” queries: **Execution** (both OS) and **macOS persistence correlation**.

---

# **1) Production detection: Cross-platform “Paste-to-Run / ClickFix-style Execution”**

  

**What it alerts on**

- **Windows**: powershell|pwsh|cmd|mshta + URL + download/obfuscation primitives
    
- **macOS**: zsh|bash|sh|osascript + URL + curl/wget and/or pipe-to-shell / chmod +x / base64 decode
    

```
#repo=base_sensor #event_simpleName=ProcessRollup2

// --- Windows suspicious execution primitive
| WinPaste := if(
    event_platform="win"
    AND ImageFileName=/((?i)\\(powershell|pwsh|cmd|mshta)\.exe$)/
    AND CommandLine=/(?i)https?:\/\//
    AND (
      CommandLine=/(?i)\b(iwr|invoke-webrequest|downloadstring|frombase64string|iex|-enc)\b/
      OR CommandLine=/(?i)\b(mshta(\.exe)?\s+https?:\/\/)\b/
      OR CommandLine=/(?i)\b(certutil\s+-urlcache|bitsadmin)\b/
    ),
    then=1, else=0
  )

// --- macOS suspicious execution primitive
| MacPaste := if(
    event_platform="mac"
    AND ImageFileName=/(?i)\/(zsh|bash|sh|osascript)$/
    AND CommandLine=/(?i)https?:\/\//
    AND (
      CommandLine=/(?i)\b(curl|wget)\b/
      OR CommandLine=/(?i)\|\s*(sh|bash|zsh)\b/
      OR CommandLine=/(?i)chmod\s+\+x\b/
      OR CommandLine=/(?i)base64\s+(-D|--decode)\b/
    ),
    then=1, else=0
  )

// Optional: exclude known automation/service accounts (tune to your env)
// | where !in(UserName, values=["*\\svc_*","*\\rmm_*","*\\jamf*","*\\intune*"])

// Time windowing for “bursty” paste-to-run behavior
| bucket(span=10m)

// Roll up by host/user/OS per window
| groupBy([_bucket, event_platform, ComputerName, UserName],
          function=[
            count(as=total_procs),
            sum(WinPaste, as=win_hits),
            sum(MacPaste, as=mac_hits),
            collect([@timestamp, ImageFileName, CommandLine], as=examples)
          ])

// Thresholds (tuneable)
| where (event_platform="win" AND win_hits >= 1) OR (event_platform="mac" AND mac_hits >= 1)

| sort(_bucket, order=desc)
```

**Why this is “production”**

- It’s **OS-aware** (no guessing from path separators)
    
- It’s **thresholded** in a defined window (10m)
    
- It’s grouped so the alert payload includes **examples** for responders (collect())
    

---

# **2) Production detection: macOS “Paste-to-Run → Persistence via launchctl”**

  

This is the same execution logic, but it only fires when the host/user also runs **launchctl bootstrap/load/enable/kickstart** in the same 30-minute window.

```
#repo=base_sensor #event_simpleName=ProcessRollup2 event_platform="mac"

| MacPaste := if(
    ImageFileName=/(?i)\/(zsh|bash|sh|osascript)$/
    AND CommandLine=/(?i)https?:\/\//
    AND (
      CommandLine=/(?i)\b(curl|wget)\b/
      OR CommandLine=/(?i)\|\s*(sh|bash|zsh)\b/
      OR CommandLine=/(?i)chmod\s+\+x\b/
      OR CommandLine=/(?i)base64\s+(-D|--decode)\b/
    ),
    then=1, else=0
  )

| LaunchCtl := if(
    ImageFileName=/(?i)\/launchctl$/
    AND CommandLine=/(?i)\b(bootstrap|load|enable|kickstart|submit)\b/,
    then=1, else=0
  )

| bucket(span=30m)

| groupBy([_bucket, ComputerName, UserName],
          function=[
            sum(MacPaste, as=paste_hits),
            sum(LaunchCtl, as=launchctl_hits),
            collect([@timestamp, ImageFileName, CommandLine], as=examples)
          ])

| where paste_hits > 0 AND launchctl_hits > 0
| sort(_bucket, order=desc)
```

---

## **Recommended defaults for scheduling**

- **Execution detection**: every **5 minutes**, looking back **15 minutes**
- **macOS persistence correlation**: every **10 minutes**, looking back **60 minutes**
---


If you tell me what you use for **host identifier** (ComputerName vs Hostname vs DeviceName) and **user** (UserName vs UserSid), I’ll swap fields so this runs _exactly_ against your schema on first paste.



---
Below is a **response playbook** you can run immediately after either detection fires. The idea is:

1. **Lock scope** to the alert’s **aid** **+ time window** (use the UI time picker; set it to the bucket window + a little padding, e.g., **-15m to +30m** around the alert).
2. Pivot in this order: **Process → Network/DNS → File writes → Persistence → PrivEsc indicators**.

I’ll give you **copy/paste LogScale queries** that assume:
- `#repo=base_sensor`
- `Host: aid (and ComputerName optional)`
- `User: UserName`
- `Process: #event_simpleName=ProcessRollup2, ImageFileName, CommandLine`

`Replace "<AID>" and (optionally) "<USER>".`

---

## **0) Scope the investigation to the host + user**

 ### **A) All suspicious processes on the host in the window**

```
#repo=base_sensor #event_simpleName=ProcessRollup2
aid="<AID>"
| table([@timestamp, event_platform, ComputerName, UserName, ParentImageFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```
 ###  **B) Same, but only for the alert user (reduces noise)**

```
#repo=base_sensor #event_simpleName=ProcessRollup2
aid="<AID>" UserName="<USER>"
| table([@timestamp, event_platform, ComputerName, UserName, ParentImageFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

---

## **1) Process pivots (what spawned what?)**

  ### **A) Find LOLBins and script engines (common second stage)**

```
#repo=base_sensor #event_simpleName=ProcessRollup2
aid="<AID>"
(ImageFileName=/((?i)\\(powershell|pwsh|cmd|mshta|rundll32|regsvr32|wscript|cscript)\.exe$)/
 OR ImageFileName=/(?i)\/(zsh|bash|sh|osascript|python3?|perl|ruby|launchctl)$/)
| table([@timestamp, UserName, ParentImageFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

 ### **B) Identify “download/exec primitives” across everything**

```
#repo=base_sensor #event_simpleName=ProcessRollup2
aid="<AID>"
CommandLine=/(?i)https?:\/\//
(CommandLine=/(?i)\b(iwr|invoke-webrequest|downloadstring|frombase64string|iex|-enc|curl|wget)\b/
 OR CommandLine=/(?i)\|\s*(sh|bash|zsh)\b/
 OR CommandLine=/(?i)chmod\s+\+x\b/
 OR CommandLine=/(?i)\b(certutil\s+-urlcache|bitsadmin)\b/)
| groupBy([UserName, ImageFileName], function=[count(as=hits), collect(CommandLine, as=examples)])
| sort(hits, order=desc)
```

---

## **2) Network & DNS pivots (C2 / payload hosts)**
 ### **A) DNS lookups around the event**

```
#repo=base_sensor #event_simpleName=DnsRequest
aid="<AID>"
| groupBy([DomainName, UserName], function=count(as=hits))
| sort(hits, order=desc)
```

 ### **B) Network connections around the event (IP-based)**

```
#repo=base_sensor #event_simpleName=NetworkConnectIP4
aid="<AID>"
| groupBy([RemoteAddressIP4, RemotePort, UserName, ImageFileName], function=count(as=hits))
| sort(hits, order=desc)
```

 ### **C) If you extracted a suspicious domain, pivot back to the process that queried it**

```
#repo=base_sensor #event_simpleName=DnsRequest
aid="<AID>"
DomainName=/(?i)<SUSPICIOUS_DOMAIN_HERE>/
| table([@timestamp, UserName, ImageFileName, DomainName])
| sort(@timestamp, order=desc)
```

---

## **3) File-write pivots (payload drop & staging)**
 ### **A) Windows staging locations (Temp / Users / Downloads)**

```
#repo=base_sensor
aid="<AID>"
#event_simpleName in ("FileCreateInfo","FileWriteInfo","FileModifyInfo")
TargetFileName=/(?i)\\Users\\|\\Temp\\|\\AppData\\(Local|Roaming)\\|\\Downloads\\/
| table([@timestamp, UserName, ImageFileName, CommandLine, TargetFileName, SHA256HashData])
| sort(@timestamp, order=desc)
```

 ### **B) macOS staging locations (/tmp, /var/tmp, ~/Downloads, ~/Library)**

```
#repo=base_sensor
aid="<AID>"
#event_simpleName in ("FileCreateInfo","FileWriteInfo","FileModifyInfo")
TargetFileName=/(?i)\/(tmp|var\/tmp|Users\/[^\/]+\/Downloads|Users\/[^\/]+\/Library)\//
| table([@timestamp, UserName, ImageFileName, CommandLine, TargetFileName, SHA256HashData])
| sort(@timestamp, order=desc)
```

---

## **4) Persistence pivots**
 ### **Windows persistence quick hits**
 #### **A) Scheduled Tasks creation**

```
#repo=base_sensor #event_simpleName=ProcessRollup2
aid="<AID>" event_platform="win"
ImageFileName=/((?i)\\schtasks\.exe$)/
CommandLine=/(?i)\s\/create\s/
| table([@timestamp, UserName, ParentImageFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

 #### **B) Services created/modified**

```
#repo=base_sensor #event_simpleName=ProcessRollup2
aid="<AID>" event_platform="win"
ImageFileName=/((?i)\\sc\.exe$)/
CommandLine=/(?i)\s(create|config)\s/
| table([@timestamp, UserName, ParentImageFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

 #### **C) Startup folder drops (file writes)**

```
#repo=base_sensor
aid="<AID>" event_platform="win"
#event_simpleName in ("FileCreateInfo","FileWriteInfo","FileModifyInfo")
TargetFileName=/(?i)\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\/
| table([@timestamp, UserName, TargetFileName, SHA256HashData, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

> If you have registry events available in your pipeline, we can add Run/RunOnce key hunting; if not, process-based pivots (reg.exe) still help:

```
#repo=base_sensor #event_simpleName=ProcessRollup2
aid="<AID>" event_platform="win"
ImageFileName=/((?i)\\reg\.exe$)/
CommandLine=/(?i)\\Software\\Microsoft\\Windows\\CurrentVersion\\(Run|RunOnce)/
| table([@timestamp, UserName, ParentImageFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

---

### **macOS persistence quick hits**
 #### **A) LaunchAgents/Daemons plist writes**

```
#repo=base_sensor
aid="<AID>" event_platform="mac"
#event_simpleName in ("FileCreateInfo","FileWriteInfo","FileModifyInfo")
TargetFileName=/(?i)\/(Library\/LaunchAgents|Library\/LaunchDaemons|Users\/[^\/]+\/Library\/LaunchAgents)\/.*\.plist$/
| table([@timestamp, UserName, TargetFileName, SHA256HashData, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

 #### **B)**   **launchctl**  **activation (load/bootstrap/enable/kickstart)**

```
#repo=base_sensor #event_simpleName=ProcessRollup2
aid="<AID>" event_platform="mac"
ImageFileName=/(?i)\/launchctl$/
CommandLine=/(?i)\b(bootstrap|load|enable|kickstart|submit)\b/
| table([@timestamp, UserName, ParentImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

 #### **C) Shell profile persistence (**.zshrc, .bash_profile **, etc.)**

```
#repo=base_sensor
aid="<AID>" event_platform="mac"
#event_simpleName in ("FileCreateInfo","FileWriteInfo","FileModifyInfo")
TargetFileName=/(?i)\/Users\/[^\/]+\/\.(zshrc|zprofile|bash_profile|bashrc|profile)$/
| table([@timestamp, UserName, TargetFileName, SHA256HashData, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

---
## **5) Privilege escalation pivots (Windows + macOS)**

 ### **Windows: UAC-bypass-ish LOLBins**

```
#repo=base_sensor #event_simpleName=ProcessRollup2
aid="<AID>" event_platform="win"
ImageFileName=/((?i)\\(fodhelper|computerdefaults|eventvwr|sdclt)\.exe$)/
| table([@timestamp, UserName, ParentImageFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

 ### **macOS: “admin prompt via AppleScript” and sudo -S**

```
#repo=base_sensor #event_simpleName=ProcessRollup2
aid="<AID>" event_platform="mac"
(
  (ImageFileName=/(?i)\/osascript$/ AND CommandLine=/(?i)with administrator privileges/)
  OR
  (ImageFileName=/(?i)\/sudo$/ AND (CommandLine=/(?i)\s-S(\s|$)/ OR CommandLine=/(?i)echo\s+.+\|\s*sudo/))
)
| table([@timestamp, UserName, ParentImageFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

---
## **6) “One screen” incident summary (good for case notes)**

```
#repo=base_sensor #event_simpleName=ProcessRollup2
aid="<AID>"
CommandLine=/(?i)https?:\/\//
| groupBy([event_platform, ComputerName, aid, UserName],
          function=[count(as=hits), collect([@timestamp, ImageFileName, CommandLine], as=examples)])
| sort(hits, order=desc)
```

---

 ### **If you paste one alert’s aid,UserName, and the top suspicious CommandLine, I can tailor these pivots into a** single “guided investigation” sequence (run order + what to look for + how to decide benign vs malicious) for your environment.**
---



