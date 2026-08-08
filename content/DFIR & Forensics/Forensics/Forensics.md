#cellebrite
https://www.cellebritelearningcenter.com/mod/page/view.php?id=46445#computer
- Identify uses for s1 RTR 
```
something that I would love for everyone to begin thinking about though is what we want out of s1 "rtr" (or whatever s1 calls it) remote acquisition scripts - I assume the majority of the time that these will be very targetted - I would love to be able to kick these off from swimlane when say intp submits a ticket with a targetted file / files of question
```

file:///Users/amorris01/Downloads/335.pdf
```
Live :: Response

date :: Local System Time (-u for UTC)
hostname :: System Hostname
uname –a :: OS & Architecture Information
sw_vers :: macOS Version & Build
netstat –anf inet or netstat -an :: Active Network Connections
lsof -i :: Active Network Connections (by process)
netstat -rn :: Routing Table
arp –an | ndp -an :: ARP Table (IPv4 | IPv6)
ifconfig :: Network Interface Configuration
lsof :: List Open Files
who –a, w :: List Logged On Users
last :: List user logins
ps aux :: List Processes
system_profiler -xml
-detaillevel full > file.spx  :: System Profiler (XML, Full Detail Level), open with System Information.app
```



#webBrowser
Web Browsing Activity
- /Users/%username%/Library/Application Support/Google/
Chrome/Default
- /Users/%username%/Library/Caches/Chrome/Default
- /Users/%username%/Library/Application Support/Firefox/Profiles
- /Users/%username%/Library/Caches/Firefox/Profiles
- /Users/%username%/Library/Application Support/Opera
- /Users/%username%/Library/Caches/Opera
- /Users/%username%/Library/Application Support/Safari
- /Users/%username%/Library/Caches/com.apple.Safari
- /Users/%username%/Library/Application Support/
BraveSoftware/Brave-Browser/Default/History
- /Users/%username%/Library/Application Support/
BraveSoftware/Brave-Browser/Default/Bookmarks
- /Users/%username%/Library/Application Support/
BraveSoftware/Brave-Browser/Default/Favicons
- /Users/%username%/Library/Application Support/
BraveSoftware/Brave-Browser/Default/Login Data
- /Users/%username%/Library/Application Support/
BraveSoftware/Brave-Browser/Default/Preferences

#bashHistory
- /Users/%username%/.bash_sessions
- /Users/%username%/.bash_history

#mru
- /Users/username/Library/Preferences/com. apple.finder.plist

#installHistory
```
plutil -p /Library/Receipts/InstallHistory.plist | less
```

#anydesk
https://support.anydesk.com/knowledge/trace-files
macOS
```
Uninstalled:
	~/.anydesk/anydesk.trace
	~/.anydesk_ad_<prefix>/anydesk_ad_<prefix>.trace
Installed:
	/var/log/anydesk.trace
	/var/log/anydesk_ad_<prefix>.trace
```

#loggedOnUser
```loggedOnUser=$(who | grep -v grep | grep console | awk '{print $1}' | tail -n 1)```
OR
`who`


```
lsof -i -P
lsof -p <PID>
cd /proc/<pid> << linux host
```

#XPC
- Application Bundle: /Contents/XPCServices/
 - /System/Library/XPCServices/

#Syslog
- syslog –d asl/
- syslog –T utc –F raw –d /asl
- /private/var/audit/
- praudit –xn /var/audit/*

LSFileQuarantineEnabled Key set to True
- ~/Library/Preferences/com.apple.LaunchService
s.QuarantineEvents.V2
- ~/Library/Preferences/com.apple.LaunchService
s.QuarantineEvents


- `scutil --nc list`
	- Available network connection services in the current set (*=enabled):
- sudo sysdiagnose
- `/private/var/db/powerlog/Library/BatteryLife
`/private/var/tmp/sysdiagnose_2025.10.18_13-49-24-0400_macOS_Mac_25A362.tar.gz`

### Tables
- `PLApplicationAgent_EventForward_FrontmostApp`
- `LocaleMetrics_TImeZone_1_2`
- `PLLocationAgent_EventForward_ClientStatus`
- `PLApplicationAgent_EventNone_AppInfo`
- `PLNetworkAgent_EventBackward_CumulativeNetworkUsage`
- `PLProcessNetworkAgent_EventInterval_UsageDiff`
- `PLPeripheralAgent_EventForward_DeviceState` - Connected devices
- `GenerativeFunctionMetrics_Summarization_1_2` - Apple intelligence and notifications





---
### Forensic artifacts by category

Elcomsoft Quick Triage targets specific, high-value files that reconstruct user behavior.

- **Chromium Artifacts**  
    _For Chrome and its derivatives (Edge, Brave, Opera, etc.), the triage profile targets the standard SQLite databases and JSON configuration files located in the User Data directories._
    
    - **User Activity & Navigation:**
        - `History` (URLs, visits, timestamps)
        - `Visited Links`
        - `Media History` (Audio/Video playback)
        - `Network Action Predictor` (Predictive loading data)
    - **Identity & Security:**
        - `Login Data` (Saved usernames and encrypted passwords)
        - `EncryptedStorage`
        - `Network\Cookies` (Session cookies)
        - `Secure Preferences`
    - **Configuration & Session:**
        - `Preferences` (User settings)
        - `Local State`
        - `Web Data` (Auto-fill, form history)
        - `Sessions` and `Session Storage`
    - **Storage:**
        - `Local Storage\leveldb\*`
        - `IndexedDB\**`
        - `WebStorage` (CacheStorage)
    - **Specific Extensions (Yandex):**
        - `Ya Credit Cards`, `Ya Passman Data`, `Ya Login Data`
- **Mozilla Artifacts**  
    _For Firefox and related browsers, the extraction focuses on the root profile directory and specific database files that handle security and history._
    
    - **Credentials & Encryption:**
        - `key3.db` / `key4.db` (Encryption keys for the password store)
        - `signons.sqlite` / `logins.json` (Saved credentials)
    - **User Data:**
        - `places.sqlite` (Bookmarks and History)
        - `formhistory.sqlite`
        - `cookies.sqlite`
        - `downloads.sqlite`
    - **Configuration:**
        - `prefs.js` (User preferences)
        - `*.json` (Session restore files, extensions)
    - **Storage:**
        - `storage\default\*.sqlite` (Local storage objects)
- **Microsoft Edge (Legacy)**  
    _While modern Edge artifacts mirror the Chromium list, the file targets the specific database used by the legacy EdgeHTML engine and Internet Explorer._
    
    - **Web Cache Database:** `Edge WebcacheV01.dat` (Located in \microsoft\windows\webcache)
    - **Internet Explorer Specifics:**
        - `index.dat` (History, Cookies, UserData – specifically for legacy/XP systems)
        - IE 9/10/11 Cache and Cookies folders
- **Safari Artifacts**  
    _For Safari on Windows, the triage targets both the raw database files and the Property List (plist) configuration files._
    
    - **Navigation & Data:**
        - `History.plist` / `History`
        - `Downloads.plist` / `Downloads`
        - `Cookies.plist` / `Cookies`
        - `Bookmarks.plist` / `Bookmarks`
    - **Session & Cache:**
        - `LastSession.plist` / `LastSession`
        - `cache.db`
    - **Security:**
        - `keychain.plist` / `keychain`
    -
[[Mac Forensics]]

Here are some common examples of locations that store session cookies on macOS:
https://www.sentinelone.com/blog/session-cookies-keychains-ssh-keys-and-more-7-kinds-of-data-malware-steals-from-macos-users/

```
~/Library/Cookies/*.binarycookies

Chrome:  ~/Library/Application Support/Google/Chrome/Default/Cookies
Firefox: ~/Library/Application Support/Firefox/Profiles/[Profile Name]/
Slack :  ~/Library/Application Support/Slack/Cookies (file) 
	 ~/Library/Application Support/Slack/storage/*
         ~/Library/Containers/com.tinyspeck.slackmacgap/Data/Library/Application Support/Slack/storage

