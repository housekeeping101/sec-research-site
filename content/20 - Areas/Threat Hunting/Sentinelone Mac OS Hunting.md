# Threat Hunting - How Malicious SoftwarePersists on macOS

## Get a List of Users
#show_users
dscl . list /Users UniqueID
dscl . list /Users UniqueID | grep -v ^_
	remove system accounts
- A great command to use here is `w`, which tells you every user that is logged in and what they are currently doing
- `last` command, which indicates previous logins

## Persistence via Launch Agent
- there are individual LaunchAgent folders for each login user,
- Each user on a Mac can have a LaunchAgents folder in their own Library folder to specify code that should be run every time that user logs in
- user LaunchAgents require no privileges to install
- 
## Launch Daemon
- LaunchDaemons only exist at the computer and system level, and technically are reserved for persistent code that does not interact with the user
- /Library/LaunchDaemons requires administrator level privileges
- LaunchDaemons run on startup and for every user
- System LaunchAgents, the System LaunchDaemons are protected by SIP so the primary location to monitor is /Library/LaunchDaemons

## Profiles
- Profiles can be viewed by users in System Preferences Profiles pane and by administrators by enumerating the /Library/Managed Preferences folder
- cron jobs
- ktexts
	- kernel extensions

## Persistent Login Items
- Once upon a time, Login Items were easily enumerated through the System Preferences utility, but a newer mechanism makes it possible for any installed application to launch itself at login time simply by including a Login Item in its own bundle
- ~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm

## AppleScript
- grep -A1 "AppleScript" ~/Library/Mail/V6/MailData/SyncedRules.plist
	- will enumerate any Mail rules that are calling AppleScripts� If any are found, those will then need to be examined closely to ensure they are not malicious

## Periodics as Persistence
- Periodics are system scripts that are generally used for maintenance and run on a daily, weekly and monthly schedule
	- etc/periodic
- check both ``/etc/defaults/periodic.conf`` and ``/etc/periodic.conf`` for system and local overrides to the default periodic configuration.

## LoginHooks and LogoutHooks
- The following command should return a result that doesn't have either LoginHook or LogoutHook values:
	- sudo defaults read com.apple.loginwindow

## At Jobs
- enumerating the ``/var/at/jobs`` directory. Jobs are prefixed with the letter a and have a hex-style name

## Emond - Forgotten Event Monitor
- /private/var/db/emondClients

# Threat Hunting - Detecting Malicious Behavior on macOS

## Check Open Ports and Connections
- netstat -na | egrep 'LISTEN|ESTABLISH'
- lsof -i
	- to list all files with an open IPv4, IPv6 or HP-UX X25 connection.
- 
## Investigate Running Processes
- ps -axo user,pid,ppid,%cpu,%mem,start,time,command
	- run as superuser
	- pay particular interest to commands where the PPID, the parent process identifier, is something other than 1, indicating a user process that's also spawning child processes
- lsappinfo list
	- information about applications including the executable path, pid, bundle identifier (useful for detection purposes) and launch time
- launchtl list
- launchctl print user/501
- launchctl print system

## Investigate Open Files
- lsof

## Examine the File System
- ls -al ~/.* ~/Library /Library ~/Library/Application\ Support /Library/Application\ Support/
	- initial audit of files in certain locations that are often populated by malware.
- check the /Users/Shared folder, and the temp directories at /private/tmp and the user's Temporary Directory (these are not the same), which you can get to using the $TMPDIR environment variable
	- ls -al /Users/Shared
	- ls -al /private/tmp
	- ls -al $TMPDIR
- /usr/local
	- ls -al /usr/local
	- ls -al /usr/local/bin
	- ls -al /usr/local/sbin
- be aware of whether your user has Homebrew installed or not� The Homebrew executable at /usr/local/bin/brew is itself a shell script� All commands in that script are executed whenever the user types$brew <command>in the Terminal� The script can be modified by any other process running as the user without authentication, and could be a tempting target for persistence or opening a backdoor� Any changes to the script will be overwritten when the user issues the$brew updatecommand, although they can also be retrieved, as helpfully indicated here by Homebrew itself
- find search to look for any files created since or between a certain time or date
	- this will find any files modified in the current working directory in the last 30 minutes
	- find . -mtime +0m -a -mtime -30m -print
- We can also query the LSQuarantine database to see what items have been downloaded by email clients and browsers
	- sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV* 'select LSQuarantineEventIdentifier, LSQuarantineAgentName, LSQuarantineAgentBundleIdentifier, LSQuarantineDataURLString, LSQuarantineSenderName, LSQuarantineSenderAddress, LSQuarantineOriginURLString, LSQuarantineTypeNumber, date(LSQuarantineTimeStamp + 978307200, "unixepoch") as downloadedDate from LSQuarantineEvent order by LSQuarantineTimeStamp' | sort | grep '|' --color
## Examine the Mac's Network Configuration

