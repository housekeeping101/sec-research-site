### Remote Maintenance and Monitoring (RMM) Tools
- RMM tools are increasingly leveraged by ransomware actors. These commercial tools are often easy to find, as they are typically registered in the Add/Remove Programs section in Windows.
- Have an approved list → BLOCK & HUNT anything not on the approved list.
- RMM tools commonly seen in ransomware incidents:
	-  AnyDesk
		- Log files:
			- `%PROGRAMDATA%\AnyDesk\connection_trace.txt`
			- `%PROGRAMDATA%\AnyDesk\ad_svc.trace`
			- `%APPDATA%\AnyDesk\ad.trace`
	- Atera
		- Log file:
			- `%PROGRAMFILES%\ATERA Networks\AteraAgent\		Packages\AgentPackageRunCommandInteractive\log.txt`
		- WEL services added:
			- `HKLM\SYSTEM\ControlSet001\Services\EventLog\Application\AlphaAgent`
		- `HKLM\SYSTEM\ControlSet001\Services\EventLog\Application\AteraAgent`
	- ConnectWise (formerly ScreenConnect)
	- Log and important file locations:
		- `%SYSTEMROOT%\temp\screenconnect\[version]\`
		- `%PROGRAMDATA%\ScreenConnect Client ([fingerprint])\`
		- `%PROGRAMFILES(x86)%\ScreenConnect Client`
([fingerprint])\
• %USERPROFILE%\Documents\ConnectWiseControl\Files\
• %USERPROFILE%\Documents\ConnectWiseControl\
captures\
› LogMeIn
» Log locations (default):
• %PROGRAMDATA%\LogMeIn\LogMeIn.log
• %PROGRAMDATA%\LogMeIn\LMI[date].log
• %PROGRAMFILES(x86)%\LogMeIn\journal.dat
» Registry key pointing to log file locations:
• HKLM\Software\LogMeIn\V5\Log
(the “V5” may be version dependent)
› Splashtop
» Log locations:
• %PROGRAMDATA%\Splashtop\Temp\log\FTCLog.txt
• %PROGRAMFILES(x86)%\Splashtop\Splashtop Remote\
Server\log\agent_log.txt
• %PROGRAMFILES(x86)%\Splashtop\Splashtop Remote\
Server\log\SPLog.txt
» Custom EVTX application providers:
• Splashtop-Splashtop Streamer-Remote Session/
Operational
• Splashtop-Splashtop Streamer-Status/Operational
› TeamViewer
» Log locations:
• %PROGRAMFILES%\TeamViewer\Connections_incoming.txt
• %PROGRAMFILES%\TeamViewer\TeamViewer15_Logfile.log
• %PROGRAMFILES%\TeamViewer\TVNetwork.log
• %APPDATA%\TeamViewer\TeamViewer15_Logfile.log
• %LOCALAPPDATA%\Temp\TeamViewer\TV15Install.log
» Note: Some of these log file names will be version-
dependent, hence the instances of “15” above.