Articles:
https://us-cert.cisa.gov/ncas/alerts/aa22-277a
https://therecord.media/cisa-multiple-government-hacking-groups-had-long-term-access-to-defense-company/
https://businessinsights.bitdefender.com/deep-dive-into-a-fin8-attack-a-forensic-investigation

Youtube Forensic Demo
https://youtu.be/UMogme3rDRA
https://www.13cubed.com/downloads/impacket_exec_commands_cheat_sheet.pdf

Github:
https://github.com/SecureAuthCorp/impacket


* https://riccardoancarani.github.io/2020-05-10-hunting-for-impacket/
* proxychains - SOCKS proxy
* Secretsdump.py
	* Remote SAM Dump
	* `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ SecurePipeServers\winreg`
	* DCERPC seen over the wire
	* DsGetNcChanges request
		* normally invoked by other domain controllers legitimately, if the same method is found to be invoked by a non-DC host it would be a good indicator of malicious activity.
	* Enable object auditing on the domain object within AD.
	* Process CLI auditing
	* `cmd.exe` was spawned by `WmiPrvSE.exe`. This usually means that `cmd.exe` was spawned using WMI.
	* wmiexec
	* `cmd.exe /Q /c  1> \\127.0.0.1\ADMIN$\ 2>&1`
	* DCOM/DCERPC protocols
		* Uses TCP
	* parent-child process anomaly of `mmc.exe` spawning `cmd.exe`. However this is true only when the `-object MMC20` option is used within the tool, as shown below
	* `dcomexec.py -object MMC20 ISENGARD/Administrator:1qazxsw2..@172.16.119.140`
* 