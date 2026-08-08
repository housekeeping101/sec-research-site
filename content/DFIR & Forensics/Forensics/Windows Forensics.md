https://youtu.be/VYROU-ZwZX8
- windows\\system32\\config
- windows\\system32\\config\\regbak
- windows\\system32\\winevt\\logs
- user profiles:
	- Ntuser.dat
		- Hkey current user - read from ntuser.dat
			- hkey_current_user = reviewing live system
			- ntuser.dat = dead box
	- usr.dat
- Registry edit
	-  hkey_current_user
- registry explorer
	- load offline hive
		- ntuser.dat
	- software > microsoft > windows > explorer
- regripper - sift
- runmru

## Windows hunting notes
#hunt 
745 event id - odd execution?

Krvtgt with 0 logon 
No auth for logging in
Pre authentication type

4768 event id

File creates from obscure executables 
5145 
Bloodhound event 

Seclogon and event type 9 - might be pass the hash
