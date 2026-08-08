https://assets.sentinelone.com/sentinellabs/chamelgang-friends-en

- DLL Hijacking
	- https://www.upguard.com/blog/dll-hijacking
- Chinese APT group ChamelGang (also known as CamoFei)
- ransomware or data encryption tooling
- APT41 umbrella has previously been seen targeting the video gaming industry for financial gain by manipulating virtual currencies, abusing in-game transaction systems, and deploying the for-purchase Encryptor RaaS ransomware
## CLUSTER 1 | CHAMELGANG INTRUSIONS
- spanning 2022 and 2023
- https://stillu.cc/assets/slides/2023-08-Unmasking%20CamoFei.pdf
- objectives beyond intelligence collection, such as PII theft and financial gain
- government organization in East Asia and an aviation organization in the Indian subcontinent
- linked the CatB ransomware and BeaconLoader to ChamelGang
- TeamT5 associates CatB with ChamelGang based on overlaps in code, staging mechanisms, and malware artifacts such as certificates, strings, and icons found in custom malware used in intrusions attributed to ChamelGang
- CatB is typically deployed using DLL hijacking into the msdtc.exe process
- https://www.ptsecurity.com/ww-en/analytics/pt-esc-threat-intelligence/new-apt-group-chamelgang/#id3-1
- During a user session, the Windows operating system tracks changes made to the registry hive HKEY_CURRENT_USER in the ntuser.dat.LOG1 and ntuser.dat.LOG2 files. HKEY_CURRENT_USER stores system and software configuration information for the currently logged in user. Parsing the ntuser.dat.LOG1 file we retrieved revealed Windows registry keys and values that point to the Presidency of Brazil. ntuser.dat.LOG1 stores a path to an Outlook Offline File (.ost) of an email user at the presidencia.gov[.]br domain, the email domain of the Presidency of Brazil. We also observed the presence of another registry key pointing to the domain presidencia.gov[.]br as an AD-related artifact: CN=Aggregate,CN=Schema,CN=Configuration,DC=presidencia,DC=gov,DC=br. This registry key is stored under HKEY_CURRENT_USER\Software\Microsoft\ADs\Providers\LDAP, which is a user-specific storage location for ADSI (Active Directory Service Interfaces). This made us suspect that the Presidency had been targeted using ChamelGang’s CatB ransomware. 
