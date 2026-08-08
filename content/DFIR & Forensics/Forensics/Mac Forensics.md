- The system.log and fseventsd logs can help correlate
- macOS tracks app launches and usage history in databases located at /var/db/diagnostics. This can be critical for tracing if and when a suspicious app or browser was used for exfiltration.
- Ioreg 
- 
https://youtube.com/watch?v=cgHmv2JKZ-Y&si=zOK_QGLEb8Re4pH4

### New Wifi database from Apple intelligence
https://www.swiftforensics.com/2025/01/new-wifi-database-from-apple.html?m=1
- The Wifi data resides in the database located here under table **wifiContextEvents**:
`/Users/<USER>/Library/IntelligencePlatform/Artifacts/internal/views.db`

- The timestamp is just a Cocoa (NSDate) type, can easily be converted back to human readable form.

```
SELECT
    behaviorType AS BehaviorType,
    SUBSTR(behaviorIdentifier, 1, INSTR(behaviorIdentifier, ':') - 1) AS Event,
    SUBSTR(behaviorIdentifier, INSTR(behaviorIdentifier, ':') + 1) AS NetworkName,
    datetime('2001-01-01', timestamp || ' seconds') AS Timestamp
FROM wifiContextEvents
ORDER BY timestamp ASC;
```


### An open source spotlight parser
[https://www.swiftforensics.com/2018/08/parsing-spotlight-database.html](https://www.swiftforensics.com/2018/08/parsing-spotlight-database.html)

### mac_apt update to BTM processing
- https://www.swiftforensics.com/2025/01/macapt-update-to-btm-processing.html?m=1
`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`

## BTM dump

https://eclecticlight.co/2026/02/20/in-the-background-identification/
  
in /var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v16.btm

sfltool dumpbtm > ~/Documents/btmdump.text
## BTM Attributions.plist

/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist
## Log Entries

log subsystem com.apple.backgroundtaskmanagement


## If you want to scale this to your “top 25 PersonIds”
```
WITH top_people AS (
  SELECT
    SUBSTR(behaviorIdentifier, INSTR(behaviorIdentifier, ':') + 1) AS PersonId,
    COUNT(*) AS cnt
  FROM personEntityInteractionEvents
  WHERE INSTR(behaviorIdentifier, ':') > 0
  GROUP BY PersonId
  ORDER BY cnt DESC
  LIMIT 25
),
ident AS (
  SELECT
    CAST(subject AS TEXT) AS PersonId,
    MAX(CASE WHEN predicate='PS33' THEN object END) AS display_name,
    MAX(CASE WHEN predicate='PS520' AND relationshipPredicate='PS407' THEN object END) AS phone
  FROM people_subgraph
  GROUP BY subject
)
SELECT
  t.PersonId,
  t.cnt,
  i.display_name,
  i.phone
FROM top_people t
LEFT JOIN ident i
  ON i.PersonId = t.PersonId
ORDER BY t.cnt DESC;
```

Here are some common examples of locations that store session cookies on macOS:
https://www.sentinelone.com/blog/session-cookies-keychains-ssh-keys-and-more-7-kinds-of-data-malware-steals-from-macos-users/

```
~/Library/Cookies/*.binarycookies

Chrome:  ~/Library/Application Support/Google/Chrome/Default/Cookies
Firefox: ~/Library/Application Support/Firefox/Profiles/[Profile Name]/
Slack :  ~/Library/Application Support/Slack/Cookies (file) 
	 ~/Library/Application Support/Slack/storage/*
         ~/Library/Containers/com.tinyspeck.slackmacgap/Data/Library/Application Support/Slack/storage
```