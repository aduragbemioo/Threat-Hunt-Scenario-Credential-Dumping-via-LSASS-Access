# Threat Event: Credential Dumping via LSASS Access  
**Unauthorized Access to LSASS for Credential Dumping**

---

## Reason for Threat Hunt

### 🚨 Recent Cybersecurity Advisory from CISA  
CISA issued a bulletin warning of increased credential theft activity leveraging tools like **Mimikatz** and **ProcDump** that target **LSASS (Local Security Authority Subsystem Service)**.  
As a result, **management has directed a proactive threat hunt** to identify signs of credential dumping in the environment.

---

## Steps the "Bad Actor" Took – Logs and IoCs Created

1. **Downloaded credential dumping tool**
   - E.g., `mimikatz.exe`, `debug.exe`, `procdump.exe`
   - Often disguised with benign names

2. **Disabled Security Controls (optional)**
   - Example: `Set-MpPreference -DisableRealtimeMonitoring $true`

3. **Executed the Credential Dump**
   - `mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"`
   - Or: `procdump.exe -ma lsass.exe lsass.dmp`

4. **Extracted the Dump**
   - File: `lsass.dmp`
   - Transferred via SMB, FTP, or outbound connection

---

## Tables Used to Detect IoCs

| Table Name              | Description                                                                 |
|------------------------|-----------------------------------------------------------------------------|
| `DeviceProcessEvents`   | Detects execution of tools and interactions with LSASS                      |
| `DeviceFileEvents`      | Monitors creation of files like `lsass.dmp`                                 |
| `DeviceImageLoadEvents` | Tracks DLLs or suspicious modules loaded by credential dumping tools       |
| `DeviceNetworkEvents`   | Flags data exfiltration via public IPs from malicious processes             |
| `DeviceRegistryEvents`  | Detects changes to security/AV-related registry keys                        |

---

## Related Queries

```kusto
// LSASS memory dump attempt using ProcDump
DeviceProcessEvents
| where ProcessCommandLine has_all ("procdump", "lsass")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine

// Execution of Mimikatz
DeviceProcessEvents
| where ProcessCommandLine has_any ("mimikatz", "sekurlsa", "logonpasswords")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine

// Detection of lsass.dmp or similar file
DeviceFileEvents
| where FileName in~ ("lsass.dmp", "lsass.zip")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessCommandLine

// DLLs loaded by mimikatz or other malicious tools
DeviceImageLoadEvents
| where InitiatingProcessFileName has "mimikatz"
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, SHA256

// Public outbound network activity from suspicious tools
DeviceNetworkEvents
| where InitiatingProcessFileName has_any("mimikatz.exe", "procdump.exe")
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, Protocol
```

## 👤 Created By

* **Author**: Aduragbemi
* **LinkedIn**: [Aduragbemi Oladapo](https://www.linkedin.com/in/aduragbemioladapo/)
* **Date**: June 25, 2025

---

## ✅ Validated By

* **Reviewer**: *TBD*
* **Contact**: *TBD*
* **Date**: *TBD*

---


## 📅 Revision History

| Version | Changes       | Date          | Modified By                |
| ------- | ------------- | ------------- | -------------------------- |
| 1.0     | Initial Draft | June 25, 2025 | Aduragbemi Oladapo |

---
