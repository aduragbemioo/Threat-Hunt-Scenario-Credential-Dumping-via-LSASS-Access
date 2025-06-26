# Threat Event: Credential Dumping via LSASS Access  
**Simulated Credential Theft Using PowerShell and Fake Mimikatz Tool**


- [Scenario Creation](https://github.com/aduragbemioo/Threat-Hunt-Scenario-Credential-Dumping-via-LSASS-Access/blob/main/scenario.md)

---
## Platforms and Tools Used

- Windows 10 Virtual Machine (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- PowerShell                         
- mimi-sim.exe (Fake executable mimicking Mimikatz behavior)


---

## Senario

### 🚨 CISA Advisory and Internal Management Directive  
Due to a recent alert from CISA warning of increased attacker activity targeting the LSASS process for credential dumping using tools like **Mimikatz** and **ProcDump**, management directed a proactive hunt for related activity across endpoints.

---



---

## Investigation Steps

---

### 🔍 **1. Detection of Suspicious Tool Creation or Download**

```kusto
DeviceFileEvents
| where FileName has_any ("debug", "mimi", "procdump") 
| where FileName endswith ".exe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, ActionType
```
Found creation of mimi-sim.exe under the user profile on device ad-stig-impleme.


🧠 2. Execution of Simulated Mimikatz with sekurlsa Argument

```kusto
DeviceProcessEvents
| where DeviceName == "ad-stig-impleme"
| where ProcessCommandLine has_any ("mimi-sim.exe", "sekurlsa")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```
The actual executable is fake, so it didn't run, but we see PowerShell initiating the command:powershell.exe -ExecutionPolicy Bypass -Command ...

🗂️ 3. LSASS Dump File Creation Detection
What is LSASS Dumping?
Attackers dump the memory of the lsass.exe process to extract plaintext credentials. This is commonly used for:

- Privilege escalation
- Lateral movement
- Credential theft

```kusto
DeviceFileEvents
| where DeviceName == "ad-stig-impleme"
| where FileName =~ "lsass.dmp"
| where FolderPath has_any ("\\Temp\\", "\\AppData\\Local\\Temp\\", "\\Desktop\\")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, ActionType
```
- The simulated script created a fake lsass.dmp on the desktop.
- The event was logged after mimi-sim.exe was dropped.

📤 4. Simulated Exfiltration to Remote Network
```kusto
DeviceNetworkEvents
| where DeviceName == "ad-stig-impleme"
| where InitiatingProcessFileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "ntoskrnl.exe")
| where RemotePort !in (80,443)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType, RemoteIP, RemotePort, RemoteIPType, RemoteUrl
| order by Timestamp asc
```
- Simulated copy to a private IP (e.g., \\192.168.1.99\shared) caused network activity.
- No actual exfiltration occurred, but logs reflect the attempt.

🛡️ 5. Defender Realtime Monitoring Tampering Attempt

```kusto
DeviceProcessEvents
| where DeviceName == "ad-stig-impleme"
| where ProcessCommandLine has "Set-MpPreference" and ProcessCommandLine has "DisableRealtimeMonitoring"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```
- PowerShell attempted to run: Set-MpPreference -DisableRealtimeMonitoring $true
- Defender logged the attempt, useful for detecting tampering efforts.


## Chronological Event Timeline

### 1. Suspicious File Drop

- **Timestamp:** Timestamp from `DeviceFileEvents`  
- **Event:** Dropped `mimi-sim.exe` into the Downloads directory via PowerShell.  
- **Path:** Likely under `C:\Users\*\Downloads\` or similar user-controlled folder.  

---

### 2. Defender Tampering Attempt

- **Timestamp:** Timestamp from `DeviceProcessEvents`  
- **Event:** PowerShell attempted to disable Windows Defender’s Real-Time Protection.  
- **Command Line:** `Set-MpPreference -DisableRealtimeMonitoring $true`  

---

### 3. Simulated Credential Dump Execution

- **Timestamp:** Timestamp from `DeviceProcessEvents`  
- **Event:** Execution of fake Mimikatz logic via PowerShell.  
- **Command Line:** `powershell.exe -ExecutionPolicy Bypass -Command "sekurlsa::logonpasswords"`  

---

### 4. LSASS Memory Dump File Created

- **Timestamp:** Timestamp from `DeviceFileEvents`  
- **Event:** Simulated creation of `lsass.dmp` representing a memory dump of LSASS.  
- **Path:** `C:\Users\<User>\Desktop\lsass.dmp` or `%TEMP%\lsass.dmp`  

---

### 5. Simulated Exfiltration Attempt

- **Timestamp:** Timestamp from `DeviceNetworkEvents`  
- **Event:** PowerShell attempted to copy the dump file to a remote share over SMB.  
- **Remote IP:** `192.168.1.99` (simulated private IP for testing)  
- **Port:** Non-standard (not 80/443), likely SMB (445) or test port  

---

## Summary of Hunt Findings

A simulated credential dumping activity was conducted using a fake executable (`mimi-sim.exe`). The activity mimics techniques used by real attackers attempting to extract credentials from LSASS memory and exfiltrate the data. One device was identified with relevant indicators.

- **Affected Device**: `ad-stig-impleme`
- **Simulated Tools Used**: `mimi-sim.exe` and `PowerShell`
- **Key Behaviors Observed**:
  - Credential dump simulation using PowerShell
  - Fake LSASS memory dump creation
  - Simulated exfiltration to a private IP
  - Attempt to disable Windows Defender Real-Time Monitoring

---

## Response Taken

- Device `ad-stig-impleme` was **flagged for observation**; no real credentials were compromised.  
- Simulation logs were preserved for SOC detection rule validation.  
-Defender alerting was reviewed and confirmed to cover all key behaviors.



