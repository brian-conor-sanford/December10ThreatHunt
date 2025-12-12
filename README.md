# December10ThreatHunt
Incident Response report from Threat Hunt
<img width="438" height="690" alt="image" src="https://github.com/user-attachments/assets/f6cd53e5-ec26-4fa7-bb3a-2bcc53912b61" />

📝 INCIDENT RESPONSE REPORT

Date of Report: 2025-12-10
Severity Level: HIGH
Report Status: Open
Escalated To: Incident Response Team
Incident ID: AZUKI-2025-TH-DEC10
Analyst: Brian Sanford

📌 SUMMARY OF FINDINGS

Attacker returned approximately 72 hours after initial access on 11/19.
Successful RemoteInteractive login using compromised account kenji.sato.
Lateral movement via mstsc.exe to azuki-fileserver01.
Evidence of discovery, privilege enumeration, staging, credential dumping, and exfiltration.
Use of persistence mechanisms, log deletion, and anti-forensics techniques.

🔍 WHO, WHAT, WHEN, WHERE, WHY, HOW

👤 WHO

Attacker Source IPs
Initial Access IP: 159.26.106.98
Later Movement: 10.1.0.108
External C2: 78.141.196.6
Compromised
Accounts: fileadmin
Systems: azuki-fileserver01

📂 WHAT (Event Summary)

Initial access via RemoteInteractive logon from 159.26.106.98 using compromised credentials.
Attacker returned 72 hours later from 10.1.0.108 to azuki-fileserver01.
Lateral movement using:
mstsc.exe /v:10.1.0.108
Share enumeration via net1 share.
Remote share enumeration using UNC paths.
Privilege enumeration: whoami.exe /all.
Network configuration enumeration: ipconfig.exe /all.
Directory hiding: attrib.exe +h +s C:\Windows\Logs\CBS.
Staging directory created: C:\Windows\Logs\CBS.
Script downloaded using certutil.exe.
Credential file created: IT-Admin-Passwords.csv.
Recursive copy via xcopy.exe.
Credential compression via tar.exe.
Renamed credential dumping tool: pd.exe.
LSASS dump created: pd.exe -accepteula -ma.
Exfiltration via curl.exe -F.
Cloud storage used: file.io.
Persistence established: autorun key FileShareSync.
Malicious beacon: svchost.ps1.
PowerShell history deleted: ConsoleHost_history.txt.

⏱ WHEN (UTC Timeline)
11/19 – Initial access.
11/22 – Attacker returns (72 hours later), conducts lateral movement.
11/22 – Discovery, privilege escalation, staging, credential dumping, exfiltration.

🖥 WHERE (Infrastructure Impact)
Compromised Host
azuki-fileserver01
Attacker Infrastructure
External IPs: 159.26.106.98, 78.141.196.6
Internal movement IP: 10.1.0.108
Malware / Staging Locations
C:\Windows\Logs\CBS
C:\Windows\System32\svchost.ps1
C:\Windows\Logs\CBS\credentials.tar.gz
C:\Windows\Logs\CBS\lsass.dmp

❓ WHY
Root Cause
Compromised credentials enabling unauthorized remote access.
Attacker Objective
Access privileged credentials
Exfiltrate sensitive administrative data

⚙️ HOW (Full Attack Chain)

Remote login using compromised credentials (kenji.sato).
Attacker returns from internal IP 10.1.0.108.
Lateral movement via mstsc.exe.
Share enumeration (net1 share).
UNC path discovery.
Privilege enumeration (whoami /all).
Network enumeration (ipconfig /all).
Hidden directory created using attrib.exe.
Malicious script downloaded using certutil.exe.
Folder copied using xcopy.exe.
Credential CSV generated.
Credentials compressed with tar.exe.
LSASS dumped using pd.exe.
Data exfiltrated via curl.exe → file.io.
Persistence added via registry autorun.
Malicious PowerShell file executed (svchost.ps1).
PowerShell history deleted.

🚨 IMPACT ASSESSMENT
Actual Impact
Credential compromise
Privileged account takeover
Exfiltration of sensitive IT admin data
LSASS dump theft
Persistence established
Risk Level: CRITICAL

🛠 RECOMMENDATIONS

🔥 IMMEDIATE
Disable kenji.sato and fileadmin accounts
Disconnect azuki-fileserver01 from the network
Block 78.141.196.6
Reset all privileged credentials

⏳ SHORT-TERM (1–7 Days)
Enterprise-wide credential reset
Rebuild azuki-fileserver01
Audit registry autoruns domain-wide
Deploy improved RDP monitoring

🛡 LONG-TERM
Enforce MFA for all privileged accounts
Implement network segmentation for file servers
Deploy EDR with LSASS protection
Monitor for suspicious tool usage: certutil, tar, xcopy, curl

📎 APPENDIX A — INDICATORS OF COMPROMISE (IOCs)
Attacker IPs
159.26.106.98
78.141.196.6
Malicious Files
svchost.ps1
credentials.tar.gz
lsass.dmp
ex.ps1
Accounts
fileadmin
kenji.sato

👁️ APPENDIX B — MITRE ATT&CK MAPPING

Tactic	Technique	ID
Initial Access	Remote Services	T1133
Execution	PowerShell	T1059.001
Persistence	Registry Run Keys	T1547.001
Defense Evasion	Hidden Directory	T1564
Credential Access	LSASS Dump	T1003.001
Discovery	Network Share Discovery	T1135
Lateral Movement	RDP	T1021.001
Exfiltration	Exfiltration Over Web Service	T1567

🗓 APPENDIX C — INVESTIGATION TIMELINE

11/19 – Initial access from 159.26.106.98
11/22 – RemoteInteractive login (compromised account)
11/22 – Lateral movement
11/22 – Discovery, staging, credential dumping
11/22 – Exfiltration to file.io
11/22 – Persistence and log tampering

📚 APPENDIX D — KQL QUERIES

Query 1 – Starting Point
'''DeviceLogonEvents
| where Timestamp >= datetime(2025-11-19)
| where Timestamp < datetime(2025-11-19) + 7d
| where DeviceName contains "azuki"'''

Query 2 – RemoteInteractive Login
'''DeviceLogonEvents
| where Timestamp >= datetime(2025-11-19)
| where Timestamp < datetime(2025-11-19) + 7d
| where AccountName contains "kenji.sato"
| where LogonType == "RemoteInteractive"
| project Timestamp, DeviceName, AccountName, LogonType, ActionType, RemoteIP, RemoteDeviceName
| order by Timestamp asc'''

Query 3 – MSTSC Lateral Movement
'''DeviceProcessEvents
| where Timestamp >= datetime(2025-11-19)
| where Timestamp < datetime(2025-11-19) + 7d
| where ProcessCommandLine contains "mstsc.exe"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| sort by Timestamp asc'''

Query 4 – Failed then Successful Attempts
'''DeviceLogonEvents
| where Timestamp >= datetime(2025-11-19)
| where Timestamp < datetime(2025-11-19) + 7d
| where RemoteIP == "10.1.0.108"
| project Timestamp, DeviceName, AccountName, ActionType, RemoteIP
| sort by Timestamp asc'''

Query 5 – Share Enumeration
'''DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where AccountName == "fileadmin"
| where Timestamp >= datetime(2025-11-19)
| where Timestamp < datetime(2025-11-19) + 7d
| where ProcessCommandLine contains "net"
| distinct ProcessCommandLine'''

Query 6 – UNC Path Enumeration
'''DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where AccountName == "fileadmin"
| where Timestamp >= datetime(2025-11-19)
| where Timestamp < datetime(2025-11-19) + 7d
| where ProcessCommandLine contains "\\"
| distinct ProcessCommandLine'''

Query 7 – Privilege Enumeration
'''DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where AccountName == "fileadmin"
| where Timestamp >= datetime(2025-11-19)
| where Timestamp < datetime(2025-11-19) + 7d
| where ProcessCommandLine contains "whoami"
| distinct ProcessCommandLine'''

Query 8 – IPConfig Enumeration
'''DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where AccountName == "fileadmin"
| where Timestamp >= datetime(2025-11-19)
| where Timestamp < datetime(2025-11-19) + 7d
| where ProcessCommandLine contains "ipconfig"
| distinct ProcessCommandLine'''

Query 9 – Attrib Hidden Directory
'''DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where AccountName == "fileadmin"
| where Timestamp >= datetime(2025-11-19)
| where Timestamp < datetime(2025-11-19) + 7d
| where ProcessCommandLine contains "attrib"
| distinct ProcessCommandLine'''

Query 10 – Certutil Download
'''DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where AccountName == "fileadmin"
| where Timestamp >= datetime(2025-11-19)
| where Timestamp < datetime(2025-11-19) + 7d
| where ProcessCommandLine contains "certutil"
| distinct ProcessCommandLine'''

Query 11 – CSV File Creation
'''DeviceFileEvents
| where DeviceName == "azuki-fileserver01"
| where Timestamp >= datetime(2025-11-19)
| where Timestamp < datetime(2025-11-19) + 7d
| where FileName has_any (".csv")
| project Timestamp, DeviceName, FileName, FolderPath, ActionType
| sort by Timestamp desc'''

Query 12 – Recursive Copy
'''DeviceFileEvents
| where DeviceName == "azuki-fileserver01"
| where Timestamp >= datetime(2025-11-19)
| where Timestamp < datetime(2025-11-19) + 7d
| where InitiatingProcessCommandLine has_any ("robo", "xcopy", "copy")
| project Timestamp, InitiatingProcessCommandLine, DeviceName, FileName, FolderPath, ActionType
| sort by Timestamp
| distinct InitiatingProcessCommandLine'''

Query 13 – Compression
'''DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where Timestamp >= datetime(2025-11-19)
| where Timestamp < datetime(2025-11-19) + 7d
| where FileName has_any ("7z.exe", "7za.exe", "zip", "tar.exe", "rar.exe", "winrar.exe", "gzip.exe")
| distinct ProcessCommandLine'''

Query 14 – Renamed Credential Tools
'''DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where Timestamp >= datetime(2025-11-19)
| where Timestamp < datetime(2025-11-19) + 7d
| where ProcessCommandLine has_any ("lsass", "lsass.exe", "comsvcs.dll", "MiniDump", "sekurlsa")
| distinct ProcessCommandLine'''

Query 15 – HTTP/HTTPS Exfiltration
'''DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where Timestamp >= datetime(2025-11-19)
| where Timestamp < datetime(2025-11-19) + 7d
| where ProcessCommandLine has_any ("http", "https")
| distinct ProcessCommandLine'''

Query 16 – Registry Persistence
'''DeviceRegistryEvents
| where DeviceName == "azuki-fileserver01"
| where Timestamp >= datetime(2025-11-19)
| where Timestamp < datetime(2025-11-19) + 7d
| where RegistryKey has_any (
    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
)
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated", "RegistryValueModified")
| project Timestamp, RegistryValueName, RegistryValueData, ActionType'''

Query 17 – Deleted PowerShell History
'''DeviceFileEvents
| where DeviceName == "azuki-fileserver01"
| where Timestamp >= datetime(2025-11-19)
| where Timestamp < datetime(2025-11-19) + 7d
| where ActionType == "FileDeleted"
| where FileName == "ConsoleHost_history.txt"
    or FolderPath has "\\Microsoft\\Windows\\PowerShell\\PSReadLine"
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc'''
