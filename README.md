# PowerShell-LotL-Investigation-Lab

## Overview
This lab investigates a PowerShell-based Living-off-the-Land (LotL) attack where an attacker leveraged built-in Windows utilities to establish persistence and execute a second-stage payload. Using Kibana and Windows event logs, I analyzed the attack timeline, identified Indicators of Compromise (IOCs), and proposed remediation and prevention strategies.

## Objective
- Investigate an IDS alert involving a suspicious executable (r.exe)
- Determine attack timeline and persistence mechanisms
- Identify second-stage payload activity
- Extract IOCs
- Recommend mitigation and hardening measures

## Environment
- SIEM: Kibana (Lab data view)
- Time Range Analyzed: 2020-10-26 12:40:00 → 13:10:00 UTC
- Log Sources:
   - PowerShell ScriptBlock Logging (Event ID 4104)
   - Service Control Manager (Event ID 7045)
   - DNS logs
   - Process creation logs

## Attack Summary
An interactive PowerShell session under user ajane downloaded and installed a malicious executable (r.exe).

The attacker: 
 1. Created a Windows service named Caculator to execute r.exe
 2. Downloaded a second-stage payload (dogecoin.exe) from an AWS EC2 host
 3. Installed it as another auto-start service named PleaseDontFindMe
 4. Both services ran under LocalSystem, granting full system privileges
This demonstrates a textbook Living-off-the-Land persistence technique using PowerShell and the Service Control Manager.

## Investigation Methodology
**Key Queries Used (KQL)**
- Search initial file: "r.exe"
- PowerShell activity: winlog.user.name:"ajane" AND event.provider:"Microsoft-Windows-PowerShell"
- Service installations: winlog.event_id:7045
- Encoded commands: process.command_line:*EncodedCommand*
- Suspicious downloads: winlog.event_data.ScriptBlockText:(wget OR Invoke-WebRequest OR IEX OR "http")
- DNS pivot: dns.question.name:*ec2-18-188-226-178*

## Timeline of Events
| Time (UTC) | Event | Description                                         |
| ---------- | ----- | --------------------------------------------------- |
| 12:44:16   | 4104  | Attempted service creation (typo)                   |
| 12:44:26   | 4104  | Successful New-Service for r.exe                |
| 12:44:26   | 7045  | Service **Caculator** installed (Auto, LocalSystem) |
| 12:44:40   | 4104  | Encoded PowerShell command executed                 |
| 12:44:03   | DNS   | Resolution of AWS EC2 domain                        |
| 12:45:35   | 7045  | Service **PleaseDontFindMe** installed              |

## Indicators of Compromise (IOCs)
| Type            | Indicator                                          |
| --------------- | -------------------------------------------------- |
| Victim Host     | DESKTOP-TDCA5J5                                    |
| Victim IP       | 192.168.36.174                                     |
| User            | ajane                                              |
| Initial Payload | C:\Users\ajane\Downloads\r.exe                     |
| Service Name    | Caculator                                          |
| Second Payload  | C:\Users\ajane\Downloads\dogecoin.exe              |
| Second Service  | PleaseDontFindMe                                   |
| External Domain | ec2-18-188-226-178.us-east-2.compute.amazonaws.com |
| External IP     | 18.188.226.178                                     |

## Analysis
**Evidence of Persistence**
PowerShell created a Windows service pointing to r.exe, confirming execution via Service Control Manager.
**Second-Stage Download**
An encoded PowerShell command downloaded dogecoin.exe from AWS EC2, which was then installed as another auto-start service.
**Behavioral Indicators**
- Use of New-Service
- Encoded PowerShell commands
- Download from external EC2 host
- Services installed from user Downloads directory
- Auto-start with LocalSystem privileges
These behaviors strongly indicate malicious persistence using built-in Windows tools.

## Mitigation & Prevention
**Immediate Containment**
- Isolate infected host
- Delete malicious services
- Quarantine payloads
- Run full EDR/AV scan
**Detection Improvements**
- Enable full PowerShell ScriptBlock logging (4104)
- Alert on Event ID 7045 for services installed from user directories
- Monitor for -EncodedCommand, New-Service, wget 
**Hardening Measures**
- Implement AppLocker / WDAC
- Restrict local admin privileges
- Apply DNS and egress monitoring
- Block executables from user-writable directories
  
## Key Skills Demonstrated
- SIEM log analysis (Kibana)
- Windows event log investigation
- Timeline reconstruction
- IOC extraction
- PowerShell attack analysis
- Persistence mechanism identification
- Defensive security recommendations

## Conclusion
This investigation confirmed a PowerShell-based Living-off-the-Land attack that leveraged native Windows functionality to establish persistence and deploy a second-stage payload.

The attack highlights the importance of:
- PowerShell logging
- Service installation monitoring
- Egress filtering
- Least privilege enforcement
This lab strengthened my skills in incident investigation, log correlation, and detection engineering.

## Author
Durga Sai Sri Ramiredy </br>
Master's student - Cybersecurity </br>
University Of Houston

*This project was developed as part of academic coursework and expanded for cybersecurity portfolio demonstration.*
