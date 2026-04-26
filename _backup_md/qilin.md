---
layout: threat_actor
title: "Qilin"
aliases: ["Qilin Ransomware"]
description: "Qilin is a ransomware group that first appeared in 2022 but had a breakout year in 2024, with around 200 victims, 156 of them based in the U.S."
permalink: /qilin/
country: "Unknown"
sector_focus: ["Critical Infrastructure", "Manufacturing", "Healthcare", "Government"]
first_seen: "2022"
last_activity: "2025"
risk_level: "High"
---

## Introduction
Qilin is a ransomware operation that first appeared in 2022 but had a breakout year in 2024, with around 200 victims—156 of them based in the U.S. The group has targeted critical infrastructure and manufacturing sectors, causing significant disruptions.

## Activities and Tactics
Qilin employs sophisticated ransomware tactics with a particular focus on critical infrastructure and manufacturing. The group has been particularly active in targeting U.S.-based organizations, causing significant operational disruptions.

## Notable Campaigns
1. **Critical Infrastructure Targeting**: Attacks on power companies, water treatment facilities, and transportation systems
2. **Manufacturing Sector**: Extensive targeting of industrial and manufacturing companies
3. **Healthcare Targeting**: Attacks on hospitals and healthcare systems
4. **U.S. Focus**: Significant targeting of U.S.-based organizations

## Tactics, Techniques, and Procedures (TTPs)
Qilin is known for the following TTPs based on recent threat intelligence (2024-2025):

### Initial Access
- **Backup Platform Exploitation**: Targeting vulnerabilities in backup and virtualization platforms like Veeam
- **VPN Abuse**: Exploiting compromised VPNs for initial access
- **External Remote Services**: Abusing compromised remote access systems

### Execution
- **Advanced Loaders**: Using NETXLOADER and SmokeLoader for in-memory execution to bypass security controls
- **Command and Scripting Interpreters**: Utilizing PowerShell and Bash for payload execution
- **Custom Executables**: Deploying ransomware payloads through various execution methods

### Persistence
- **System Service Modification**: Installing or modifying system services for persistent access
- **Scheduled Task Configuration**: Configuring scheduled tasks for persistence
- **Remote Access Tools**: Deploying legitimate remote access tools like AnyDesk and Radmin

### Privilege Escalation
- **Credential Dumping**: Employing credential dumping techniques and Kerberos ticket theft
- **Active Directory Manipulation**: Engaging in deeper Active Directory manipulation
- **Kerberos Ticket Abuse**: Stealing and abusing Kerberos tickets for privilege escalation

### Defense Evasion
- **BYOVD Techniques**: Adopting Bring Your Own Vulnerable Driver techniques to bypass endpoint detection and antivirus solutions
- **Log Clearing**: Employing advanced log clearing methods to evade detection
- **Obfuscation**: Using obfuscation techniques to hide malicious activity

### Impact
- **Disk Space Overwriting**: Overwriting free disk space after encryption, making data recovery virtually impossible
- **Backup Deletion**: Deleting backups to prevent recovery
- **Double Extortion**: Threatening to leak exfiltrated data to pressure victims

## Notable Indicators of Compromise (IOCs)
Based on recent threat intelligence from reliable sources (2025):

### Qilin-Specific IOCs
**Note**: Qilin is a sophisticated ransomware-as-a-service operation with advanced evasion techniques.

### Infrastructure
- **Backblaze C2**: Use of Backblaze-hosted command and control infrastructure
- **CyberDuck**: Deployment of CyberDuck for data exfiltration
- **Custom Encryptors**: Hardcoded victim credentials in compiled encryptors

### RMM Tools Used
- **TeamViewer**: Remote access and control
- **VNC**: Virtual Network Computing for remote access
- **AnyDesk**: Remote desktop software
- **Chrome Remote Desktop**: Google's remote access solution
- **Distant Desktop**: Remote access tool
- **QuickAssist**: Microsoft's remote assistance tool
- **ToDesk**: Remote desktop software

### Persistence Mechanisms
- **AutoRun Entries**: Creation in Software registry Hive
- **Scheduled Tasks**: For persistent access and ransomware execution
- **System Reboot Triggers**: Execution upon system reboot or user logon

### Sources
- [Cisco Talos IR Trends Q2 2025](https://blog.talosintelligence.com/ir-trends-q2-2025/) - 2025
- [CISA StopRansomware Official Alerts](https://www.cisa.gov/stopransomware/official-alerts-statements-cisa) - 2025

## Emulating TTPs with Atomic Red Team
To emulate Qilin's TTPs, you can use Atomic Red Team's tests:
- **Ransomware Simulation**: [T1486 - Data Encrypted for Impact](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md)
- **Data Exfiltration**: [T1041 - Exfiltration Over C2 Channel](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md)
- **Network Discovery**: [T1018 - Remote System Discovery](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md)

## Malware and Tools
Based on recent threat intelligence (2024-2025), Qilin uses the following tools:

### Advanced Loaders
- **NETXLOADER**: Advanced loader for in-memory execution to bypass security controls
- **SmokeLoader**: Sophisticated loader used for payload delivery and execution

### Remote Access Tools
- **AnyDesk**: Legitimate remote desktop software used for persistent access
- **Radmin**: Remote administration tool for maintaining access to compromised systems

### Credential Access Tools
- **Mimikatz**: Credential dumping tool for extracting passwords and authentication tokens
- **Kerberos Ticket Tools**: Utilities for stealing and abusing Kerberos tickets

### Data Exfiltration Tools
- **WinRAR**: File archiving utility for compressing data before exfiltration
- **Rclone**: Command-line program for transferring data to cloud services

### Execution Tools
- **PowerShell**: Command-line shell and scripting language for payload execution
- **Bash**: Unix shell for command execution and automation
- **Custom Ransomware**: Sophisticated RaaS platform with advanced evasion techniques

### RaaS Platform Features
- **Legal Guidance Services**: Offering affiliates legal guidance and other services
- **"Call Lawyer" Feature**: Psychological pressure tactic integrated into affiliate panels
- **Spam Distribution**: Providing spam distribution services to affiliates
- **DDoS Attack Services**: Offering DDoS attack capabilities

## Attribution and Evidence
Cybersecurity researchers are still investigating Qilin's origins and attribution. The group's focus on U.S. targets and critical infrastructure suggests potential geopolitical motivations.

## References
1. **CyberProof Mid-Year Threat Landscape Report 2025**: [Link to report](https://www.cyberproof.com/blog/mid-year-threat-landscape-report-top-ransomware-trends-ttps-and-defense-strategies-for-2025/)
2. **DeepStrike.io Ransomware Groups 2025**: [Link to analysis](https://deepstrike.io/blog/ransomware-groups-2025)
3. **CYFIRMA Tracking Ransomware June 2025**: [Link to analysis](https://www.cyfirma.com/research/tracking-ransomware-june-2025/)
4. **Cyble Blog on Top Ransomware Groups June 2025**: [Link to analysis](https://cyble.com/blog/top-ransomware-groups-june-2025-qilin-top-spot/)

## External Links
- [Wikipedia on Qilin](https://en.wikipedia.org/wiki/Qilin_ransomware)
