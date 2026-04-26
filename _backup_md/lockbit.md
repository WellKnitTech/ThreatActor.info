---
layout: threat_actor
title: "LockBit"
aliases: ["ABCD Ransomware"]
description: "LockBit is a ransomware-as-a-service operation known for its fast encryption and double extortion tactics."
permalink: /lockbit/
country: "Russia"
sector_focus: ["Critical Infrastructure", "Healthcare", "Education"]
first_seen: "2019"
last_activity: "2024"
risk_level: "Critical"
---

## Introduction
LockBit is a ransomware-as-a-service (RaaS) operation that has been active since 2019 and has become one of the most prolific ransomware groups. The group is known for its fast encryption capabilities and aggressive double extortion tactics, targeting organizations worldwide.

## Activities and Tactics
LockBit employs sophisticated ransomware tactics, including fast encryption, double extortion, and a well-organized affiliate program. The group has been particularly active in targeting critical infrastructure and healthcare organizations.

## Notable Campaigns
1. **Critical Infrastructure Targeting**: Attacks on water treatment facilities, power companies, and transportation systems
2. **Healthcare Sector**: Extensive targeting of hospitals and healthcare systems
3. **Education Sector**: Attacks on universities and school districts
4. **Government Entities**: Targeting of local and state government organizations

## Tactics, Techniques, and Procedures (TTPs)
LockBit is known for the following TTPs based on recent threat intelligence (2024-2025):

### Initial Access
- **Public-Facing Application Exploitation**: Exploiting vulnerabilities in public-facing applications and remote access services
- **Phishing Campaigns**: Conducting phishing campaigns for initial access
- **Remote Desktop Protocol Exploitation**: Targeting vulnerabilities in RDP systems

### Execution
- **Command and Scripting Interpreters**: Utilizing PowerShell and Bash for payload execution
- **Custom Executables**: Deploying ransomware payloads through various execution methods
- **Fast Encryption**: Rapid encryption of files to minimize detection

### Persistence
- **Scheduled Task Creation**: Creating scheduled tasks for persistent access
- **Registry Key Modification**: Modifying registry keys for persistence
- **User Account Manipulation**: Creating or reactivates user accounts to maintain access

### Privilege Escalation
- **Credential Dumping**: Utilizing tools like Mimikatz for credential dumping
- **Account Manipulation**: Creating or modifying user accounts for privilege escalation

### Defense Evasion
- **BYOVD Techniques**: Employing Bring Your Own Vulnerable Driver tactics to disable security solutions
- **Log Clearing**: Clearing system logs to evade detection
- **Security Tool Tampering**: Disabling or tampering with endpoint security tools
- **Obfuscation**: Using obfuscation techniques to hide malicious activity

### Exfiltration
- **Data Archiving**: Using tools like WinRAR to compress sensitive data
- **Cloud Services**: Exfiltrating data via cloud services and SFTP protocols
- **StealBit**: Custom data exfiltration tool
- **Double Extortion**: Threatening to leak exfiltrated data to pressure victims

## Notable Indicators of Compromise (IOCs)
Based on recent threat intelligence from reliable sources (2025):

### LockBit-Specific IOCs
**Note**: LockBit operates a ransomware-as-a-service model with specific infrastructure and tools.

### Known Infrastructure
- **Leak Sites**: Multiple Tor-based leak sites for victim shaming
- **StealBit Tool**: Custom data exfiltration tool developed by LockBit
- **Affiliate Program**: Well-organized affiliate recruitment and management

### File Extensions
- **LockBit 2.0**: `.lockbit`
- **LockBit 3.0**: `.lockbit3`
- **LockBit 4.0**: `.lockbit4`

### Ransom Notes
- **Filename**: `Restore-My-Files.txt`
- **Content**: Contains ransom demands and contact information
- **Language**: Multiple language support including English, Spanish, French

### Sources
- [CISA StopRansomware Official Alerts](https://www.cisa.gov/stopransomware/official-alerts-statements-cisa) - 2025
- [FBI Flash Alert on LockBit](https://www.ic3.gov/Media/News/2023/230601.pdf) - June 2023
- [CISA Advisory on LockBit Ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-075a) - March 2023

## Emulating TTPs with Atomic Red Team
To emulate LockBit's TTPs, you can use Atomic Red Team's tests:
- **Ransomware Simulation**: [T1486 - Data Encrypted for Impact](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md)
- **Data Exfiltration**: [T1041 - Exfiltration Over C2 Channel](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md)
- **Network Discovery**: [T1018 - Remote System Discovery](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md)

## Malware and Tools
Based on recent threat intelligence (2024-2025), LockBit uses the following tools:

### Data Exfiltration Tools
- **StealBit**: Custom data exfiltration tool developed by LockBit
- **WinRAR**: File archiving utility for compressing data before exfiltration
- **Rclone**: Command-line program for transferring data to cloud services

### Credential Access Tools
- **Mimikatz**: Credential dumping tool for extracting passwords and authentication tokens

### Execution Tools
- **PowerShell**: Command-line shell and scripting language for payload execution
- **Bash**: Unix shell for command execution and automation
- **LockBit Ransomware**: Custom ransomware variant with fast encryption capabilities

### Persistence Tools
- **Scheduled Task Creation**: Utilities for creating persistent scheduled tasks
- **Registry Key Modification**: Tools for modifying Windows registry keys
- **User Account Management**: Tools for creating or modifying user accounts

### RaaS Platform Features
- **Affiliate Program**: Well-organized affiliate program providing ransomware to affiliates
- **Initial Access Brokers**: Using third-party access to compromised networks
- **Living off the Land**: Extensive use of legitimate tools and techniques
- **Fast Encryption**: Rapid encryption capabilities to minimize detection time

## Attribution and Evidence
Cybersecurity researchers have attributed LockBit's activities to Russian cybercriminals based on various pieces of evidence, including malware code similarities, operational patterns, and the targeting of specific geopolitical interests.

## References
1. **CyberProof Mid-Year Threat Landscape Report 2025**: [Link to report](https://www.cyberproof.com/blog/mid-year-threat-landscape-report-top-ransomware-trends-ttps-and-defense-strategies-for-2025/)
2. **DeepStrike.io Ransomware Groups 2025**: [Link to analysis](https://deepstrike.io/blog/ransomware-groups-2025)
3. **BlackKite 2025 Ransomware Report**: [Link to report](https://content.blackkite.com/ebook/2025-ransomware-report/top-groups)
4. **CISA Alert on LockBit**: [Link to alert](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-249a)
5. **FBI Alert**: [Link to alert](https://www.ic3.gov/Media/News/2022/220601.pdf)

## External Links
- [Wikipedia on LockBit](https://en.wikipedia.org/wiki/LockBit)
- [MITRE ATT&CK - LockBit](https://attack.mitre.org/groups/G0082/)


