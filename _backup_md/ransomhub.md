---
layout: threat_actor
title: "RansomHub"
aliases: ["RansomHub RaaS"]
description: "RansomHub is a dominant ransomware-as-a-service operation that emerged in 2024 and quickly became the most prolific group with 736 disclosed victims."
permalink: /ransomhub/
country: "Unknown"
sector_focus: ["Critical Infrastructure", "Healthcare", "Education", "Manufacturing"]
first_seen: "2024"
last_activity: "2025"
risk_level: "Critical"
---

## Introduction
RansomHub is a ransomware-as-a-service (RaaS) operation that emerged in 2024 and quickly became the most dominant force in the ransomware landscape. The group disclosed 736 victims in 2024, the highest among all ransomware groups, and has maintained strong operational discipline and stable leadership.

## Activities and Tactics
RansomHub employs sophisticated ransomware tactics with effective encryptors and measured yet threatening communications. The group has attracted many former affiliates from other ransomware groups, contributing to its widespread attacks and rapid growth.

## Notable Campaigns
1. **Critical Infrastructure Targeting**: Attacks on power companies, water treatment facilities, and transportation systems
2. **Healthcare Sector**: Extensive targeting of hospitals and healthcare systems
3. **Education Sector**: Attacks on universities and school districts
4. **Manufacturing**: Targeting of industrial and manufacturing companies

## Tactics, Techniques, and Procedures (TTPs)
RansomHub is known for the following TTPs based on recent threat intelligence (2024-2025):

### Initial Access
- **Phishing Campaigns**: Gaining access through malicious attachments and social engineering
- **Credential Abuse**: Exploiting compromised credentials for initial access
- **Malicious Attachments**: Using email attachments to deliver payloads

### Execution
- **Command and Scripting Interpreters**: Utilizing PowerShell and Bash for payload execution
- **Custom Executables**: Deploying ransomware payloads through various execution methods

### Persistence
- **User Account Manipulation**: Creating or reactivates user accounts to maintain access
- **Registry Key Manipulation**: Modifying registry keys for persistent access
- **Scheduled Tasks**: Creating malicious scheduled tasks for persistence

### Privilege Escalation
- **Credential Dumping**: Utilizing LSASS memory scraping and tools like Mimikatz
- **Kerberos Ticket Theft**: Stealing Kerberos tickets for privilege escalation
- **Account Manipulation**: Creating or modifying user accounts

### Defense Evasion
- **BYOVD Techniques**: Employing Bring Your Own Vulnerable Driver tactics to disable security solutions
- **Log Clearing**: Clearing system logs to evade detection
- **Obfuscation**: Using obfuscation techniques to hide malicious activity
- **Security Tool Tampering**: Disabling or tampering with endpoint security tools

### Exfiltration
- **Data Archiving**: Using tools like WinRAR to compress sensitive data
- **Cloud Services**: Exfiltrating data via cloud services and SFTP protocols
- **Double Extortion**: Threatening to leak exfiltrated data to pressure victims

## Notable Indicators of Compromise (IOCs)
Based on recent threat intelligence from reliable sources (2025):

### RansomHub-Specific IOCs
**Note**: RansomHub is a ransomware-as-a-service operation that emerged from the rebranding of previous groups.

### EDR Evasion Tools
- **EDRKillShifter**: Custom EDR killer tool using Bring Your Own Vulnerable Driver (BYOVD) technique
- **BYOVD Techniques**: Employing vulnerable drivers to terminate security solutions

### File Extensions
- **RansomHub Ransomware**: Custom file extensions for encrypted files
- **Ransom Notes**: Specific ransom note format and content

### Attack Patterns
- **Phishing Campaigns**: Gaining access through malicious attachments and social engineering
- **Credential Abuse**: Exploiting compromised credentials for initial access
- **Double Extortion**: Threatening to leak exfiltrated data to pressure victims

### Sources
- [CISA Advisory AA24-242A](https://www.cisa.gov/stopransomware/official-alerts-statements-cisa) - August 2024
- [CISA StopRansomware Official Alerts](https://www.cisa.gov/stopransomware/official-alerts-statements-cisa) - 2025

## Emulating TTPs with Atomic Red Team
To emulate RansomHub's TTPs, you can use Atomic Red Team's tests:
- **Ransomware Simulation**: [T1486 - Data Encrypted for Impact](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md)
- **Data Exfiltration**: [T1041 - Exfiltration Over C2 Channel](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md)
- **Network Discovery**: [T1018 - Remote System Discovery](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md)

## Malware and Tools
Based on recent threat intelligence (2024-2025), RansomHub uses the following tools:

### EDR Evasion Tools
- **EDRKillShifter**: Custom EDR killer tool using Bring Your Own Vulnerable Driver (BYOVD) technique to terminate security solutions

### Credential Access Tools
- **Mimikatz**: Credential dumping tool for extracting passwords and authentication tokens
- **LSASS Memory Scraping**: Techniques for extracting credentials from memory

### Data Exfiltration Tools
- **WinRAR**: File archiving utility for compressing data before exfiltration
- **Rclone**: Command-line program for transferring data to cloud services

### Execution Tools
- **PowerShell**: Command-line shell and scripting language for payload execution
- **Bash**: Unix shell for command execution and automation
- **Custom Ransomware**: Effective encryptors provided to affiliates

### Persistence Tools
- **Registry Manipulation**: Tools for modifying Windows registry keys
- **Scheduled Task Creation**: Utilities for creating persistent scheduled tasks
- **User Account Management**: Tools for creating or modifying user accounts

## Attribution and Evidence
Cybersecurity researchers are still investigating RansomHub's origins and attribution. The group's operational patterns and communication style suggest experienced ransomware operators, possibly with connections to other established groups.

## References
1. **CyberProof Mid-Year Threat Landscape Report 2025**: [Link to report](https://www.cyberproof.com/blog/mid-year-threat-landscape-report-top-ransomware-trends-ttps-and-defense-strategies-for-2025/)
2. **DeepStrike.io Ransomware Groups 2025**: [Link to analysis](https://deepstrike.io/blog/ransomware-groups-2025)
3. **SLCyber Blog on Prolific Ransomware Groups**: [Link to analysis](https://slcyber.io/blog/the-most-prolific-ransomware-groups-to-be-aware-of-now/)
4. **BlackKite 2025 Ransomware Report**: [Link to report](https://content.blackkite.com/ebook/2025-ransomware-report/top-groups)

## External Links
- [Wikipedia on RansomHub](https://en.wikipedia.org/wiki/RansomHub)
