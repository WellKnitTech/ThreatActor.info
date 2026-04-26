---
layout: threat_actor
title: "SafePay"
aliases: ["SafePay Ransomware"]
description: "SafePay is a ransomware group particularly active in Germany, responsible for 24% of the 74 ransomware victims reported in the country during Q1 2025."
permalink: /safepay/
country: "Unknown"
sector_focus: ["Healthcare", "Logistics", "Manufacturing", "Government"]
first_seen: "2024"
last_activity: "2025"
risk_level: "High"
---

## Introduction
SafePay is a ransomware operation that has been particularly active in Germany, responsible for 24% of the 74 ransomware victims reported in the country during Q1 2025. The group's tactics include RDP/VPN brute-force attacks, credential stuffing, and double extortion, causing widespread disruptions, especially in healthcare and logistics environments.

## Activities and Tactics
SafePay employs aggressive ransomware tactics with a particular focus on German targets. The group uses RDP/VPN brute-force attacks and credential stuffing to gain initial access, then implements double extortion tactics to maximize pressure on victims.

## Notable Campaigns
1. **German Healthcare Targeting**: Extensive attacks on German hospitals and healthcare systems
2. **Logistics Sector**: Targeting of logistics and transportation companies
3. **Manufacturing**: Attacks on German manufacturing companies
4. **Government Entities**: Targeting of German government organizations

## Tactics, Techniques, and Procedures (TTPs)
SafePay is known for the following TTPs based on recent threat intelligence (2024-2025):

### Initial Access
- **Phishing Campaigns**: Gaining access through phishing campaigns and social engineering
- **Public-Facing Application Exploitation**: Exploiting vulnerabilities in public-facing applications
- **Remote Access Service Exploitation**: Targeting vulnerabilities in remote access services

### Execution
- **Command and Scripting Interpreters**: Utilizing PowerShell and Bash for payload execution
- **Custom Executables**: Deploying ransomware payloads through various execution methods

### Persistence
- **System Service Modification**: Creating or modifying system services for persistent access
- **Scheduled Task Configuration**: Configuring scheduled tasks for persistence
- **User Account Manipulation**: Creating or reactivates user accounts to maintain access

### Privilege Escalation
- **Credential Dumping**: Utilizing tools like Mimikatz for credential dumping
- **Account Manipulation**: Creating or modifying user accounts for privilege escalation

### Defense Evasion
- **BYOVD Techniques**: Employing Bring Your Own Vulnerable Driver tactics to disable security solutions
- **Log Clearing**: Clearing system logs to evade detection
- **Security Tool Tampering**: Disabling or tampering with endpoint security tools

### Exfiltration
- **Data Archiving**: Using tools like WinRAR to compress sensitive data
- **Cloud Services**: Exfiltrating data via cloud services and SFTP protocols
- **Double Extortion**: Threatening to leak exfiltrated data to pressure victims

## Notable Indicators of Compromise (IOCs)
Based on recent threat intelligence from reliable sources (2025):

### SafePay-Specific IOCs
**Note**: SafePay is known for its specific focus on German organizations and regional specialization.

### Geographic Focus
- **German Targeting**: Specific focus on German organizations, responsible for 24% of German ransomware victims in Q1 2025
- **Regional Specialization**: Concentrated attacks on German healthcare, logistics, and manufacturing sectors

### Attack Patterns
- **Phishing Campaigns**: Gaining access through phishing campaigns and social engineering
- **Public-Facing Application Exploitation**: Exploiting vulnerabilities in public-facing applications
- **Remote Access Service Exploitation**: Targeting vulnerabilities in remote access services

### File Extensions
- **SafePay Ransomware**: Custom file extensions for encrypted files
- **Ransom Notes**: Specific ransom note format and content

### Persistence Mechanisms
- **Scheduled Task Creation**: Utilities for creating persistent scheduled tasks
- **System Service Modification**: Tools for creating or modifying system services
- **User Account Management**: Tools for creating or modifying user accounts

### Sources
- [CISA StopRansomware Official Alerts](https://www.cisa.gov/stopransomware/official-alerts-statements-cisa) - 2025
- [German BSI Threat Intelligence Reports](https://www.bsi.bund.de/) - 2025

## Emulating TTPs with Atomic Red Team
To emulate SafePay's TTPs, you can use Atomic Red Team's tests:
- **Brute Force Attacks**: [T1110 - Brute Force](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110/T1110.md)
- **Ransomware Simulation**: [T1486 - Data Encrypted for Impact](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md)
- **Data Exfiltration**: [T1041 - Exfiltration Over C2 Channel](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md)

## Malware and Tools
Based on recent threat intelligence (2024-2025), SafePay uses the following tools:

### Credential Access Tools
- **Mimikatz**: Credential dumping tool for extracting passwords and authentication tokens

### Data Exfiltration Tools
- **WinRAR**: File archiving utility for compressing data before exfiltration
- **Rclone**: Command-line program for transferring data to cloud services

### Execution Tools
- **PowerShell**: Command-line shell and scripting language for payload execution
- **Bash**: Unix shell for command execution and automation
- **Custom Ransomware**: Custom ransomware payloads with evolving capabilities

### Persistence Tools
- **Scheduled Task Creation**: Utilities for creating persistent scheduled tasks
- **System Service Modification**: Tools for creating or modifying system services
- **User Account Management**: Tools for creating or modifying user accounts

### Geographic Focus
- **German Targeting**: Specific focus on German organizations, responsible for 24% of German ransomware victims in Q1 2025
- **Regional Specialization**: Concentrated attacks on German healthcare, logistics, and manufacturing sectors

## Attribution and Evidence
Cybersecurity researchers are still investigating SafePay's origins and attribution. The group's focus on German targets and aggressive tactics suggest experienced ransomware operators.

## References
1. **CyberProof Mid-Year Threat Landscape Report 2025**: [Link to report](https://www.cyberproof.com/blog/mid-year-threat-landscape-report-top-ransomware-trends-ttps-and-defense-strategies-for-2025/)
2. **WNY Cyber Current Threat Data**: [Link to analysis](https://www.wnycyber.com/Current-Threat-Data.php?id=3775)
3. **Cyble Blog on Ransomware Groups July 2025**: [Link to analysis](https://cyble.com/blog/ransomware-groups-july-2025-attacks/)

## External Links
- [Wikipedia on SafePay](https://en.wikipedia.org/wiki/SafePay_ransomware)
