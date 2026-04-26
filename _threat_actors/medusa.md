---
layout: threat_actor
title: "Medusa"
aliases: ["Medusa Ransomware"]
description: "Medusa is a long-time presence in the ransomware scene that stepped up its activities in late 2024, pushing past its previous limits."
permalink: /medusa/
country: "Unknown"
sector_focus: ["Healthcare", "Education", "Government", "Technology"]
first_seen: "2021"
last_activity: "2025"
risk_level: "High"
---

## Introduction
Medusa is a ransomware operation that has been a long-time presence in the ransomware scene but stepped up its activities in late 2024, pushing past its previous limits. The group has been involved in numerous attacks, contributing to the overall increase in ransomware incidents.

## Activities and Tactics
Medusa employs standard ransomware tactics with a focus on consistent operations. The group has been particularly active in targeting healthcare, education, and government sectors, maintaining a steady pace of attacks.

## Notable Campaigns
1. **Multilingual Extortion Operations**: Medusa pressured victims with multilingual communications and aggressive follow-up through voice and messaging platforms
2. **Critical-Sector Intrusions**: Public reporting repeatedly associated the group with healthcare, education, and government victims where outages increase leverage
3. **Remote Access and Application Abuse**: Intrusions commonly aligned with exposed services, phishing, and exploitation of internet-facing systems
4. **High-Pressure Leak Operations**: The group paired encryption with public-relations style leak-site pressure to accelerate negotiations

## Tactics, Techniques, and Procedures (TTPs)
Medusa is known for the following TTPs based on recent threat intelligence (2024-2025):

### Initial Access
- **Public-Facing Application Exploitation**: Exploiting vulnerabilities in public-facing applications and remote access services
- **Phishing Campaigns**: Conducting phishing campaigns for initial access
- **Remote Access Service Exploitation**: Targeting vulnerabilities in remote access systems

### Execution
- **Custom Executables**: Deploying custom executables and using command and scripting interpreters
- **Command and Scripting Interpreters**: Utilizing PowerShell and Bash for payload execution

### Persistence
- **Scheduled Task Configuration**: Configuring scheduled tasks for persistent access
- **System Service Installation**: Installing or modifying system services for persistence
- **Remote Access Tools**: Deploying legitimate remote access tools for sustained access

### Privilege Escalation
- **Credential Dumping**: Utilizing credential dumping techniques for privilege escalation
- **Account Abuse**: Abusing valid accounts for privilege escalation

### Defense Evasion
- **BYOVD Techniques**: Employing Bring Your Own Vulnerable Driver tactics to disable security solutions
- **Log Clearing**: Clearing system logs to evade detection
- **Obfuscation**: Using obfuscation techniques to hide malicious activity
- **Security Tool Tampering**: Disabling or tampering with endpoint security tools

### Exfiltration
- **Data Archiving**: Using tools like WinRAR to compress sensitive data
- **Cloud Services**: Exfiltrating data via cloud services and SFTP protocols
- **Double Extortion**: Threatening to leak exfiltrated data to pressure victims

### Unique Characteristics
- **Multilingual Extortion**: Employing aggressive, multilingual extortion tactics
- **Voice Message Threats**: Sending voice messages via platforms like WhatsApp or Teams in the victim's native language
- **Telegram Operations**: Maintaining public-facing "PR" operations via Telegram platforms

## Notable Indicators of Compromise (IOCs)
Based on recent threat intelligence from reliable sources (2025):

### Medusa-Specific IOCs
**Note**: Medusa is known for using outdated PowerShell versions and aggressive multilingual extortion tactics.

### PowerShell 1.0 Usage
- **Defense Evasion**: Use of PowerShell 1.0 to bypass script execution policy restrictions
- **Antivirus Bypass**: Adding core operating system directories to antivirus exclusion lists
- **File Transfer Monitoring**: Monitoring peer-to-peer file transfers within victim networks

### Communication Methods
- **WhatsApp**: Sending voice message threats to victims
- **Microsoft Teams**: Platform for delivering voice message threats
- **Telegram**: Maintaining public-facing leak site operations and broadcasting new victims

### Multilingual Capabilities
- **Native Language Communication**: Ability to communicate in victims' native languages
- **Voice Message Delivery**: Sending threatening voice messages to increase pressure
- **Public Relations Operations**: Maintaining Telegram channels for victim shaming

### Sources
- [Cisco Talos IR Trends Q2 2025](https://blog.talosintelligence.com/ir-trends-q2-2025/) - 2025
- [CISA Advisory AA25-071A](https://www.cisa.gov/stopransomware/official-alerts-statements-cisa) - February 2025

## Emulating TTPs with Atomic Red Team
To emulate Medusa's TTPs, you can use Atomic Red Team's tests:
- **Ransomware Simulation**: [T1486 - Data Encrypted for Impact](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md)
- **Data Exfiltration**: [T1041 - Exfiltration Over C2 Channel](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md)
- **Network Discovery**: [T1018 - Remote System Discovery](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md)

## Malware and Tools
Based on recent threat intelligence (2024-2025), Medusa uses the following tools:

### Credential Access Tools
- **Mimikatz**: Credential dumping tool for extracting passwords and authentication tokens

### Data Exfiltration Tools
- **WinRAR**: File archiving utility for compressing data before exfiltration
- **Rclone**: Command-line program for transferring data to cloud services
- **WinSCP**: Secure file transfer tool for data exfiltration

### Execution Tools
- **PowerShell**: Command-line shell and scripting language for payload execution
- **Bash**: Unix shell for command execution and automation
- **Custom Ransomware**: Custom ransomware variants with fast encryption algorithms

### Persistence Tools
- **Scheduled Task Creation**: Utilities for creating persistent scheduled tasks
- **System Service Modification**: Tools for creating or modifying system services
- **Remote Access Tools**: Tools for maintaining persistent access

### Communication Tools
- **WhatsApp**: Used for sending voice message threats to victims
- **Microsoft Teams**: Platform for delivering voice message threats
- **Telegram**: Maintaining public-facing leak site operations and broadcasting new victims

### Unique Operational Features
- **Multilingual Capabilities**: Ability to communicate in victims' native languages
- **Voice Message Delivery**: Sending threatening voice messages to increase pressure
- **Public Relations Operations**: Maintaining Telegram channels for victim shaming and pressure tactics

## Attribution and Evidence
Cybersecurity researchers are still investigating Medusa's origins and attribution. The group's long-term presence and recent activity increase suggest experienced ransomware operators.

## References
1. **CyberProof Mid-Year Threat Landscape Report 2025**: [Link to report](https://www.cyberproof.com/blog/mid-year-threat-landscape-report-top-ransomware-trends-ttps-and-defense-strategies-for-2025/)
2. **WNY Cyber Current Threat Data**: [Link to analysis](https://www.wnycyber.com/Current-Threat-Data.php?id=3775)
3. **Cyber Insurance Academy Guide**: [Link to guide](https://www.cyberinsuranceacademy.com/blog/guides/4-ransomware-gangs-you-need-to-know/)
4. **Cyble Blog on Ransomware Groups July 2025**: [Link to analysis](https://cyble.com/blog/ransomware-groups-july-2025-attacks/)

## External Links
- [Wikipedia on Medusa](https://en.wikipedia.org/wiki/Medusa_ransomware)
