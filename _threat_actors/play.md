---
layout: threat_actor
title: "Play"
aliases: ["Play Ransomware"]
description: "Play is a ransomware group that emerged quietly in 2022, found its footing in 2023, and made a notable leap in 2024 with 369 disclosed victims."
permalink: /play/
country: "Unknown"
sector_focus: ["Healthcare", "Education", "Government", "Technology"]
first_seen: "2022"
last_activity: "2025"
risk_level: "High"
---

## Introduction
Play is a ransomware operation that emerged quietly in 2022, found its footing in 2023, and made a notable leap in 2024 with 369 disclosed victims. The group focuses on operational execution rather than media theatrics, with victim disclosures designed to apply direct pressure on targets.

## Activities and Tactics
Play employs efficient ransomware tactics with a focus on operational execution. The group has been particularly active in targeting healthcare, education, and government sectors, maintaining a steady pace of attacks without extensive media attention.

## Notable Campaigns
1. **2024 Victim Surge**: Public disclosures increased sharply in 2024 as Play expanded the pace and visibility of its extortion operations
2. **ESXi and Linux Targeting**: Reporting tied the group to Linux variants and VMware ESXi-focused intrusions rather than Windows-only operations
3. **Critical-Sector Pressure Campaigns**: Healthcare, education, and government victims appeared repeatedly in public reporting
4. **BYOVD-Enabled Intrusions**: Operations increasingly aligned with EDR-killing tools and bring-your-own-vulnerable-driver tradecraft

## Tactics, Techniques, and Procedures (TTPs)
Play is known for the following TTPs based on recent threat intelligence (2024-2025):

### Initial Access
- **Public-Facing Application Exploitation**: Exploiting vulnerabilities in public-facing applications and remote access services
- **Remote Access Service Exploitation**: Targeting vulnerabilities in remote access systems

### Execution
- **Custom Executables**: Deploying custom executables and using command and scripting interpreters
- **Linux ESXi Targeting**: Deploying Linux variants specifically targeting VMware ESXi environments
- **Command and Scripting Interpreters**: Utilizing PowerShell and Bash for payload execution

### Persistence
- **Scheduled Task Configuration**: Configuring scheduled tasks for persistent access
- **System Service Installation**: Installing or modifying system services for persistence
- **Remote Access Tools**: Deploying legitimate remote access tools for sustained access

### Privilege Escalation
- **Credential Dumping**: Utilizing credential dumping techniques for privilege escalation
- **Account Abuse**: Abusing valid accounts for privilege escalation

### Defense Evasion
- **EDR Killing**: Deploying EDR killers like EDRKillShifter using BYOVD tactics to terminate security solutions
- **BYOVD Techniques**: Employing Bring Your Own Vulnerable Driver techniques
- **Log Clearing**: Clearing system logs to evade detection
- **Obfuscation**: Using obfuscation techniques to hide malicious activity

### Exfiltration
- **Data Archiving**: Using tools like WinRAR to compress sensitive data
- **Cloud Services**: Exfiltrating data via cloud services and SFTP protocols
- **Double Extortion**: Threatening to leak exfiltrated data to pressure victims

## Notable Indicators of Compromise (IOCs)
Based on recent threat intelligence from reliable sources (2025):

### Play-Specific IOCs
**Note**: Play is known for sharing tactics with other ransomware operations and targeting ESXi environments.

### File Extensions
- **Play Ransomware**: `.play`

### EDR Evasion Tools
- **EDRKillShifter**: EDR killer tool using Bring Your Own Vulnerable Driver (BYOVD) technique

### Ransomware Variants
- **Play Ransomware**: Custom ransomware that appends the ".play" extension to encrypted files
- **Linux ESXi Variant**: Linux variant specifically targeting VMware ESXi environments

### Attack Patterns
- **Public-Facing Application Exploitation**: Exploiting vulnerabilities in public-facing applications and remote access services
- **Linux ESXi Targeting**: Deploying Linux variants specifically targeting VMware ESXi environments
- **Tactical Sharing**: Shares tactics with ransomware operations like Nokoyawa and Hive

### Operational Characteristics
- **Infrastructure Sharing**: Possible shared infrastructure with other ransomware groups

### Sources
- [CISA StopRansomware Official Alerts](https://www.cisa.gov/stopransomware/official-alerts-statements-cisa) - 2025
- [FBI Flash Alert on Play Ransomware](https://www.ic3.gov/Media/News/2023/230601.pdf) - June 2023

## Emulating TTPs with Atomic Red Team
To emulate Play's TTPs, you can use Atomic Red Team's tests:
- **Ransomware Simulation**: [T1486 - Data Encrypted for Impact](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md)
- **Data Exfiltration**: [T1041 - Exfiltration Over C2 Channel](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md)
- **Network Discovery**: [T1018 - Remote System Discovery](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md)

## Malware and Tools
Based on recent threat intelligence (2024-2025), Play uses the following tools:

### EDR Evasion Tools
- **EDRKillShifter**: EDR killer tool using Bring Your Own Vulnerable Driver (BYOVD) technique to terminate security solutions

### Ransomware Variants
- **Play Ransomware**: Custom ransomware that appends the ".play" extension to encrypted files
- **Linux ESXi Variant**: Linux variant specifically targeting VMware ESXi environments

### Credential Access Tools
- **Mimikatz**: Credential dumping tool for extracting passwords and authentication tokens

### Data Exfiltration Tools
- **WinRAR**: File archiving utility for compressing data before exfiltration
- **Rclone**: Command-line program for transferring data to cloud services

### Execution Tools
- **PowerShell**: Command-line shell and scripting language for payload execution
- **Bash**: Unix shell for command execution and automation
- **Custom Executables**: Malware masquerading as legitimate processes

### Operational Characteristics
- **Tactical Sharing**: Shares tactics with ransomware operations like Nokoyawa and Hive, suggesting operational connections
- **Infrastructure Sharing**: Possible shared infrastructure with other ransomware groups

## Attribution and Evidence
Cybersecurity researchers are still investigating Play's origins and attribution. The group's operational focus and steady growth suggest experienced ransomware operators.

## References
1. **CyberProof Mid-Year Threat Landscape Report 2025**: [Link to report](https://www.cyberproof.com/blog/mid-year-threat-landscape-report-top-ransomware-trends-ttps-and-defense-strategies-for-2025/)
2. **SLCyber Blog on Prolific Ransomware Groups**: [Link to analysis](https://slcyber.io/blog/the-most-prolific-ransomware-groups-to-be-aware-of-now/)
3. **DeepStrike.io Ransomware Groups 2025**: [Link to analysis](https://deepstrike.io/blog/ransomware-groups-2025)

## External Links
- [Wikipedia on Play](https://en.wikipedia.org/wiki/Play_ransomware)
