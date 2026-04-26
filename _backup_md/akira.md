---
layout: threat_actor
title: "Akira"
aliases: ["Akira Ransomware"]
description: "Akira is a ransomware group launched in 2023 that experienced a sharp rise in 2024, disclosing 349 victims and targeting various industries."
permalink: /akira/
country: "Unknown"
sector_focus: ["Healthcare", "Education", "Government", "Technology"]
first_seen: "2023"
last_activity: "2025"
risk_level: "High"
---

## Introduction
Akira is a ransomware operation that was launched in 2023 and experienced a sharp rise in activity during 2024, disclosing 349 victims. The group has ramped up its operations and maintained a steady pace, targeting various industries with its ransomware attacks.

## Activities and Tactics
Akira employs standard ransomware tactics with a focus on operational execution. The group has been particularly active in targeting healthcare, education, and government sectors, causing significant disruptions to critical services.

## Notable Campaigns
1. **2024 Victim Growth**: Public victim disclosures accelerated during 2024 as Akira expanded its operational tempo across multiple sectors
2. **Cross-Platform Intrusions**: Operations targeted Windows, Linux, and ESXi environments rather than staying limited to a single platform
3. **Critical-Service Disruption**: The group repeatedly targeted healthcare, education, and government organizations where outages create immediate pressure
4. **VPN and Credential Access Operations**: Intrusions frequently aligned with exposed remote access services and credential-driven entry paths

## Tactics, Techniques, and Procedures (TTPs)
Akira is known for the following TTPs based on recent threat intelligence (2024-2025):

### Initial Access
- **VPN Exploitation**: Targeting single-factor VPNs and external remote services using stolen or purchased credentials
- **Credential Theft**: Utilizing access brokers to obtain credentials from third parties for faster intrusions
- **External Remote Services**: Exploiting compromised VPN appliances and remote access systems

### Execution
- **Custom Executables**: Deploying executables masquerading as legitimate processes to evade detection
- **Command and Scripting Interpreters**: Utilizing PowerShell and Bash for payload execution and automation
- **Multi-Platform Targeting**: Targeting Windows, Linux, and ESXi systems

### Persistence
- **System Service Modification**: Installing or modifying system services for persistent access
- **Scheduled Task Configuration**: Configuring scheduled tasks for persistence
- **Remote Access Tools**: Deploying legitimate remote access tools like AnyDesk and Radmin

### Privilege Escalation
- **Credential Dumping**: Leveraging Active Directory manipulation and Kerberos ticket abuse
- **Service Impersonation**: Using service impersonation techniques for privilege escalation

### Defense Evasion
- **Log Clearing**: Clearing system logs to evade detection
- **Obfuscation**: Using obfuscation techniques to blend into normal operations
- **Service Impersonation**: Employing service impersonation to evade detection

### Exfiltration
- **Data Archiving**: Using tools like WinRAR to compress sensitive data
- **Cloud Services**: Exfiltrating data via cloud services and SFTP protocols
- **Double Extortion**: Threatening to leak exfiltrated data to pressure victims

## Notable Indicators of Compromise (IOCs)
Based on recent threat intelligence from reliable sources (2025):

### Akira-Specific IOCs
**Note**: Akira is known for targeting VPNs and using access broker networks for faster intrusions.

### Ransomware Variants
- **Akira Ransomware**: Original C++-based ransomware strain targeting Windows and Linux systems
- **Megazord**: Rust-based ransomware variant that encrypts files with a `.powerranges` extension

### File Extensions
- **Akira**: `.akira`
- **Megazord**: `.powerranges`

### Attack Patterns
- **VPN Exploitation**: Targeting single-factor VPNs and external remote services
- **Access Broker Networks**: Utilizing third-party credential providers for faster intrusions
- **Multi-Platform Targeting**: Targeting Windows, Linux, and ESXi systems

### Remote Access Tools
- **AnyDesk**: Legitimate remote desktop software used for persistent access
- **Radmin**: Remote administration tool for maintaining access to compromised systems

### Sources
- [CISA StopRansomware Official Alerts](https://www.cisa.gov/stopransomware/official-alerts-statements-cisa) - 2025
- [FBI Flash Alert on Akira Ransomware](https://www.ic3.gov/Media/News/2023/230601.pdf) - June 2023

## Emulating TTPs with Atomic Red Team
To emulate Akira's TTPs, you can use Atomic Red Team's tests:
- **Ransomware Simulation**: [T1486 - Data Encrypted for Impact](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md)
- **Data Exfiltration**: [T1041 - Exfiltration Over C2 Channel](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md)
- **Network Discovery**: [T1018 - Remote System Discovery](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md)

## Malware and Tools
Based on recent threat intelligence (2024-2025), Akira uses the following tools:

### Ransomware Variants
- **Akira Ransomware**: Original C++-based ransomware strain targeting Windows and Linux systems
- **Megazord**: Rust-based ransomware variant that encrypts files with a `.powerranges` extension

### Remote Access Tools
- **AnyDesk**: Legitimate remote desktop software used for persistent access
- **Radmin**: Remote administration tool for maintaining access to compromised systems

### Credential Access Tools
- **Mimikatz**: Credential dumping tool for extracting passwords and authentication tokens
- **Access Broker Networks**: Utilizing third-party credential providers for faster intrusions

### Data Exfiltration Tools
- **WinRAR**: File archiving utility for compressing data before exfiltration
- **Rclone**: Command-line program for transferring data to cloud services

### Execution Tools
- **PowerShell**: Command-line shell and scripting language for payload execution
- **Bash**: Unix shell for command execution and automation
- **Custom Executables**: Malware masquerading as legitimate processes

## Attribution and Evidence
Cybersecurity researchers are still investigating Akira's origins and attribution. The group's operational patterns and targeting suggest experienced ransomware operators.

## References
1. **CyberProof Mid-Year Threat Landscape Report 2025**: [Link to report](https://www.cyberproof.com/blog/mid-year-threat-landscape-report-top-ransomware-trends-ttps-and-defense-strategies-for-2025/)
2. **SLCyber Blog on Prolific Ransomware Groups**: [Link to analysis](https://slcyber.io/blog/the-most-prolific-ransomware-groups-to-be-aware-of-now/)
3. **DeepStrike.io Ransomware Groups 2025**: [Link to analysis](https://deepstrike.io/blog/ransomware-groups-2025)
4. **Cyber Insurance Academy Guide**: [Link to guide](https://www.cyberinsuranceacademy.com/blog/guides/4-ransomware-gangs-you-need-to-know/)

## External Links
- [Wikipedia on Akira](https://en.wikipedia.org/wiki/Akira_ransomware)
