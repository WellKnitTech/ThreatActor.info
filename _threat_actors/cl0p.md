---
layout: threat_actor
title: "Cl0p"
aliases: ["Clop", "TA505"]
description: "Cl0p is a highly active ransomware group known for exploiting zero-day vulnerabilities in third-party platforms and conducting large-scale supply chain attacks."
permalink: /cl0p/
country: "Russia"
sector_focus: ["Technology", "Healthcare", "Financial", "Government"]
first_seen: "2019"
last_activity: "2025"
risk_level: "Critical"
---

## Introduction
Cl0p is a ransomware-as-a-service (RaaS) operation that has been extremely active in 2025, with 392 publicly named victims in the first quarter alone. The group is known for its sophisticated exploitation of zero-day vulnerabilities in widely used third-party platforms, particularly file transfer services.

## Activities and Tactics
Cl0p employs advanced tactics including zero-day exploitation, supply chain attacks, and double extortion. The group has been particularly successful in targeting managed file transfer products and service providers to gain access to multiple clients simultaneously.

## Notable Campaigns
1. **MOVEit Transfer Exploitation**: Large-scale attacks exploiting vulnerabilities in Progress Software's MOVEit Transfer platform
2. **Supply Chain Attacks**: Targeting service providers to access multiple client organizations
3. **Healthcare Targeting**: Extensive attacks on healthcare organizations and medical facilities
4. **Financial Sector**: Targeting banks, insurance companies, and financial services

## Tactics, Techniques, and Procedures (TTPs)
Cl0p is known for the following TTPs based on recent threat intelligence (2024-2025):

### Initial Access
- **Zero-Day Exploitation**: Rapid exploitation of vulnerabilities in secure file transfer software like MOVEit and GoAnywhere
- **Supply Chain Attacks**: Compromising service providers to access multiple client organizations simultaneously

### Execution
- **Custom Executables**: Deploying executables masquerading as legitimate processes to evade detection
- **Command and Scripting Interpreters**: Utilizing PowerShell and Bash for payload execution and lateral movement

### Persistence
- **Web Shell Deployment**: Installing web shells for persistent access to compromised systems
- **Registry Manipulation**: Creating or modifying registry keys to maintain access

### Defense Evasion
- **BYOVD Techniques**: Employing Bring Your Own Vulnerable Driver tactics to bypass endpoint detection and antivirus solutions
- **Log Clearing**: Clearing system logs to evade detection
- **Obfuscation**: Using obfuscation techniques to blend into normal operations

### Exfiltration
- **Data Exfiltration Priority**: Prioritizing mass data exfiltration over encryption, demanding payment to prevent data leaks
- **Cloud Services**: Exfiltrating data via cloud services and SFTP protocols

## Notable Indicators of Compromise (IOCs)
Based on recent threat intelligence from reliable sources (2025):

### Cl0p-Specific IOCs
**Note**: Cl0p is known for exploiting zero-day vulnerabilities in file transfer software. Specific IOCs are typically associated with their supply chain attacks.

### Vulnerabilities Exploited
- **MOVEit Transfer**: CVE-2023-34362 (SQL injection vulnerability)
- **GoAnywhere MFT**: CVE-2023-0669 (remote code execution vulnerability)
- **Accellion FTA**: CVE-2021-27101, CVE-2021-27102, CVE-2021-27103, CVE-2021-27104

### Attack Patterns
- **Supply Chain Focus**: Targeting managed file transfer (MFT) software used by service providers
- **Mass Data Exfiltration**: Prioritizing data theft over encryption
- **Web Shell Deployment**: Installing persistent web shells on compromised MFT servers

### Sources
- [CISA StopRansomware Official Alerts](https://www.cisa.gov/stopransomware/official-alerts-statements-cisa) - 2025
- [CISA Advisory on MOVEit Vulnerability](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a) - June 2023
- [CISA Advisory on GoAnywhere Vulnerability](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-040a) - February 2023

## Emulating TTPs with Atomic Red Team
To emulate Cl0p's TTPs, you can use Atomic Red Team's tests:
- **Web Shell Deployment**: [T1505.003 - Web Shell](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1505.003/T1505.003.md)
- **Data Exfiltration**: [T1041 - Exfiltration Over C2 Channel](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md)
- **Ransomware Simulation**: [T1486 - Data Encrypted for Impact](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md)

## Malware and Tools
Based on recent threat intelligence (2024-2025), Cl0p uses the following tools:

### Data Exfiltration Tools
- **Rclone**: Command-line program for transferring data to cloud services
- **WinRAR**: File archiving utility for compressing data before exfiltration

### Credential Access Tools
- **Mimikatz**: Credential dumping tool for extracting passwords and authentication tokens
- **LSASS Memory Scraping**: Techniques for extracting credentials from memory

### Execution Tools
- **PowerShell**: Command-line shell and scripting language for payload execution
- **Bash**: Unix shell for command execution and automation
- **Custom Executables**: Malware masquerading as legitimate processes

### Persistence Tools
- **Web Shells**: Custom web shells for maintaining persistent access
- **Registry Manipulation**: Tools for modifying Windows registry keys

### Defense Evasion Tools
- **BYOVD Tools**: Bring Your Own Vulnerable Driver utilities for disabling security solutions
- **Log Clearing Utilities**: Tools for removing evidence of malicious activity

## Attribution and Evidence
Cybersecurity researchers have attributed Cl0p's activities to Russian cybercriminals based on various pieces of evidence, including malware code similarities, operational patterns, and the targeting of specific geopolitical interests.

## References
1. **CyberProof Mid-Year Threat Landscape Report 2025**: [Link to report](https://www.cyberproof.com/blog/mid-year-threat-landscape-report-top-ransomware-trends-ttps-and-defense-strategies-for-2025/)
2. **DeepStrike.io Ransomware Groups 2025**: [Link to analysis](https://deepstrike.io/blog/ransomware-groups-2025)
3. **CISA Alert on Cl0p**: [Link to alert](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a)
4. **FBI Alert**: [Link to alert](https://www.ic3.gov/Media/News/2023/230601.pdf)
5. **Microsoft Analysis**: [Link to analysis](https://www.microsoft.com/security/blog/2023/06/15/cl0p-ransomware-analysis/)

## External Links
- [Wikipedia on Cl0p](https://en.wikipedia.org/wiki/Cl0p)
- [MITRE ATT&CK - Cl0p](https://attack.mitre.org/groups/G0092/)
