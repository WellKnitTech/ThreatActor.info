---
layout: threat_actor
title: "APT29"
aliases: ["Cozy Bear", "The Dukes"]
description: "APT29 is a Russian cyber espionage group believed to be associated with the Russian intelligence services."
permalink: /apt29/
country: "Russia"
sector_focus: ["Government", "Healthcare", "Energy"]
first_seen: "2008"
last_activity: "2024"
risk_level: "High"
---

## Introduction
APT29, also known as Cozy Bear or The Dukes, is a Russian cyber espionage group that has been active since at least 2008. The group is believed to be associated with the Russian foreign intelligence service (SVR) and is known for conducting sophisticated, long-term cyber espionage operations against government, healthcare, and energy sector targets.

## Activities and Tactics
APT29 employs advanced persistent threat (APT) tactics with a focus on stealth and persistence. The group is known for its patient, methodical approach to cyber espionage, often maintaining access to compromised networks for extended periods.

## Notable Campaigns
1. **SolarWinds Supply Chain Attack (2020)**: Compromise of SolarWinds Orion software affecting thousands of organizations
2. **Democratic National Committee Hack (2016)**: Infiltration of the DNC alongside APT28
3. **COVID-19 Vaccine Research Targeting (2020)**: Attacks on pharmaceutical companies and research institutions
4. **Norwegian Government Attack (2018)**: Cyber attack on Norwegian government networks
5. **Operation Ghost**: Long-running campaign targeting government and diplomatic entities

## Tactics, Techniques, and Procedures (TTPs)
APT29 is known for the following TTPs:
- **Supply Chain Compromise**: Targeting software supply chains and trusted relationships
- **Spear Phishing**: Use of targeted email campaigns with malicious attachments
- **Living off the Land**: Extensive use of legitimate tools and techniques
- **Custom Malware**: Development of sophisticated malware families
- **Persistence**: Long-term access maintenance through multiple techniques
- **Data Exfiltration**: Systematic theft of sensitive information

## Notable Indicators of Compromise (IOCs)
Based on recent threat intelligence from reliable sources (2025):

### APT29-Specific IOCs
**Note**: APT29 (Cozy Bear) is a Russian state-sponsored threat group known for sophisticated cyber espionage operations.

### File Hashes (SHA-256)
- `7a9d7a91c3700d0afe5f05351de4b1b6a7c7316db21adce7da5a0c5733197a1c`

### Domains
- `api-metrics-collector[.]com`

### Attack Patterns
- **Credential Harvesting**: Compromising legitimate websites and using fake verification pages to steal Microsoft 365 credentials
- **Microsoft Device Code Abuse**: Abuse of Microsoft device code authentication mechanisms
- **Cloudflare Verification Pages**: Fake Cloudflare verification pages for credential theft

### TTPs
- **Credential Harvesting**: Through compromised legitimate websites, employing fake Cloudflare verification pages
- **Abuse of Microsoft Device Code**: Authentication mechanisms for unauthorized access

### Sources
- [FireCompass Weekly Report](https://firecompass.com/weekly-report-new-hacking-techniques-and-critical-cves-03-sep-09-sep/) - September 2025
- [Klavan Security Threat Intel Report](https://www.klavansecurity.com/news/security-threat-intel-report-2025-03-28) - March 2025
- [CISA StopRansomware Official Alerts](https://www.cisa.gov/stopransomware/official-alerts-statements-cisa) - 2025

## Emulating TTPs with Atomic Red Team
To emulate APT29's TTPs, you can use Atomic Red Team's tests:
- **Supply Chain Compromise**: [T1195 - Supply Chain Compromise](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1195/T1195.md)
- **Spear Phishing**: [T1566.001 - Phishing: Spearphishing Attachment](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566/T1566.md)
- **Living off the Land**: [T1059.001 - Command and Scripting Interpreter: PowerShell](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059/T1059.md)
- **Persistence**: [T1053.005 - Scheduled Task/Job: Scheduled Task](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053/T1053.md)

## Malware and Tools
APT29 uses a range of custom malware and tools, including:
- **Sunburst**: Custom backdoor used in SolarWinds attack
- **Teardrop**: Custom malware used in recent campaigns
- **WellMess**: Custom backdoor for data exfiltration
- **WellMail**: Custom tool for C2 communication
- **Cobalt Strike**: Commercial penetration testing tool

## Attribution and Evidence
The U.S. government and cybersecurity researchers have attributed APT29's activities to the Russian foreign intelligence service (SVR) based on various pieces of evidence, including malware code similarities, operational patterns, and the targeting of specific geopolitical interests.

## References
1. **CrowdStrike APT29 Analysis**: [Link to analysis](https://www.crowdstrike.com/blog/who-is-apt29/)
2. **FireEye APT29 Report**: [Link to report](https://www.fireeye.com/blog/threat-research/2014/10/apt29-a-window-into-russias-cyber-espionage-operations.html)
3. **FBI Alert on APT29**: [Link to alert](https://www.ic3.gov/Media/News/2018/180412.pdf)
4. **CISA SolarWinds Analysis**: [Link to analysis](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-008a)

## External Links
- [Wikipedia on APT29](https://en.wikipedia.org/wiki/APT29)
- [MITRE ATT&CK - APT29](https://attack.mitre.org/groups/G0016/)