---
layout: threat_actor
title: "APT28"
aliases: ["Fancy Bear", "Sofacy Group"]
description: "APT28 is a threat actor group known for its sophisticated cyber espionage activities."
permalink: /apt28/
country: "Russia"
sector_focus: ["Government", "Military", "Media"]
first_seen: "2007"
last_activity: "2024"
risk_level: "High"
---

## Introduction
APT28, also known as Fancy Bear or Sofacy Group, is a Russian cyber espionage group that has been active since at least 2007. The group is believed to be associated with the Russian military intelligence service (GRU) and is known for conducting sophisticated cyber espionage operations against government, military, and media targets worldwide.

## Activities and Tactics
APT28 employs advanced persistent threat (APT) tactics, including spear-phishing campaigns, exploitation of zero-day vulnerabilities, and use of custom malware. The group is known for its persistence and ability to maintain long-term access to compromised networks.

## Notable Campaigns
1. **Democratic National Committee Hack (2016)**: Infiltration of the DNC and release of stolen emails
2. **German Parliament Attack (2015)**: Cyber attack on the German Bundestag
3. **World Anti-Doping Agency (2016)**: Attack on WADA and release of athlete medical records
4. **Ukrainian Power Grid (2015)**: Cyber attack on Ukrainian power infrastructure
5. **Operation Pawn Storm**: Long-running campaign targeting government and military entities

## Tactics, Techniques, and Procedures (TTPs)
APT28 is known for the following TTPs:
- **Spear Phishing**: Use of targeted email campaigns with malicious attachments
- **Watering Hole Attacks**: Compromising websites frequented by targets
- **Zero-Day Exploits**: Use of previously unknown vulnerabilities
- **Custom Malware**: Development of sophisticated malware families
- **Living off the Land**: Use of legitimate tools and techniques
- **Data Exfiltration**: Systematic theft of sensitive information

## Notable Indicators of Compromise (IOCs)
Based on recent threat intelligence from reliable sources (2025):

### APT28-Specific IOCs
**Note**: APT28 (Fancy Bear) is a Russian state-sponsored threat group known for sophisticated cyber espionage operations.

### IP Addresses
- `45.32.22[.]62`
- `45.17.43[.]250`
- `185.142.98[.]65`

### File Hashes (MD5)
- `0777EA1D01DAD6DC261A6B602205E2C8` (China Chopper Web Shell)
- `feda15d3509b210cb05eacc22485a78c` (Generic PHP Web Shell)
- `C9F4C41C195B25675BFA860EB9B45945` (Linux Exploit CVE-2016-5195)

### File Hashes (SHA-256)
- `e1d8f6d72a43b21a0b0c5f46307d02f2e9a59d3522827b0e7b768135ed3a92c1`

### Domains
- `api-metrics-collector[.]com`

### Malware and Tools
- **NotDoor Backdoor**: Custom backdoor used in recent campaigns
- **Microsoft Outlook Exploitation**: Targeting Outlook vulnerabilities for initial access
- **ClickFix Technique**: Social engineering method using dialogue boxes

### Sources
- [CISA Advisory AA25-141A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-141a) - May 2025
- [CYFIRMA Weekly Intelligence Report](https://www.cyfirma.com/news/weekly-intelligence-report-12-september-2025/) - September 2025
- [Klavan Security Threat Intel Report](https://www.klavansecurity.com/news/security-threat-intel-report-2025-03-28) - March 2025

## Emulating TTPs with Atomic Red Team
To emulate APT28's TTPs, you can use Atomic Red Team's tests:
- **Spear Phishing**: [T1566.001 - Phishing: Spearphishing Attachment](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566/T1566.md)
- **Watering Hole**: [T1189 - Drive-by Compromise](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1189/T1189.md)
- **Command and Control**: [T1071.001 - Application Layer Protocol: Web Protocols](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071/T1071.md)
- **Data Exfiltration**: [T1041 - Exfiltration Over C2 Channel](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md)

## Malware and Tools
APT28 uses a range of custom malware and tools, including:
- **X-Agent**: Custom backdoor used for data exfiltration
- **X-Tunnel**: Custom tunneling tool for C2 communication
- **Sofacy**: Custom malware family
- **Zebrocy**: Custom backdoor used in recent campaigns
- **Cobalt Strike**: Commercial penetration testing tool

## Attribution and Evidence
The U.S. government and cybersecurity researchers have attributed APT28's activities to the Russian military intelligence service (GRU) based on various pieces of evidence, including malware code similarities, operational patterns, and the targeting of specific geopolitical interests.

## References
1. **CrowdStrike APT28 Analysis**: [Link to analysis](https://www.crowdstrike.com/blog/who-is-apt28/)
2. **FireEye APT28 Report**: [Link to report](https://www.fireeye.com/blog/threat-research/2014/10/apt28-a-window-into-russias-cyber-espionage-operations.html)
3. **FBI Alert on APT28**: [Link to alert](https://www.ic3.gov/Media/News/2018/180412.pdf)
4. **CISA Analysis**: [Link to analysis](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-048a)

## External Links
- [Wikipedia on APT28](https://en.wikipedia.org/wiki/APT28)
- [MITRE ATT&CK - APT28](https://attack.mitre.org/groups/G0007/)