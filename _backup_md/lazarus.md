---
layout: threat_actor
title: "Lazarus Group"
aliases: ["Hidden Cobra", "Guardians of Peace"]
description: "Lazarus Group is a North Korean state-sponsored cybercrime group known for destructive attacks and financial theft."
permalink: /lazarus/
country: "North Korea"
sector_focus: ["Financial", "Cryptocurrency", "Entertainment"]
first_seen: "2009"
last_activity: "2024"
risk_level: "Critical"
---

## Introduction
Lazarus Group, also known as Hidden Cobra or Guardians of Peace, is a North Korean state-sponsored cybercrime group that has been active since at least 2009. The group is known for conducting both destructive attacks and financially motivated operations, including cryptocurrency theft and ransomware attacks.

## Activities and Tactics
Lazarus Group employs a wide range of tactics, from sophisticated cyber espionage to destructive attacks and financial theft. The group has been responsible for some of the most high-profile cyber attacks in recent years.

## Notable Campaigns
1. **Sony Pictures Hack (2014)**: Destructive attack on Sony Pictures Entertainment
2. **WannaCry Ransomware (2017)**: Global ransomware attack affecting hundreds of thousands of systems
3. **Cryptocurrency Exchange Attacks**: Multiple attacks on cryptocurrency exchanges, including the 2018 Coincheck hack
4. **Bangladesh Bank Heist (2016)**: Attempted theft of $1 billion from Bangladesh Bank

## Tactics, Techniques, and Procedures (TTPs)
Lazarus Group is known for the following TTPs:
- **Destructive Malware**: Use of wiper malware to destroy data
- **Cryptocurrency Theft**: Targeting cryptocurrency exchanges and wallets
- **Supply Chain Attacks**: Compromising software supply chains
- **Social Engineering**: Sophisticated social engineering campaigns
- **Living off the Land**: Use of legitimate tools and techniques

## Notable Indicators of Compromise (IOCs)
Based on recent threat intelligence from reliable sources (2025):

### Lazarus Group-Specific IOCs
**Note**: Lazarus Group is a North Korean state-sponsored threat group known for cryptocurrency theft and cyber espionage.

### IP Addresses
- `185.142.98[.]65`

### File Hashes (SHA-256)
- `e1d8f6d72a43b21a0b0c5f46307d02f2e9a59d3522827b0e7b768135ed3a92c1`

### Malware and Tools
- **VMware Exploitation**: Targeting VMware vulnerabilities for initial access
- **Custom Malware**: Development of sophisticated malware for data exfiltration
- **Cryptocurrency Theft**: Specialized tools for stealing cryptocurrency

### Attack Patterns
- **Supply Chain Attacks**: Compromising software supply chains
- **Social Engineering**: Sophisticated social engineering campaigns
- **Living off the Land**: Extensive use of legitimate tools and techniques

### Sources
- [Klavan Security Threat Intel Report](https://www.klavansecurity.com/news/security-threat-intel-report-2025-03-28) - March 2025
- [CISA StopRansomware Official Alerts](https://www.cisa.gov/stopransomware/official-alerts-statements-cisa) - 2025
- [FBI Flash Alert on Lazarus Group](https://www.ic3.gov/Media/News/2023/230601.pdf) - June 2023

## Emulating TTPs with Atomic Red Team
To emulate Lazarus Group's TTPs, you can use Atomic Red Team's tests:
- **Destructive Malware**: [T1485 - Data Destruction](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.md)
- **Cryptocurrency Mining**: [T1496 - Resource Hijacking](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1496/T1496.md)
- **Supply Chain Compromise**: [T1195 - Supply Chain Compromise](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1195/T1195.md)

## Malware and Tools
Lazarus Group uses a range of custom malware and tools, including:
- **WannaCry**: Ransomware used in the 2017 global attack
- **Bankshot**: Backdoor used in financial attacks
- **Fallchill**: Remote access trojan
- **Hoplight**: Backdoor used for persistence

## Attribution and Evidence
The U.S. government and cybersecurity researchers have attributed Lazarus Group's activities to North Korea based on various pieces of evidence, including malware code similarities, operational patterns, and the targeting of specific geopolitical interests.

## References
1. **FBI Alert on Hidden Cobra**: [Link to alert](https://www.ic3.gov/Media/News/2017/170609.pdf)
2. **CISA Analysis**: [Link to analysis](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-048a)
3. **Microsoft Analysis**: [Link to analysis](https://www.microsoft.com/security/blog/2021/04/16/north-korean-threat-actor-group-targets-security-researchers/)

## External Links
- [Wikipedia on Lazarus Group](https://en.wikipedia.org/wiki/Lazarus_Group)
- [MITRE ATT&CK - Lazarus Group](https://attack.mitre.org/groups/G0032/)
