---
layout: threat_actor
title: "Ryuk"
aliases: ["Wizard Spider"]
description: "Ryuk is a ransomware operation known for targeting large organizations and demanding high ransom payments."
permalink: /ryuk/
country: "Russia"
sector_focus: ["Healthcare", "Government", "Education"]
first_seen: "2018"
last_activity: "2021"
risk_level: "Critical"
---

## Introduction
Ryuk, also known as Wizard Spider, is a ransomware operation that emerged in 2018 and quickly became known for targeting large organizations and demanding high ransom payments. The group is believed to be associated with Russian cybercriminals and has been responsible for some of the most high-profile ransomware attacks.

## Activities and Tactics
Ryuk employs aggressive ransomware tactics, including double extortion (encrypting files and threatening to leak data), and is known for targeting high-value organizations with significant financial resources.

## Notable Campaigns
1. **Healthcare Targeting**: Extensive targeting of healthcare organizations during the COVID-19 pandemic
2. **Government Entity Attacks**: Targeting of government organizations and agencies
3. **Education Sector Attacks**: Attacks on universities and school districts
4. **Critical Infrastructure Attacks**: Targeting of critical infrastructure organizations
5. **Financial Sector Attacks**: Targeting of financial institutions and banks

## Tactics, Techniques, and Procedures (TTPs)
Ryuk is known for the following TTPs:
- **Double Extortion**: Encrypting files and threatening to leak data
- **Ransomware-as-a-Service**: Providing ransomware to affiliates
- **Initial Access Brokers**: Using third-party access to compromised networks
- **Living off the Land**: Use of legitimate tools and techniques
- **Fast Encryption**: Rapid encryption of files to minimize detection
- **Data Exfiltration**: Systematic theft of sensitive information

## Notable Indicators of Compromise (IOCs)
Public reporting on Ryuk includes changing infrastructure and victim-specific tooling, but this repository does not yet maintain a vetted IOC set specific to this actor. This section is intentionally conservative until it can be refreshed with actor-specific indicators and provenance.

## Emulating TTPs with Atomic Red Team
To emulate Ryuk's TTPs, you can use Atomic Red Team's tests:
- **Ransomware Simulation**: [T1486 - Data Encrypted for Impact](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md)
- **Data Exfiltration**: [T1041 - Exfiltration Over C2 Channel](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md)
- **Network Discovery**: [T1018 - Remote System Discovery](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md)
- **Persistence**: [T1053.005 - Scheduled Task/Job: Scheduled Task](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053/T1053.md)

## Malware and Tools
Ryuk uses a range of custom malware and tools, including:
- **Ryuk Ransomware**: Custom ransomware variant
- **Cobalt Strike**: Commercial penetration testing tool
- **Mimikatz**: Credential dumping tool
- **PsExec**: Legitimate tool for remote execution
- **Custom Backdoors**: Various custom-developed backdoors

## Attribution and Evidence
Cybersecurity researchers have attributed Ryuk's activities to Russian cybercriminals based on various pieces of evidence, including malware code similarities, operational patterns, and the targeting of specific financial interests.

## References
1. **CISA Alert on Ryuk**: [Link to alert](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-131a)
2. **FBI Alert on Ryuk**: [Link to alert](https://www.ic3.gov/Media/News/2021/210601.pdf)
3. **Microsoft Analysis**: [Link to analysis](https://www.microsoft.com/security/blog/2021/05/27/ransomware-as-a-service-understanding-the-cybercrime-gig-economy-and-how-to-protect-yourself/)
4. **CrowdStrike Ryuk Analysis**: [Link to analysis](https://www.crowdstrike.com/blog/who-is-ryuk/)

## External Links
- [Wikipedia on Ryuk](https://en.wikipedia.org/wiki/Ryuk_ransomware)
- [MITRE ATT&CK - Ryuk](https://attack.mitre.org/groups/G0052/)
