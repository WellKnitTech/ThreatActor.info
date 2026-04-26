---
layout: threat_actor
title: "Conti"
aliases: ["Ryuk", "Wizard Spider"]
description: "Conti is a Russian ransomware-as-a-service operation known for targeting healthcare and critical infrastructure."
permalink: /conti/
country: "Russia"
sector_focus: ["Healthcare", "Critical Infrastructure", "Government"]
first_seen: "2020"
last_activity: "2022"
risk_level: "Critical"
---

## Introduction
Conti is a Russian ransomware-as-a-service (RaaS) operation that emerged in 2020 and quickly became one of the most prolific ransomware groups. The group is known for targeting healthcare organizations, critical infrastructure, and government entities, often during critical times such as the COVID-19 pandemic.

## Activities and Tactics
Conti employs aggressive ransomware tactics, including double extortion (encrypting files and threatening to leak data), and has been known to target organizations during vulnerable periods.

## Notable Campaigns
1. **Healthcare Targeting**: Extensive targeting of healthcare organizations during the COVID-19 pandemic
2. **Critical Infrastructure**: Attacks on water treatment facilities and power companies
3. **Government Entities**: Targeting of local and state government organizations
4. **Education Sector**: Attacks on universities and school districts

## Tactics, Techniques, and Procedures (TTPs)
Conti is known for the following TTPs:
- **Double Extortion**: Encrypting files and threatening to leak data
- **Ransomware-as-a-Service**: Providing ransomware to affiliates
- **Initial Access Brokers**: Using third-party access to compromised networks
- **Living off the Land**: Use of legitimate tools and techniques
- **Fast Encryption**: Rapid encryption of files to minimize detection

## Notable Indicators of Compromise (IOCs)
Public reporting on Conti includes changing infrastructure and victim-specific tooling, but this repository does not yet maintain a vetted IOC set specific to this actor. This section is intentionally conservative until it can be refreshed with actor-specific indicators and provenance.

## Emulating TTPs with Atomic Red Team
To emulate Conti's TTPs, you can use Atomic Red Team's tests:
- **Ransomware Simulation**: [T1486 - Data Encrypted for Impact](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md)
- **Data Exfiltration**: [T1041 - Exfiltration Over C2 Channel](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md)
- **Network Discovery**: [T1018 - Remote System Discovery](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md)

## Malware and Tools
Conti uses a range of custom malware and tools, including:
- **Conti Ransomware**: Custom ransomware variant
- **Cobalt Strike**: Commercial penetration testing tool
- **Mimikatz**: Credential dumping tool
- **PsExec**: Legitimate tool for remote execution

## Attribution and Evidence
Cybersecurity researchers have attributed Conti's activities to Russian cybercriminals based on various pieces of evidence, including malware code similarities, operational patterns, and the targeting of specific geopolitical interests.

## References
1. **CISA Alert on Conti**: [Link to alert](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-131a)
2. **FBI Alert**: [Link to alert](https://www.ic3.gov/Media/News/2021/210601.pdf)
3. **Microsoft Analysis**: [Link to analysis](https://www.microsoft.com/security/blog/2021/05/27/ransomware-as-a-service-understanding-the-cybercrime-gig-economy-and-how-to-protect-yourself/)

## External Links
- [Wikipedia on Conti](https://en.wikipedia.org/wiki/Conti_ransomware)
- [MITRE ATT&CK - Conti](https://attack.mitre.org/groups/G0082/)


