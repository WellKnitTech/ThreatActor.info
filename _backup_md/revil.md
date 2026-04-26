---
layout: threat_actor
title: "REvil"
aliases: ["Sodinokibi", "Sodin"]
description: "REvil is a Russian ransomware-as-a-service operation that has targeted major corporations worldwide."
permalink: /revil/
country: "Russia"
sector_focus: ["Technology", "Healthcare", "Legal"]
first_seen: "2019"
last_activity: "2021"
risk_level: "Critical"
---

## Introduction
REvil, also known as Sodinokibi or Sodin, is a Russian ransomware-as-a-service (RaaS) operation that emerged in 2019 and quickly became one of the most prolific ransomware groups. The group is known for targeting major corporations worldwide and demanding high ransom payments, often in the millions of dollars.

## Activities and Tactics
REvil employs aggressive ransomware tactics, including double extortion (encrypting files and threatening to leak data), and has been known to target high-value organizations with significant financial resources.

## Notable Campaigns
1. **Kaseya Supply Chain Attack (2021)**: Attack on Kaseya VSA software affecting thousands of organizations
2. **JBS Foods Attack (2021)**: Attack on the world's largest meat processor
3. **Acer Attack (2021)**: Attack on Taiwanese computer manufacturer
4. **Travelex Attack (2020)**: Attack on British foreign exchange company
5. **Garmin Attack (2020)**: Attack on GPS device manufacturer

## Tactics, Techniques, and Procedures (TTPs)
REvil is known for the following TTPs:
- **Double Extortion**: Encrypting files and threatening to leak data
- **Ransomware-as-a-Service**: Providing ransomware to affiliates
- **Supply Chain Attacks**: Targeting software supply chains
- **Initial Access Brokers**: Using third-party access to compromised networks
- **Living off the Land**: Use of legitimate tools and techniques
- **Fast Encryption**: Rapid encryption of files to minimize detection

## Notable Indicators of Compromise (IOCs)
Public reporting on REvil includes changing infrastructure and victim-specific tooling, but this repository does not yet maintain a vetted IOC set specific to this actor. This section is intentionally conservative until it can be refreshed with actor-specific indicators and provenance.

## Emulating TTPs with Atomic Red Team
To emulate REvil's TTPs, you can use Atomic Red Team's tests:
- **Ransomware Simulation**: [T1486 - Data Encrypted for Impact](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md)
- **Data Exfiltration**: [T1041 - Exfiltration Over C2 Channel](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md)
- **Supply Chain Compromise**: [T1195 - Supply Chain Compromise](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1195/T1195.md)
- **Network Discovery**: [T1018 - Remote System Discovery](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md)

## Malware and Tools
REvil uses a range of custom malware and tools, including:
- **Sodinokibi**: Custom ransomware variant
- **Cobalt Strike**: Commercial penetration testing tool
- **Mimikatz**: Credential dumping tool
- **PsExec**: Legitimate tool for remote execution
- **Custom Backdoors**: Various custom-developed backdoors

## Attribution and Evidence
Cybersecurity researchers have attributed REvil's activities to Russian cybercriminals based on various pieces of evidence, including malware code similarities, operational patterns, and the targeting of specific geopolitical interests.

## References
1. **CISA Alert on REvil**: [Link to alert](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-131a)
2. **FBI Alert on REvil**: [Link to alert](https://www.ic3.gov/Media/News/2021/210601.pdf)
3. **Microsoft Analysis**: [Link to analysis](https://www.microsoft.com/security/blog/2021/05/27/ransomware-as-a-service-understanding-the-cybercrime-gig-economy-and-how-to-protect-yourself/)
4. **Kaseya Attack Analysis**: [Link to analysis](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-190a)

## External Links
- [Wikipedia on REvil](https://en.wikipedia.org/wiki/REvil)
- [MITRE ATT&CK - REvil](https://attack.mitre.org/groups/G0113/)
