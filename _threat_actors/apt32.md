---
layout: threat_actor
title: "APT32"
aliases: ["OceanLotus", "APT-C-00"]
description: "APT32 is a Vietnamese cyber espionage group targeting foreign corporations, journalists, and government entities."
permalink: /apt32/
country: "Vietnam"
sector_focus: ["Government", "Media", "Technology"]
first_seen: "2012"
last_activity: "2024"
risk_level: "High"
---

## Introduction
APT32, also known as OceanLotus or APT-C-00, is a Vietnamese cyber espionage group that has been active since at least 2012. The group is believed to be associated with the Vietnamese government and is known for targeting foreign corporations, journalists, and government entities, particularly those with interests in Vietnam.

## Activities and Tactics
APT32 employs advanced persistent threat (APT) tactics with a focus on cyber espionage and information gathering. The group is known for its sophisticated malware and persistent targeting of specific sectors and individuals.

## Notable Campaigns
1. **Journalist Targeting**: Systematic targeting of journalists and media organizations
2. **Foreign Corporation Espionage**: Attacks on multinational corporations with Vietnamese interests
3. **Government Entity Targeting**: Cyber espionage against foreign government entities
4. **Human Rights Organization Attacks**: Targeting of human rights and advocacy groups
5. **Technology Sector Espionage**: Attacks on technology companies and research institutions

## Tactics, Techniques, and Procedures (TTPs)
APT32 is known for the following TTPs:
- **Spear Phishing**: Use of targeted email campaigns with malicious attachments
- **Watering Hole Attacks**: Compromising websites frequented by targets
- **Custom Malware**: Development of sophisticated malware families
- **Living off the Land**: Use of legitimate tools and techniques
- **Persistence**: Long-term access maintenance through multiple techniques
- **Data Exfiltration**: Systematic theft of sensitive information

## Notable Indicators of Compromise (IOCs)
Public reporting on APT32 includes changing infrastructure and malware artifacts, but this repository does not yet maintain a vetted IOC set specific to this actor. This section is intentionally conservative until it can be refreshed with actor-specific indicators and provenance.

## Emulating TTPs with Atomic Red Team
To emulate APT32's TTPs, you can use Atomic Red Team's tests:
- **Spear Phishing**: [T1566.001 - Phishing: Spearphishing Attachment](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566/T1566.md)
- **Watering Hole**: [T1189 - Drive-by Compromise](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1189/T1189.md)
- **Custom Malware**: [T1059.001 - Command and Scripting Interpreter: PowerShell](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059/T1059.md)
- **Persistence**: [T1053.005 - Scheduled Task/Job: Scheduled Task](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053/T1053.md)

## Malware and Tools
APT32 uses a range of custom malware and tools, including:
- **OceanLotus**: Custom backdoor used for data exfiltration
- **Cobalt Strike**: Commercial penetration testing tool
- **Mimikatz**: Credential dumping tool
- **PsExec**: Legitimate tool for remote execution
- **Custom Backdoors**: Various custom-developed backdoors

## Attribution and Evidence
Cybersecurity researchers have attributed APT32's activities to the Vietnamese government based on various pieces of evidence, including malware code similarities, operational patterns, and the targeting of specific geopolitical interests.

## References
1. **FireEye APT32 Analysis**: [Link to analysis](https://www.fireeye.com/blog/threat-research/2017/05/apt32_osx_document_macmalware.html)
2. **CrowdStrike APT32 Report**: [Link to report](https://www.crowdstrike.com/blog/who-is-apt32/)
3. **Volexity APT32 Analysis**: [Link to analysis](https://www.volexity.com/blog/2020/07/08/oceanlotus-apt32-targets-vietnamese-dissidents-and-foreign-corporations/)
4. **CISA Alert on APT32**: [Link to alert](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-048a)

## External Links
- [Wikipedia on APT32](https://en.wikipedia.org/wiki/APT32)
- [MITRE ATT&CK - APT32](https://attack.mitre.org/groups/G0050/)
