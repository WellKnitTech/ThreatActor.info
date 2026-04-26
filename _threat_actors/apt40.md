---
layout: threat_actor
title: "APT40"
aliases: ["Kryptonite Panda", "Leviathan"]
description: "APT40 is a Chinese cyber espionage group targeting maritime industries and government entities."
permalink: /apt40/
country: "China"
sector_focus: ["Maritime", "Government", "Defense"]
first_seen: "2013"
last_activity: "2024"
risk_level: "High"
---

## Introduction
APT40, also known as Kryptonite Panda or Leviathan, is a Chinese cyber espionage group that has been active since at least 2013. The group is believed to be associated with the Chinese government and is known for targeting maritime industries, government entities, and defense contractors, particularly those with interests in the South China Sea region.

## Activities and Tactics
APT40 employs advanced persistent threat (APT) tactics with a focus on cyber espionage and information gathering. The group is known for its sophisticated malware and persistent targeting of specific sectors and geographic regions.

## Notable Campaigns
1. **Maritime Industry Targeting**: Systematic targeting of maritime companies and organizations
2. **Government Entity Espionage**: Attacks on government entities in the Asia-Pacific region
3. **Defense Contractor Targeting**: Cyber espionage against defense contractors
4. **South China Sea Focus**: Targeting of organizations with interests in the South China Sea
5. **Technology Sector Espionage**: Attacks on technology companies and research institutions

## Tactics, Techniques, and Procedures (TTPs)
APT40 is known for the following TTPs:
- **Spear Phishing**: Use of targeted email campaigns with malicious attachments
- **Watering Hole Attacks**: Compromising websites frequented by targets
- **Custom Malware**: Development of sophisticated malware families
- **Living off the Land**: Use of legitimate tools and techniques
- **Persistence**: Long-term access maintenance through multiple techniques
- **Data Exfiltration**: Systematic theft of sensitive information

## Notable Indicators of Compromise (IOCs)
Public reporting on APT40 includes changing infrastructure and malware artifacts, but this repository does not yet maintain a vetted IOC set specific to this actor. This section is intentionally conservative until it can be refreshed with actor-specific indicators and provenance.

## Emulating TTPs with Atomic Red Team
To emulate APT40's TTPs, you can use Atomic Red Team's tests:
- **Spear Phishing**: [T1566.001 - Phishing: Spearphishing Attachment](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566/T1566.md)
- **Watering Hole**: [T1189 - Drive-by Compromise](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1189/T1189.md)
- **Custom Malware**: [T1059.001 - Command and Scripting Interpreter: PowerShell](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059/T1059.md)
- **Persistence**: [T1053.005 - Scheduled Task/Job: Scheduled Task](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053/T1053.md)

## Malware and Tools
APT40 uses a range of custom malware and tools, including:
- **Kryptonite**: Custom backdoor used for data exfiltration
- **Cobalt Strike**: Commercial penetration testing tool
- **Mimikatz**: Credential dumping tool
- **PsExec**: Legitimate tool for remote execution
- **Custom Backdoors**: Various custom-developed backdoors

## Attribution and Evidence
Cybersecurity researchers have attributed APT40's activities to the Chinese government based on various pieces of evidence, including malware code similarities, operational patterns, and the targeting of specific geopolitical interests.

## References
1. **FireEye APT40 Analysis**: [Link to analysis](https://www.fireeye.com/blog/threat-research/2017/05/apt40_osx_document_macmalware.html)
2. **CrowdStrike APT40 Report**: [Link to report](https://www.crowdstrike.com/blog/who-is-apt40/)
3. **CISA Alert on APT40**: [Link to alert](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-048a)

## External Links
- [Wikipedia on APT40](https://en.wikipedia.org/wiki/APT40)
- [MITRE ATT&CK - APT40](https://attack.mitre.org/groups/G0065/)
