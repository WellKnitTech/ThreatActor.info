---
layout: threat_actor
title: "APT34"
aliases: ["OilRig", "Helix Kitten"]
description: "APT34 is an Iranian cyber espionage group targeting Middle Eastern governments and energy companies."
permalink: /apt34/
country: "Iran"
sector_focus: ["Energy", "Government", "Telecommunications"]
first_seen: "2014"
last_activity: "2024"
risk_level: "High"
---

## Introduction
APT34, also known as OilRig or Helix Kitten, is an Iranian cyber espionage group that has been active since at least 2014. The group is believed to be associated with the Iranian government and is known for targeting Middle Eastern governments, energy companies, and telecommunications organizations.

## Activities and Tactics
APT34 employs advanced persistent threat (APT) tactics with a focus on cyber espionage and information gathering. The group is known for its sophisticated malware and persistent targeting of specific sectors and geographic regions.

## Notable Campaigns
1. **Energy Sector Targeting**: Systematic targeting of energy companies and organizations
2. **Government Entity Espionage**: Attacks on government entities in the Middle East
3. **Telecommunications Targeting**: Cyber espionage against telecommunications companies
4. **Financial Sector Attacks**: Targeting of financial institutions and banks
5. **Technology Sector Espionage**: Attacks on technology companies and research institutions

## Tactics, Techniques, and Procedures (TTPs)
APT34 is known for the following TTPs:
- **Spear Phishing**: Use of targeted email campaigns with malicious attachments
- **Watering Hole Attacks**: Compromising websites frequented by targets
- **Custom Malware**: Development of sophisticated malware families
- **Living off the Land**: Use of legitimate tools and techniques
- **Persistence**: Long-term access maintenance through multiple techniques
- **Data Exfiltration**: Systematic theft of sensitive information

## Notable Indicators of Compromise (IOCs)
Public reporting on APT34 includes changing infrastructure and malware artifacts, but this repository does not yet maintain a vetted IOC set specific to this actor. This section is intentionally conservative until it can be refreshed with actor-specific indicators and provenance.

## Emulating TTPs with Atomic Red Team
To emulate APT34's TTPs, you can use Atomic Red Team's tests:
- **Spear Phishing**: [T1566.001 - Phishing: Spearphishing Attachment](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566/T1566.md)
- **Watering Hole**: [T1189 - Drive-by Compromise](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1189/T1189.md)
- **Custom Malware**: [T1059.001 - Command and Scripting Interpreter: PowerShell](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059/T1059.md)
- **Persistence**: [T1053.005 - Scheduled Task/Job: Scheduled Task](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053/T1053.md)

## Malware and Tools
APT34 uses a range of custom malware and tools, including:
- **OilRig**: Custom backdoor used for data exfiltration
- **Cobalt Strike**: Commercial penetration testing tool
- **Mimikatz**: Credential dumping tool
- **PsExec**: Legitimate tool for remote execution
- **Custom Backdoors**: Various custom-developed backdoors

## Attribution and Evidence
Cybersecurity researchers have attributed APT34's activities to the Iranian government based on various pieces of evidence, including malware code similarities, operational patterns, and the targeting of specific geopolitical interests.

## References
1. **CrowdStrike APT34 Report**: [Link to report](https://www.crowdstrike.com/blog/who-is-apt34/)
2. **CISA Alert on APT34**: [Link to alert](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-048a)

## External Links
- [Wikipedia on APT34](https://en.wikipedia.org/wiki/APT34)
- [MITRE ATT&CK - APT34](https://attack.mitre.org/groups/G0049/)
