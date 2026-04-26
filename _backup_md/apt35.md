---
layout: threat_actor
title: "APT35"
aliases: ["Charming Kitten", "Phosphorus"]
description: "APT35 is an Iranian cyber espionage group targeting journalists, academics, and government officials."
permalink: /apt35/
country: "Iran"
sector_focus: ["Media", "Academia", "Government"]
first_seen: "2014"
last_activity: "2024"
risk_level: "High"
---

## Introduction
APT35, also known as Charming Kitten or Phosphorus, is an Iranian cyber espionage group that has been active since at least 2014. The group is believed to be associated with the Iranian government and is known for targeting journalists, academics, and government officials, particularly those with interests in Iran and the Middle East.

## Activities and Tactics
APT35 employs advanced persistent threat (APT) tactics with a focus on cyber espionage and information gathering. The group is known for its sophisticated social engineering techniques and persistent targeting of specific individuals and organizations.

## Notable Campaigns
1. **Journalist Targeting**: Systematic targeting of journalists and media organizations
2. **Academic Espionage**: Attacks on universities and research institutions
3. **Government Official Targeting**: Cyber espionage against government officials
4. **Human Rights Organization Attacks**: Targeting of human rights and advocacy groups
5. **Technology Sector Espionage**: Attacks on technology companies and research institutions

## Tactics, Techniques, and Procedures (TTPs)
APT35 is known for the following TTPs:
- **Spear Phishing**: Use of targeted email campaigns with malicious attachments
- **Social Engineering**: Sophisticated social engineering techniques
- **Custom Malware**: Development of sophisticated malware families
- **Living off the Land**: Use of legitimate tools and techniques
- **Persistence**: Long-term access maintenance through multiple techniques
- **Data Exfiltration**: Systematic theft of sensitive information

## Notable Indicators of Compromise (IOCs)
Public reporting on APT35 includes changing infrastructure and malware artifacts, but this repository does not yet maintain a vetted IOC set specific to this actor. This section is intentionally conservative until it can be refreshed with actor-specific indicators and provenance.

## Emulating TTPs with Atomic Red Team
To emulate APT35's TTPs, you can use Atomic Red Team's tests:
- **Spear Phishing**: [T1566.001 - Phishing: Spearphishing Attachment](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566/T1566.md)
- **Social Engineering**: [T1566.002 - Phishing: Spearphishing Link](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566/T1566.md)
- **Custom Malware**: [T1059.001 - Command and Scripting Interpreter: PowerShell](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059/T1059.md)
- **Persistence**: [T1053.005 - Scheduled Task/Job: Scheduled Task](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053/T1053.md)

## Malware and Tools
APT35 uses a range of custom malware and tools, including:
- **Charming Kitten**: Custom backdoor used for data exfiltration
- **Cobalt Strike**: Commercial penetration testing tool
- **Mimikatz**: Credential dumping tool
- **PsExec**: Legitimate tool for remote execution
- **Custom Backdoors**: Various custom-developed backdoors

## Attribution and Evidence
Cybersecurity researchers have attributed APT35's activities to the Iranian government based on various pieces of evidence, including malware code similarities, operational patterns, and the targeting of specific geopolitical interests.

## References
1. **CrowdStrike APT35 Report**: [Link to report](https://www.crowdstrike.com/blog/who-is-apt35/)
2. **CISA Alert on APT35**: [Link to alert](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-048a)

## External Links
- [Wikipedia on APT35](https://en.wikipedia.org/wiki/APT35)
- [MITRE ATT&CK - APT35](https://attack.mitre.org/groups/G0047/)
