---
layout: threat_actor
title: "APT1"
aliases: ["Comment Crew", "Comment Panda"]
description: "APT1 is a Chinese cyber espionage group that has been conducting cyber espionage against a broad range of victims."
permalink: /apt1/
country: "China"
sector_focus: ["Government", "Defense", "Technology"]
first_seen: "2006"
last_activity: "2023"
risk_level: "High"
---

## Introduction
APT1, also known as Comment Crew or Comment Panda, is a Chinese cyber espionage group that has been conducting cyber espionage against a broad range of victims since at least 2006. The group is believed to be associated with the Chinese military and has been one of the most prolific cyber espionage groups in the world.

## Activities and Tactics
APT1 employs a variety of tactics, techniques, and procedures (TTPs) in its cyber operations, including spear-phishing campaigns, exploitation of zero-day vulnerabilities, and use of custom malware.

## Notable Campaigns
1. **Operation Aurora (2009-2010)**: APT1 was implicated in the Operation Aurora attacks against Google and other major technology companies.
2. **Defense Contractor Targeting**: The group has consistently targeted defense contractors and government entities worldwide.

## Tactics, Techniques, and Procedures (TTPs)
APT1 is known for the following TTPs:
- **Spear Phishing**: Use of targeted email campaigns to deliver malware
- **Watering Hole Attacks**: Compromising websites frequented by targets
- **Custom Malware**: Development and use of sophisticated custom malware families
- **Command and Control**: Use of various C2 techniques to maintain persistence

## Notable Indicators of Compromise (IOCs)
Public reporting on APT1 is historically rich, but this repository does not yet maintain a vetted IOC set specific to this actor. This section is intentionally conservative until it can be refreshed with actor-specific indicators and provenance.

## Emulating TTPs with Atomic Red Team
To emulate APT1's TTPs, you can use Atomic Red Team's tests:
- **Spear Phishing**: [T1566 - Phishing](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566/T1566.md)
- **Watering Hole**: [T1189 - Drive-by Compromise](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1189/T1189.md)
- **Command and Control**: [T1071 - Application Layer Protocol](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071/T1071.md)

## Malware and Tools
APT1 uses a range of custom malware and tools, including:
- **Gh0st RAT**: A remote access trojan used for data exfiltration
- **Poison Ivy**: A backdoor used for remote access
- **Custom Backdoors**: Various custom-developed backdoors

## Attribution and Evidence
Researchers and government agencies have attributed APT1's activities to the Chinese military based on various pieces of evidence, including malware code similarities, operational patterns, and the targeting of specific geopolitical interests.

## References
1. **Mandiant APT1 Report**: [Link to report](https://www.mandiant.com/resources/blog/apt1-exposing-one-of-chinas-cyber-espionage-units)
2. **FireEye Analysis**: [Link to analysis](https://www.fireeye.com/blog/threat-research/2013/02/operation-aurora-apt1.html)
3. **CrowdStrike Analysis**: [Link to analysis](https://www.crowdstrike.com/blog/who-is-apt1/)

## External Links
- [Wikipedia on APT1](https://en.wikipedia.org/wiki/APT1)
- [MITRE ATT&CK - APT1](https://attack.mitre.org/groups/G0006/)

