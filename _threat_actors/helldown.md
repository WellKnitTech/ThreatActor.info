---
layout: threat_actor
title: "Helldown"
aliases: ["Helldown"]
description: "Helldown is an emerging ransomware group first identified in August 2024, known for its fast-evolving and cross-platform threat capabilities. It exploits critical vulnerabilities—most notably CVE-2024-"
permalink: /helldown/
---

## Introduction
Helldown is an emerging ransomware group first identified in August 2024, known for its fast-evolving and cross-platform threat capabilities. It exploits critical vulnerabilities—most notably CVE-2024-42057 in Zyxel firewalls—for initial access and demonstrates modular design and anti-detection mechanisms. Helldown targets both Windows and Linux environments, including VMware and ESXi systems. It employs a double-extortion strategy: encrypting files with randomized extensions via executables like hellenc.exe, and threatening victims with data dump releases via its Tor-hosted leak site.

## Activities and Tactics
*Information pending cataloguing.*

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
### Ransomware Vulnerability Matrix observations

| Category | Vendor | Product | CVEs |
|---|---|---|---|
| Network Edge | Zyxel | Zyxel Firewall | CVE-2024-11667, CVE-2024-42057 |

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
### Ransomware Tool Matrix observations

| Category | Observed tools |
|---|---|
| Credential Theft | Mimikatz |
| Defense Evasion | HRSword |
| Discovery | Advanced Port Scanner |
| LOLBAS | PsExec |
| RMM Tools | TeamViewer |

## Attribution and Evidence
*Information pending cataloguing.*

## References
*References pending cataloguing.*

